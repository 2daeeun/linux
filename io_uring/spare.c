// SPDX-License-Identifier: GPL-2.0
/*
 * SpareRing: the owner of a single SQ/CQ lends ranges of eligible SQEs
 * (chunks) to executors on spare cores. An executor claims, preps and issues
 * a chunk's requests one slot at a time and finishes them: it stores their
 * CQEs and frees them, and the owner, the only CQ producer, posts the stored
 * CQEs. Inline completions are stored in the chunk, async ones in the
 * executor's port for that ring. Whoever is idle finishes an async
 * completion: the owner when it waits on the CQ anyway, else the executor
 * while it runs, else the owner. A stalled executor strands at most its
 * in-progress request: the owner takes back unissued slots and queued
 * completions, posts stored CQEs, and plugs are flushed every few requests.
 * An owner about to wait on a running executor splits its unissued tail
 * rather than sleep, unless that chunk's issues went async (device-bound).
 *
 * uring_lock may nest q->lock or grp->lock; grp->lock never nests any lock
 * and never overlaps q->lock. io_spare_mutex serializes attachment changes,
 * with uring_lock dropped before acquiring it. Executors only try uring_lock
 * and never wait for an owner, including while exiting.
 * Resource tables remain frozen until attachment, chunks and async requests
 * are all gone.
 *
 * Buffered reads are split at their copy: the executor looks the page cache
 * up and pins the folios, the owner copies them into the user buffer when it
 * posts the CQE, so the data lands in the cache of the core that reads it.
 */
#include <linux/audit.h>
#include <linux/blkdev.h>
#include <linux/completion.h>
#include <linux/cpuset.h>
#include <linux/cred.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/folio_batch.h>
#include <linux/fsnotify.h>
#include <linux/hrtimer.h>
#include <linux/io_uring.h>
#include <linux/irq_work.h>
#include <linux/jump_label.h>
#include <linux/llist.h>
#include <linux/log2.h>
#include <linux/nospec.h>
#include <linux/pagemap.h>
#include <linux/percpu_counter.h>
#include <linux/preempt.h>
#include <linux/refcount.h>
#include <linux/sched/clock.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/cacheflush.h>
#include <linux/moduleparam.h>

#include "io_uring.h"
#include "alloc_cache.h"
#include "cancel.h"
#include "filetable.h"
#include "rsrc.h"
#include "refs.h"
#include "rw.h"
#include "spare.h"
#include "tctx.h"

#define IO_SPARE_MAX_EXEC	64
#define IO_SPARE_MAX_SQES	64
#define IO_SPARE_REQ_CACHE	32
#define IO_SPARE_REQ_BATCH	16
#define IO_SPARE_RESELECT_NS	(50 * NSEC_PER_USEC)
#define IO_SPARE_SIBLING_SCAN_NS	(2 * NSEC_PER_USEC)	/* lingering sibling: group counter check period */
#define IO_SPARE_KICK_BATCH	8	/* CQEs per mid-chunk kick */
#define IO_SPARE_FLUSH_DEEP_QD	(2 * IO_SPARE_KICK_BATCH)	/* coalescing only with this many in flight */

/*
 * Tunables for the measurement rounds (/sys/module/spare/parameters/, root).
 * EXEC_FINISH wake coalescing: a sleeping owner on a deep queue is woken per
 * gathered batch of flush_batch journal entries, or after flush_delay_us. An
 * idle lease holder takes a chunk it handed off back only after a sibling had
 * handoff_grace_us to take it.
 */
static unsigned int io_spare_flush_batch = 16;
module_param_named(flush_batch, io_spare_flush_batch, uint, 0644);
static unsigned int io_spare_flush_delay_us = 8;
module_param_named(flush_delay_us, io_spare_flush_delay_us, uint, 0644);
/* Coalescing depth gate: this port's outstanding requests (0) or the ring's delegated-live count (1). */
static bool io_spare_flush_ring_depth;
module_param_named(flush_ring_depth, io_spare_flush_ring_depth, bool, 0644);
/*
 * An owner waiting for a count (min_complete > 1) gets its CQEs posted at once,
 * uncoalesced. Measured neutral (3 executors) to -5% (2 executors): the lazy
 * wake alone gives such an owner its one wake per batch, and more, smaller
 * posts cost uring_lock trylocks and CQ line transfers. Off by default.
 */
static bool io_spare_batch_post;
module_param_named(batch_post, io_spare_batch_post, bool, 0644);
static unsigned int io_spare_handoff_grace_us = 10;
module_param_named(handoff_grace_us, io_spare_handoff_grace_us, uint, 0644);
/*
 * Issued slots per executor plug flush; 0 issues every request unplugged. The
 * plug batches the driver's doorbell writes, but the device starts a request
 * only at the flush, so each one first waits for up to a batch of issues.
 * Measured (null_blk, timer completions): a plug smaller than this scatters
 * the completions, one owner wake each (plug 0: -35% IOPS, owner 2.5x).
 */
static unsigned int io_spare_plug_batch = 8;
module_param_named(plug_batch, io_spare_plug_batch, uint, 0644);
/*
 * Flush granularity while the owner is idle: waiting on the CQ
 * (io_cqring_wait()) with fewer than plug_batch CQEs it has not reaped. 0
 * holds the plug to the chunk end. An idle owner gains nothing from an early
 * start of a chunk's requests: it is woken once per flush, and the chunk's
 * last request, which decides when the application's batch is complete,
 * starts at the chunk end either way. So its requests go in bursts of
 * plug_batch_idle (16: one for an 11-slot chunk, two for a 32-slot one; C=0:
 * n11 +10% IOPS, owner -19%; n32 +10%, owner -32%). Not the whole chunk: the
 * owner reaps the last burst after the chunk's last completion, on the
 * batch's critical path (32 at once: owner 76 ns/IO, no IOPS gain, and the
 * multi-ring hot shard -20%). An owner that is loaded (running, or busy for
 * plug_idle_busy percent of its time: compute per completion) is fed every
 * plug_batch instead; whole-chunk bursts cost it -11%. Read per flush point.
 */
static unsigned int io_spare_plug_batch_idle = 16;
module_param_named(plug_batch_idle, io_spare_plug_batch_idle, uint, 0644);
/*
 * Owner utilization (percent of its wall time not asleep on the CQ, EWMA over
 * its last eight waits) from which it counts as loaded: then every plug_batch
 * is flushed, not plug_batch_idle. Measured: owners at 25..40% (no compute
 * per completion) gain from the bursts, owners at 85..95% (500 ns per
 * completion) lose 11% to them; the multi-ring hot shard sits in between.
 */
static unsigned int io_spare_plug_idle_busy = 50;
module_param_named(plug_idle_busy, io_spare_plug_idle_busy, uint, 0644);
/*
 * Executor direct post: wait this long for uring_lock before kicking the owner
 * to post instead. The lock is mostly held briefly by a sibling posting its
 * own journal; a kick delays the CQEs until the owner wakes and costs it the
 * posting (io_exec_lock_for_post()).
 */
static unsigned int io_spare_flush_spin_ns = 1000;
module_param_named(flush_spin_ns, io_spare_flush_spin_ns, uint, 0644);
/*
 * Holder publishes for an idle sibling while scanning its own chunk
 * (io_exec_publish_more()). Off by default: on the batch-submitting
 * benchmark it cut the pickup of a new batch (median 4.6 -> 3.7 us) but the
 * batch's last chunk, the critical path, still waited for the holder, while
 * the evenly spread completions woke the owner 1.65x as often (owner +7..12%,
 * IOPS -2..7%). An application that submits incrementally may want it.
 */
static bool io_spare_early_publish;
module_param_named(early_publish, io_spare_early_publish, bool, 0644);
#define IO_SPARE_DIRECT_MAX	64	/* CQEs an executor posts per uring_lock hold */
#define IO_SPARE_MIN_RUN	16	/* default n_min, capped at n_max */
#define IO_SPARE_JOURNAL	512	/* port CQEs awaiting the owner, power of 2 */
#define IO_SPARE_COPY_FOLIOS	4	/* folios a deferred buffered read may span */
#define IO_SPARE_CHUNK_FILES	4	/* distinct non-fixed files a chunk may name */
#define IO_SPARE_PULL_POOL	16	/* retired pull chunks kept per ring, loosely bounded */
#define IO_SPARE_CHUNK_CACHE	16	/* pooled chunks an executor keeps for its own pulls (>= the pool bound: a refill never overflows) */
#define IO_SPARE_NO_FILE	0xffU	/* fidx of a fixed-file slot */
#define IO_SPARE_FILE_BAD	0xfeU	/* failed lookup, never resolve the fd again */
#define IO_SPARE_SHORT_UNITS	4	/* pull units below n_min in a row before handback */
#define IO_SPARE_COPY_NS	25	/* owner cost of one SQE copy (line transfer, measured) */
#define IO_SPARE_EWMA_SHIFT	3	/* cost samples: new = old + (sample - old) / 8 */
/* A chunk CQE whose data the owner still has to copy: flags = COPY | slot. */
#define IO_SPARE_CQE_COPY	(1U << 31)
#define IO_SPARE_CQE_SLOT_MASK	0xffffU
/* io_uring_spare_complete idx of a CQE stored in the port journal, not the chunk */
#define IO_SPARE_TRACE_JOURNAL	(1U << 31)

enum io_spare_slot {
	IO_SPARE_FREE,
	IO_SPARE_EXEC,
	IO_SPARE_OWNER,
	IO_SPARE_CANCEL,
	IO_SPARE_RESERVED,
};

#define IO_W_HOLDER(w)	((u8)((w) >> 56))
#define IO_W_GEN(w)	((u32)((w) >> 32) & 0xffffff)
#define IO_W_CURSOR(w)	((u32)(w))
#define IO_W(h, g, c)	(((u64)(h) << 56) | ((u64)((g) & 0xffffff) << 32) | (u32)(c))

enum { IO_CHUNK_PUSH, IO_CHUNK_PULL };
enum { IO_CHUNK_PUBLISHED, IO_CHUNK_CLAIMED, IO_CHUNK_WITHDRAWN };
enum { IO_RTOK_QUEUED, IO_RTOK_TAKEOVER, IO_RTOK_DRAIN };

#ifdef CONFIG_IO_URING_SPARE_DEBUG
struct io_spare_debug_arm {
	u32 action, count, usec, slot, hits, release;
};
#endif

enum {
	IO_SPARE_STOP,
	IO_SPARE_PARK,
};

struct io_spare_exec {
	/* Read by owners while the executor runs: rescue hints and wakes. */
	struct io_spare_grp *grp;
	struct task_struct *task;
	unsigned long state;
	int cpu;
	pid_t owner_pid;
	bool busy;		/* between claim and fin; read by owner rescue */
	bool awake;		/* outside the group wait queue */
	atomic_t offered;	/* one handoff hint per executor across rings */
	struct io_spare_q *serving;	/* ring it claims from next; owners only compare */
	struct io_spare_q *lease_q;	/* notifier reads it; selection ctx ref protects it */
	u8 exec_id;
#ifdef CONFIG_PREEMPT_NOTIFIERS
	struct preempt_notifier pn;
#endif
	/* Executor only. */
	struct list_head open ____cacheline_aligned_in_smp;	/* chunks awaiting completion */
	struct io_kiocb *req_cache[IO_SPARE_REQ_CACHE];
	unsigned int nr_cached;
	struct io_alloc_cache rw_cache;
	struct io_chunk *chunk_cache[IO_SPARE_CHUNK_CACHE];	/* refilled from q->pull_pool */
	unsigned int nr_chunk_cache;
	struct list_head ports;	/* ports it polls, each with a ctx ref */
	struct io_chunk *ahead;	/* next chunk of the current ring, claimed early */
	bool may_ahead;		/* this chunk is not the last before reselection */
	u64 busy_end;		/* end of the last chunk, sizes linger */
	u64 linger_ns;
	unsigned int empty_wakes;
	u64 lease_w;
	struct io_chunk *publishing;
	struct completion exited ____cacheline_aligned_in_smp;
} ____cacheline_aligned_in_smp;

struct io_spare_grp {
	refcount_t refs;		/* queues plus each created executor */
	spinlock_t lock;		/* ctx_list and executor task pointers only */
	struct list_head ctx_list;
	wait_queue_head_t wq;
	const struct cred *creds;
	cpumask_var_t mask;		/* where unpinned executors may run */
	struct io_spare_q *hint;	/* under lock: the ring the last wake was for */
	pid_t tgid;
	unsigned int nr_exec;
	u64 linger_ns;
	atomic64_t sleeps, empty_wakes;	/* statistics */
	/* Polled by every lingering executor; written per chunk by publish and claim. */
	atomic_t nr_pending ____cacheline_aligned_in_smp;
	atomic_t nr_offers;
	atomic_t nr_handoff;
	atomic_t pull_gen;	/* owner submits on an offered ring without a holder */
	/* Sleep and wake bookkeeping, read by every owner publish. */
	atomic_t nr_awake ____cacheline_aligned_in_smp;
	atomic_t nr_live;
	atomic_t wake_credit;
	struct io_spare_exec exec[];
};

struct io_spare_rescue_entry {
	struct io_uring_sqe sqe;
	struct file *file;	/* the chunk's, alive until the chunk retires */
	struct io_kiocb *req;	/* takeover rounds preallocate outside q->lock */
	bool cancel;
};

/*
 * One per (ring, executor index): the completion side of the lease. Async
 * completions of the executor's requests are queued here while it runs and
 * polls the port; it finishes them and stores their CQEs in the journal for
 * the owner to post. Anyone may take all queued completions at once
 * (llist_del_all()), so the owner takes them over whenever the executor
 * cannot. Allocated at registration and kept until the ring is freed.
 */
struct io_spare_port {
	/* Read-mostly; the flags change only when the executor picks it up or drops it. */
	struct io_spare_q *q;
	struct io_spare_exec *exec;
	struct io_kiocb *token;		/* owner task_work posting the journal */
	struct io_cqe *journal;		/* IO_SPARE_JOURNAL entries */
	bool active;			/* the executor polls done; read by completions */
	bool held;			/* on the executor's list, or still leaving it */
	/* Completion side: completions add, the executor or the owner takes all. */
	struct llist_head done ____cacheline_aligned_in_smp;
	/* Issued async and not yet freed: the executor adds, whoever frees subtracts. */
	atomic_t outstanding ____cacheline_aligned_in_smp;
	/*
	 * Executor-written. posted is advanced under uring_lock by whoever posts
	 * the journal: mostly this executor itself (direct), else the owner.
	 */
	unsigned int produced ____cacheline_aligned_in_smp;
	unsigned int posted;
	unsigned int kick_sent;
	unsigned int batch;		/* executor only: entries since the last post or kick */
	u64 unflushed_since;		/* executor only: local_clock() when batch left zero */
	struct list_head node;		/* exec->ports */
	/* Owner-written. */
	unsigned int kick_seen ____cacheline_aligned_in_smp;
	/*
	 * Statistics this port's executor writes alone (fdinfo sums the ports,
	 * io_spare_ports_sum()): ring-wide counters bounced one line between the
	 * executors on every chunk, reap and post. Plain u64: a 32-bit reader may
	 * see a torn value; they are statistics only.
	 */
	u64 claims ____cacheline_aligned_in_smp;	/* chunks it executed */
	u64 handoffs;		/* chunks it published for a sibling */
	u64 delegated, chunks;	/* SQEs and chunks it published */
	u64 direct;		/* CQEs it posted itself */
	u64 async_exec;		/* completions it finished */
	u64 kicks;		/* owner kicks it sent */
	u64 early, early_kept;	/* units published mid-chunk; of them, kept to run next */
};

/* Owner scratch: the distinct files a run of non-fixed SQEs names. */
struct io_spare_run {
	struct file *files[IO_SPARE_CHUNK_FILES];
	u8 fidx[IO_SPARE_MAX_SQES];
	unsigned int nr_files;
};

struct io_spare_q {
	/*
	 * The claim lines: owner publish and retire, executor claim and the
	 * owner's rescue scan all work on them under q->lock. Nothing the owner
	 * writes per submission shares them, and the counters idle executors
	 * poll (nr_pending, nr_handoff) have their own line below, so neither an
	 * owner submit nor a publish invalidates the pollers.
	 */
	spinlock_t lock ____cacheline_aligned_in_smp;
	struct list_head pending;
	struct list_head handoff;
	struct list_head inflight;
	struct list_head rescue;	/* claimed chunks; stale once unvisited is 0 */
	unsigned int nr_chunks;
	atomic_t nr_rsv_chunks;
	atomic_t nr_publishers;
	struct list_head pull;
	u64 seq;			/* owner under uring_lock (push), lessee under q->lock (pull) */
	u32 cost_exec;			/* under q->lock; read without it (split quota, fdinfo) */
	u8 inelig_streak;		/* lessee only */
	u8 short_streak;		/* lessee only: units below n_min in a row */
	/*
	 * Polled by idle executors on every pass (io_spare_thread()). Written
	 * under q->lock, but only as chunks queue or leave, not by the rest of a
	 * publish or retire: on the lock line, each of those writes pulled the
	 * line away from the pollers.
	 */
	unsigned int nr_pending ____cacheline_aligned_in_smp;
	unsigned int nr_handoff;
	/* The lessee's cursor moves independently of the claim and owner lines. */
	atomic64_t lease ____cacheline_aligned_in_smp;
	/*
	 * Retired pull chunks for the next pull. Any last put adds; the holder
	 * takes them all at once (llist_del_all(), safe with any number of
	 * producers and consumers) into its private cache (io_exec_chunk_alloc()).
	 */
	struct llist_head pull_pool ____cacheline_aligned_in_smp;
	atomic_t nr_pull_pool;
	/* Read-mostly after registration. */
	struct io_ring_ctx *ctx ____cacheline_aligned_in_smp;
	struct io_spare_grp *grp;	/* retained even after detach, until reuse/free */
	struct list_head grp_node;
	u32 n_max, n_min, u_pending, u_chunks, mode, flags;
	struct io_spare_port *ports[IO_SPARE_MAX_EXEC];	/* set once, freed with the ring */
	unsigned int nr_ports;
	u32 gen, rescue_ns;
	bool pull_ok;
	bool attached;
	bool dead;
	u8 offer;
	u8 wait_batched;		/* the owner has waited for more than one CQE (sticky) */
	u64 hold_until;
	struct io_kiocb *rtoken;
	unsigned long rbits;
	struct irq_work notify_work;
#ifdef CONFIG_IO_URING_SPARE_DEBUG
	spinlock_t dbg_lock;
	wait_queue_head_t dbg_wait;
	atomic_t dbg_parked;
	struct io_spare_debug_arm dbg[IORING_SPARE_DBG_EXEC_BEFORE_REAP + 1];
#endif
	/* Owner only, under uring_lock: per-submission sampling, scratch, reuse, statistics. */
	u32 ready_hits ____cacheline_aligned_in_smp;
	u64 t_wait_last, t_sleep, blocked_acc;	/* utilization sampling, io_spare_wait_start() */
	u32 sample_end;
	u32 short_end;			/* SQ head below which this submission's run is short */
	bool sampled;
	u32 tail_entry;
	bool took_over;
	bool owner_wait;		/* the wait path submits: not the application's backlog */
	u32 zp_cq_tail;
	struct {
		u32 cursor, tail, nr_rsv_chunks, free;
		bool valid;
	} zp_snap;
	size_t chunk_size;		/* power of two: kmalloc aligns it to its size */
	struct io_spare_rescue_entry *rescue_buf;	/* n_max entries */
	struct io_spare_run *run;	/* scratch for the run being delegated */
	struct list_head free_chunks;	/* retired chunks for reuse */
	unsigned int nr_free;
	/*
	 * Cost model (ns, EWMA): what one inline SQE costs the owner, what
	 * starting a chunk costs it, what one SQE costs an executor. The owner
	 * delegates a run that starts a chunk only if the issue it saves pays for
	 * the chunk; the split at wait balances the two sides' finish times.
	 * cost_exec, written by the retiring executor, is on the lock line.
	 */
	u32 cost_inline, cost_chunk;
	u64 t_submit, t_delegate;	/* this submission: start, time spent delegating */
	u32 n_deleg_sub;		/* this submission: SQEs delegated */
	atomic64_t delegated, chunks, rescued, wakes;
	u64 skip[IO_SPARE_SKIP_NR];
	u64 rescue_chunks, rescue_tail, rescue_split;
	u64 rescue_left;		/* owner waits that left chunks to a serving executor */
	u64 async_owner;		/* async completions the owner finished */
	u64 deferred;			/* buffered reads whose data the owner copied */
	u64 appended;			/* SQEs that joined an unclaimed chunk */
	u64 files;			/* file references taken for chunks */
	/*
	 * Executor-side statistics of rare events, kept off the lines the owner
	 * writes; the per-chunk, per-reap and per-post counts are per port.
	 */
	atomic64_t kicks ____cacheline_aligned_in_smp;	/* chunk lease kicks; port kicks are per port */
	atomic64_t bounced, cancelled, handback;
	atomic64_t async_steal;		/* finished by the owner after a steal */
	atomic64_t blocked;		/* blocking issues */
	atomic64_t lease_acquires, releases, handbacks, takeovers;
	atomic64_t withdraw_owner, withdraw_exec, abort_publish;
	atomic64_t token_push, timer_fires, zero_progress, reserved_taken;
	/*
	 * Delegated SQEs with no request of the ring yet (io_uring.c counts live
	 * requests in nr_req_allocated for IOSQE_IO_DRAIN): added at delegation,
	 * subtracted when their CQE is posted or they become the ring's request
	 * (adoption, reissue, inline resubmission of a copy). Added by the
	 * publisher, subtracted by whoever posts: its own line.
	 */
	atomic_t live ____cacheline_aligned_in_smp;
	/*
	 * Owner utilization, 0..1024: the share of its wall time the owner spent
	 * off the CQ wait, EWMA over its last eight waits (io_spare_wait_start()).
	 * Written per wait, read by executors at plug flush points.
	 */
	u32 owner_busy ____cacheline_aligned_in_smp;
};

/*
 * A buffered read split at its copy (io_rw_spare_pin()): the executor looked
 * the folios up and holds references, the owner copies them into the user
 * buffer on its own core when it posts the CQE, so the data is hot in the
 * cache of the thread that reads it. Written by the executor before the CQE
 * entry that names the slot, read by the owner after it.
 */
struct io_spare_copy {
	struct file *file;
	loff_t pos;
	unsigned int len;
	u16 nr;
	bool fput;		/* file came from fget(): the owner puts it */
	struct folio *folios[IO_SPARE_COPY_FOLIOS];
};

struct io_chunk {
	/* Under q->lock: publish, claim and retire move it between the lists. */
	struct list_head list;	/* q->pending or q->inflight */
	struct list_head rescue;	/* q->rescue */
	struct list_head handoff;	/* q->handoff, separate from q->pull */
	struct llist_node pool;		/* q->pull_pool */
	struct io_spare_exec *handoff_to;	/* reserved hint, under q->lock */
	u64 handoff_at;			/* local_clock() at enqueue, under q->lock */
	struct io_spare_q *q;
	struct io_spare_exec *exec;
	struct io_spare_port *port;	/* the executor's port of this ring */
	u64 seq;
	u8 kind, state;
	bool copy_done, fin_seen;
	u32 start;
	u32 size;		/* pull: allocation size, checked before reuse (re-registration) */
	refcount_t refs;
	/*
	 * Written by the owner before publication (and, under q->lock, while the
	 * chunk is still unclaimed: appends), read-mostly by the executor.
	 */
	unsigned int n ____cacheline_aligned_in_smp;
	struct io_uring_sqe *sqes;
	struct io_cqe *cqes;
	u8 *slot;
	u8 *fidx;			/* per slot: index into files, or IO_SPARE_NO_FILE */
	struct io_spare_copy *copy;	/* per slot */
	struct io_kiocb *lease, *fin;
	/* Referenced at delegation as inline submission would; put at retire. */
	struct file *files[IO_SPARE_CHUNK_FILES];
	unsigned int nr_files;
	/* Executor-written, on its own line so per-completion stores stay local. */
	unsigned int produced ____cacheline_aligned_in_smp;
	unsigned int kick_sent;
	unsigned int kicked;		/* produced at the last kick attempt, executor only */
	unsigned int taken, handled;	/* executor only */
	unsigned int async;		/* issued async, finished through the port; traced */
	atomic_t unvisited;
	atomic_t rsv;
	bool scanned;
	bool return_ready;
	bool bounced;		/* executor only: a reissue went to the owner before fin */
	struct list_head open;	/* executor only */
	struct io_wq_work_list retry;	/* executor only: issue blocking after the scan */
	u64 t_claim, t_done;		/* executor: claim, end of the nonblocking scan */
	u64 returned, returned_cancel;	/* exit handback, published once */
	/* Owner-written while the chunk is open, off the header the executor re-reads. */
	unsigned int posted ____cacheline_aligned_in_smp;
	unsigned int kick_seen;
	bool returned_done;
	/* Embedded tokens use only dedicated callbacks, never generic request free. */
	struct io_kiocb lease_tok ____cacheline_aligned_in_smp;
	struct io_kiocb fin_tok ____cacheline_aligned_in_smp;
	/* sqes[n_max], cqes[n_max], slot[n_max], fidx[n_max], copy[n_max] */
	u8 data[] ____cacheline_aligned_in_smp;
};

static DEFINE_MUTEX(io_spare_mutex);

static bool io_spare_rescue_locked(struct io_ring_ctx *ctx, bool wait,
				   bool split);
static bool io_spare_eligible(const struct io_uring_sqe *sqe, bool executor);
static void io_chunk_returned(struct io_chunk *chunk, bool cancel);
static bool io_spare_task_stalled(struct io_spare_exec *exec);
static struct io_chunk *io_exec_claim(struct io_spare_exec *exec,
				      struct io_spare_q *q);
static bool io_spare_wake(struct io_spare_q *q, unsigned int demand, bool force);
static void io_exec_port_flush(struct io_spare_port *port);
static void io_exec_port_flush_maybe(struct io_spare_port *port);
static bool io_exec_publish_more(struct io_spare_exec *exec, struct io_spare_q *q);

/* fdinfo: a per-port statistic summed over the ring's ports (lockless snapshot). */
#define io_spare_ports_sum(q, field) ({					\
	struct io_spare_q *q_ = (q);						\
	unsigned int i_, n_ = READ_ONCE(q_->nr_ports);				\
	u64 s_ = 0;								\
	for (i_ = 0; i_ < n_; i_++) {						\
		struct io_spare_port *p_ = READ_ONCE(q_->ports[i_]);		\
		if (p_)								\
			s_ += READ_ONCE(p_->field);				\
	}									\
	s_;									\
})
static void io_spare_inflight_done(struct io_spare_q *q, unsigned int nr);
static bool io_spare_rescue_token(struct io_spare_q *q,
				  struct io_spare_exec *exec);
static void io_pull_chunk_put(struct io_chunk *chunk);
static void io_spare_pull_wake(struct io_spare_q *q);
static bool io_spare_ports_owner(struct io_spare_q *q);
static bool io_spare_ports_queued(struct io_spare_q *q);
static bool io_spare_ports_hint(struct io_spare_q *q);
static bool io_spare_harvest_locked(struct io_spare_q *q);
static bool io_spare_pull_wait(struct io_spare_q *q);
static bool io_spare_pull_work(struct io_spare_q *q, u64 w);
static bool io_spare_wait_takeover(struct io_ring_ctx *ctx);
static void io_spare_rtoken_tw(struct io_tw_req tw_req, io_tw_token_t tw);
static void io_spare_notify_fn(struct irq_work *work);
static void io_spare_publish_head(struct io_spare_q *q, u32 want);

#ifdef CONFIG_IO_URING_SPARE_DEBUG
static DEFINE_STATIC_KEY_FALSE(io_spare_dbg_key);

/* A snapshot lets RELEASE replace an arm without holding a lock while parked. */
static bool io_spare_dbg_take(struct io_spare_q *q, u32 point, u32 slot,
			      struct io_spare_debug_arm *out)
{
	struct io_spare_debug_arm *arm = &q->dbg[point];
	unsigned long flags;
	bool fired = false;

	spin_lock_irqsave(&q->dbg_lock, flags);
	if (arm->action && arm->count &&
	    (point != IORING_SPARE_DBG_EXEC_MID_COPY || arm->slot == slot)) {
		*out = *arm;
		arm->hits++;
		if (!--arm->count)
			WRITE_ONCE(arm->action, 0);
		fired = true;
	}
	spin_unlock_irqrestore(&q->dbg_lock, flags);
	return fired;
}

static bool io_spare_dbg_released(struct io_spare_q *q, u32 point, u32 release,
				 struct io_spare_exec *exec)
{
	return READ_ONCE(q->dbg[point].release) != release ||
	       READ_ONCE(q->dead) || fatal_signal_pending(current) ||
	       (exec && test_bit(IO_SPARE_STOP, &exec->state));
}

static bool io_spare_dbg_fire(struct io_spare_q *q, u32 point, u32 slot,
			      struct io_spare_exec *exec)
{
	struct io_spare_debug_arm arm;
	ktime_t end, tick;
	u64 ns;
	DEFINE_WAIT(wait);

	if (!io_spare_dbg_take(q, point, slot, &arm))
		return false;
	if (arm.action == IORING_SPARE_DBG_KILL)
		return true;
	ns = (u64)(arm.usec ?: 10000000U) * NSEC_PER_USEC;
	/*
	 * The owner parks after its last check with its sleeping state already
	 * set (wait.c): a waitqueue sleep here would consume the very wake under
	 * test and return TASK_RUNNING, so it never sleeps afterwards. Stay on
	 * the CPU instead: a wake meanwhile makes the following schedule() return.
	 */
	if (point == IORING_SPARE_DBG_OWNER_AFTER_LAST_CHECK) {
		end = ktime_add_ns(ktime_get(), min_t(u64, ns, NSEC_PER_SEC));
		while (ktime_before(ktime_get(), end) && !task_sigpending(current))
			cpu_relax();
		return false;
	}
	if (arm.action == IORING_SPARE_DBG_SPIN) {
		end = ktime_add_ns(ktime_get(), min_t(u64, ns, NSEC_PER_SEC));
		while (ktime_before(ktime_get(), end) &&
		       !io_spare_dbg_released(q, point, arm.release, exec))
			cpu_relax();
		return false;
	}
	if (arm.action != IORING_SPARE_DBG_PARK &&
	    arm.action != IORING_SPARE_DBG_BLOCK)
		return false;
	end = ktime_add_ns(ktime_get(), min_t(u64, ns, 10ULL * NSEC_PER_SEC));
	atomic_inc(&q->dbg_parked);
	for (;;) {
		prepare_to_wait(&q->dbg_wait, &wait,
			       arm.action == IORING_SPARE_DBG_BLOCK ?
			       TASK_UNINTERRUPTIBLE : TASK_INTERRUPTIBLE);
		if (io_spare_dbg_released(q, point, arm.release, exec) ||
		    ktime_compare(ktime_get(), end) >= 0 ||
		    (arm.action == IORING_SPARE_DBG_PARK && signal_pending(current)))
			break;
		/* Even uninterruptible BLOCK observes STOP and fatal signals within 1 ms. */
		tick = ktime_add_ns(ktime_get(), NSEC_PER_MSEC);
		if (ktime_compare(tick, end) > 0)
			tick = end;
		schedule_hrtimeout_range(&tick, 0, HRTIMER_MODE_ABS);
	}
	finish_wait(&q->dbg_wait, &wait);
	atomic_dec(&q->dbg_parked);
	return false;
}

static __always_inline bool io_spare_dbg_check(struct io_spare_q *q,
					      u32 point, u32 slot,
					      struct io_spare_exec *exec)
{
	return static_branch_unlikely(&io_spare_dbg_key) &&
	       READ_ONCE(q->dbg[point].action) &&
	       io_spare_dbg_fire(q, point, slot, exec);
}

#define io_spare_dbg(q, point, slot) io_spare_dbg_check(q, point, slot, NULL)
#define io_spare_dbg_exec(q, point, slot, exec) \
	io_spare_dbg_check(q, point, slot, exec)

static u32 io_spare_dbg_alloc_limit(struct io_spare_q *q, u32 got)
{
	struct io_spare_debug_arm arm;

	if (!got)
		return 0;
	if (static_branch_unlikely(&io_spare_dbg_key) &&
	    READ_ONCE(q->dbg[IORING_SPARE_DBG_OWNER_ALLOC_FAIL].action) &&
	    io_spare_dbg_take(q, IORING_SPARE_DBG_OWNER_ALLOC_FAIL, 0, &arm))
		return min(got, arm.slot);
	return got;
}

/* Called under q->lock before attachment: no executor may observe the reset. */
static void io_spare_dbg_init_head(struct io_spare_q *q)
{
	struct io_ring_ctx *ctx = q->ctx;
	struct io_spare_debug_arm arm;
	u32 head = ctx->cached_sq_head;

	if (!static_branch_unlikely(&io_spare_dbg_key) || q->nr_chunks ||
	    READ_ONCE(ctx->rings->sq.head) != head ||
	    READ_ONCE(ctx->rings->sq.tail) != head ||
	    !io_spare_dbg_take(q, IORING_SPARE_DBG_RING_INIT_HEAD, 0, &arm))
		return;
	head = 0U - arm.slot;
	WRITE_ONCE(ctx->rings->sq.head, head);
	WRITE_ONCE(ctx->rings->sq.tail, head);
	ctx->cached_sq_head = head;
	atomic64_set(&q->lease, IO_W(0, q->gen, head));
}

static bool io_spare_dbg_valid(const struct io_uring_spare_debug *dbg)
{
	u32 p = dbg->point, a = dbg->action;

	if (!p || p > IORING_SPARE_DBG_EXEC_BEFORE_REAP)
		return false;
	if (a == IORING_SPARE_DBG_QUERY || a == IORING_SPARE_DBG_DISARM)
		return true;
	if (a == IORING_SPARE_DBG_RELEASE)
		return p <= IORING_SPARE_DBG_EXEC_IN_ISSUE ||
		       p == IORING_SPARE_DBG_EXEC_BEFORE_REAP;
	if (!dbg->count)
		return false;
	if (p <= IORING_SPARE_DBG_EXEC_TOKEN_CLAIMED)
		return a >= IORING_SPARE_DBG_PARK && a <= IORING_SPARE_DBG_KILL;
	if (p == IORING_SPARE_DBG_EXEC_IN_ISSUE || p == IORING_SPARE_DBG_EXEC_BEFORE_REAP)
		return a >= IORING_SPARE_DBG_PARK && a <= IORING_SPARE_DBG_SPIN;
	if (p == IORING_SPARE_DBG_OWNER_AFTER_LAST_CHECK)
		return a == IORING_SPARE_DBG_PARK && dbg->usec;
	if (p == IORING_SPARE_DBG_OWNER_ALLOC_FAIL)
		return a == IORING_SPARE_DBG_FAIL;
	return a == IORING_SPARE_DBG_SET;
}
#else
static inline bool io_spare_dbg_check(struct io_spare_q *q, u32 point, u32 slot,
				      struct io_spare_exec *exec)
{
	return false;
}
#define io_spare_dbg(q, point, slot) io_spare_dbg_check(q, point, slot, NULL)
#define io_spare_dbg_exec(q, point, slot, exec) \
	io_spare_dbg_check(q, point, slot, exec)
static inline u32 io_spare_dbg_alloc_limit(struct io_spare_q *q, u32 got)
{
	return got;
}
static inline void io_spare_dbg_init_head(struct io_spare_q *q) { }
#endif

int io_register_spare_debug(struct io_ring_ctx *ctx, void __user *arg,
			    unsigned int nr_args)
{
#ifdef CONFIG_IO_URING_SPARE_DEBUG
	struct io_uring_spare_debug __user *user = arg;
	struct io_uring_spare_debug dbg;
	struct io_spare_q *q = ctx->spare;
	struct io_spare_debug_arm *arm;
	unsigned long flags;
	u32 hits;
	bool enable = false, wake = false;

	BUILD_BUG_ON(sizeof(struct io_uring_spare_debug) != 32);
	lockdep_assert_held(&ctx->uring_lock);
	if (!q || nr_args != 1)
		return -EINVAL;
	if (copy_from_user(&dbg, arg, sizeof(dbg)))
		return -EFAULT;
	if (dbg.resv || !io_spare_dbg_valid(&dbg))
		return -EINVAL;
	arm = &q->dbg[dbg.point];
	spin_lock_irqsave(&q->dbg_lock, flags);
	hits = arm->hits;
	if (dbg.action == IORING_SPARE_DBG_RELEASE) {
		WRITE_ONCE(arm->release, arm->release + 1);
		wake = true;
	} else if (dbg.action == IORING_SPARE_DBG_DISARM) {
		WRITE_ONCE(arm->action, 0);
		WRITE_ONCE(arm->release, arm->release + 1);
		wake = true;
	} else if (dbg.action != IORING_SPARE_DBG_QUERY) {
		u32 release = arm->release + 1;

		*arm = (struct io_spare_debug_arm) {
			.action = dbg.action, .count = dbg.count,
			.usec = dbg.usec, .slot = dbg.slot, .release = release,
		};
		enable = true;
		wake = true;
	}
	spin_unlock_irqrestore(&q->dbg_lock, flags);
	if (wake)
		wake_up_all(&q->dbg_wait);
	if (enable && !static_branch_unlikely(&io_spare_dbg_key)) {
		/* Jump-label patching may sleep and must not invert uring_lock. */
		mutex_unlock(&ctx->uring_lock);
		static_branch_enable(&io_spare_dbg_key);
		mutex_lock(&ctx->uring_lock);
	}
	if (dbg.action == IORING_SPARE_DBG_QUERY && put_user(hits, &user->hits))
		return -EFAULT;
	return 0;
#else
	return -EINVAL;
#endif
}

static void io_spare_grp_put(struct io_spare_grp *grp)
{
	if (refcount_dec_and_test(&grp->refs)) {
#ifdef CONFIG_PREEMPT_NOTIFIERS
		preempt_notifier_dec();
#endif
		put_cred(grp->creds);
		free_cpumask_var(grp->mask);
		kfree(grp);
	}
}

static struct io_chunk *io_req_chunk(struct io_kiocb *req)
{
	/* These four RW opcodes never use big_cqe; extended CQEs are rejected. */
	return (struct io_chunk *)(unsigned long)req->big_cqe.extra1;
}

/*
 * Owner, uring_lock, in the submitter task unless cancel: finish a buffered
 * read the executor split at its copy. The copy loop is filemap_read()'s;
 * the destination comes from the SQE copy, so no request object is needed.
 * In cancel mode (ring teardown runs this from a kworker without the user
 * mm) nothing is copied. Returns the CQE result.
 */
static int io_spare_copy(struct io_chunk *chunk, unsigned int slot,
			 unsigned int len, bool cancel, struct folio_batch *fb)
{
	struct io_spare_copy *cp = &chunk->copy[slot];
	const struct io_uring_sqe *sqe = &chunk->sqes[slot];
	struct io_ring_ctx *ctx = chunk->q->ctx;
	struct iov_iter iter;
	loff_t pos = cp->pos, end = cp->pos + len;
	size_t copied = 0;
	bool writably_mapped;
	int ret = 0, i;

	if (cancel) {
		ret = -ECANCELED;
		goto put;
	}
	if (sqe->opcode == IORING_OP_READ_FIXED) {
		struct io_rsrc_node *node;

		/* Frozen while chunks are out: the executor's lookup still holds. */
		node = io_rsrc_node_lookup(&ctx->buf_table, sqe->buf_index);
		ret = node ? io_import_reg_buf_node(node, &iter, sqe->addr, len,
						    ITER_DEST) : -EFAULT;
		if (ret)
			goto put;
	} else {
		/* As the executor's prep did: access_ok() and the MAX_RW_COUNT clamp. */
		ret = import_ubuf(ITER_DEST, u64_to_user_ptr(sqe->addr), len, &iter);
		if (ret)
			goto put;
	}
	writably_mapped = mapping_writably_mapped(cp->file->f_mapping);
	for (i = 0; i < cp->nr && pos < end; i++) {
		struct folio *folio = cp->folios[i];
		size_t fsize = folio_size(folio);
		size_t offset = pos & (fsize - 1);
		size_t bytes = min_t(loff_t, end - pos, fsize - offset);
		size_t n;

		if (end <= folio_pos(folio))
			break;
		if (writably_mapped)
			flush_dcache_folio(folio);
		n = copy_folio_to_iter(folio, offset, bytes, &iter);
		copied += n;
		pos += n;
		if (n < bytes) {
			if (!copied)
				ret = -EFAULT;
			break;
		}
	}
	chunk->q->deferred++;
put:
	/* Each folio line is the executor's: putting them in one batch overlaps the transfers. */
	for (i = 0; i < cp->nr; i++)
		if (!folio_batch_add(fb, cp->folios[i]))
			folios_put(fb);
	/* A file the executor referenced itself (no table slot); table files go at retire. */
	if (cp->fput)
		fput(cp->file);
	return ret ? ret : copied;
}

/* Owner only: post the CQEs stored since the last post. src: IO_SPARE_POST_*. */
static void io_chunk_post(struct io_chunk *chunk, int src, bool cancel)
{
	struct folio_batch fb;
	unsigned int p, i;

	folio_batch_init(&fb);
	/*
	 * Deferred copies need the submitter's mm: not from the exit kworker,
	 * not from an exiting owner, and not once the ring is going away.
	 */
	cancel |= io_should_terminate_tw(chunk->q->ctx);
	/* Pairs with the executor's release of produced in io_chunk_record(). */
	p = smp_load_acquire(&chunk->produced);
	trace_io_uring_spare_post(chunk->q->ctx, chunk->seq, chunk->posted, p, src);
	for (i = chunk->posted; i < p; i++) {
		struct io_cqe *cqe = &chunk->cqes[i];
		int res = cqe->res;
		u32 flags = cqe->flags;

		if (flags & IO_SPARE_CQE_COPY) {
			res = io_spare_copy(chunk, flags & IO_SPARE_CQE_SLOT_MASK,
					    res, cancel, &fb);
			flags = 0;
		}
		io_add_aux_cqe(chunk->q->ctx, cqe->user_data, res, flags);
	}
	io_spare_inflight_done(chunk->q, p - chunk->posted);
	chunk->posted = p;
	if (folio_batch_count(&fb))
		folios_put(&fb);
}

/*
 * Owner only (delegate and retire run under uring_lock): reuse saves a
 * kmalloc/kfree and its memcg charge per chunk. Up to u_chunks are kept.
 */
static struct io_chunk *io_spare_chunk_get(struct io_spare_q *q)
{
	struct io_chunk *chunk;

	if (!q->nr_free)
		return kmalloc(q->chunk_size, GFP_KERNEL_ACCOUNT);
	chunk = list_first_entry(&q->free_chunks, struct io_chunk, list);
	list_del(&chunk->list);
	q->nr_free--;
	return chunk;
}

static void io_spare_chunk_put(struct io_spare_q *q, struct io_chunk *chunk)
{
	if (q->nr_free < q->u_chunks) {
		list_add(&chunk->list, &q->free_chunks);
		q->nr_free++;
	} else {
		kfree(chunk);
	}
}

/*
 * Pull chunks never enter the owner's list cache (S4). The last put, mostly a
 * taker's (io_exec_retire()), returns the chunk to the ring's pool for the
 * holder's next pull instead of a remote kfree() of what another core
 * allocated; past the loose bound it is freed. Last puts may fput.
 */
static void io_pull_chunk_put(struct io_chunk *chunk)
{
	struct io_spare_q *q = chunk->q;
	struct io_ring_ctx *ctx = q->ctx;

	if (!refcount_dec_and_test(&chunk->refs))
		return;
	while (chunk->nr_files)
		fput(chunk->files[--chunk->nr_files]);
	if (atomic_inc_return(&q->nr_pull_pool) <= IO_SPARE_PULL_POOL) {
		llist_add(&chunk->pool, &q->pull_pool);
	} else {
		atomic_dec(&q->nr_pull_pool);
		kfree(chunk);
	}
	/* The pool entry is reachable before this: the ring's free drains it. */
	percpu_ref_put(&ctx->refs);
}

static void io_pull_publisher_put(struct io_spare_exec *exec)
{
	struct io_chunk *chunk = exec->publishing;

	if (!chunk)
		return;
	exec->publishing = NULL;
	atomic_dec(&chunk->q->nr_publishers);
	/* The ctx reference belongs to chunk through the final put. */
	io_pull_chunk_put(chunk);
}

/* The drain gate (io_queue_deferred()) must wait for delegated SQEs too. */
unsigned int io_spare_inflight(struct io_ring_ctx *ctx)
{
	struct io_spare_q *q = ctx->spare;

	return q ? atomic_read(&q->live) : 0;
}

static void io_spare_inflight_done(struct io_spare_q *q, unsigned int nr)
{
	if (!nr)
		return;
	atomic_sub(nr, &q->live);
	if (q->pull_ok && current != q->ctx->submitter_task) {
		/* Dekker pair: io_init_req()'s drain flag store / live load. */
		smp_mb__after_atomic();
		if (READ_ONCE(q->ctx->int_flags) & IO_RING_F_DRAIN_ACTIVE) {
			set_bit(IO_RTOK_DRAIN, &q->rbits);
			io_spare_rescue_token(q, NULL);
		}
	}
}

/* Cost samples in ns: one eighth of the difference moves the estimate. */
static void io_spare_ewma(u32 *est, u64 sample)
{
	s32 cur = *est, next = min_t(u64, sample, S32_MAX / 2);

	/* cost_exec is read without q->lock (split quota, fdinfo). */
	WRITE_ONCE(*est, cur ? cur + (next - cur) / (1 << IO_SPARE_EWMA_SHIFT) : next);
}

static void io_chunk_retire(struct io_chunk *chunk, int how)
{
	struct io_spare_q *q = chunk->q;

	lockdep_assert_held(&q->ctx->uring_lock);
	/* produced is stable: fin, or never issued. */
	trace_io_uring_spare_retire(q->ctx, chunk->seq, chunk->n,
				    READ_ONCE(chunk->produced), how);
	spin_lock(&q->lock);
	list_del(&chunk->list);
	list_del_init(&chunk->rescue);
	q->nr_chunks--;
	/* The executor's nonblocking scan time per SQE feeds the split at wait. */
	if (how == IO_SPARE_RETIRE_FIN && chunk->n &&
	    READ_ONCE(chunk->t_done) > READ_ONCE(chunk->t_claim))
		io_spare_ewma(&q->cost_exec,
			      div_u64(chunk->t_done - chunk->t_claim, chunk->n));
	spin_unlock(&q->lock);
	/* Nothing issued from this chunk runs any more; its file references go. */
	while (chunk->nr_files)
		fput(chunk->files[--chunk->nr_files]);
	if (chunk->kind == IO_CHUNK_PULL) {
		/* Embedded tokens never enter completion/cache APIs (tw.c:283,316). */
		io_pull_chunk_put(chunk);
		return;
	}
	/* req_set_fail() would remove CQE_SKIP (io_uring.h:329-335). */
	if (chunk->lease)
		io_req_complete_defer(chunk->lease);
	io_req_complete_defer(chunk->fin);
	io_spare_chunk_put(q, chunk);
}

static void io_spare_free_chunks(struct io_spare_q *q)
{
	struct io_chunk *chunk, *next;
	struct llist_node *node;
	unsigned int nr = 0;

	list_for_each_entry_safe(chunk, next, &q->free_chunks, list)
		kfree(chunk);
	INIT_LIST_HEAD(&q->free_chunks);
	q->nr_free = 0;
	/*
	 * Ring free, or re-registration with a new n_max. A put racing with this
	 * (a publisher past its lease check) leaves its chunk for the next holder,
	 * which frees a chunk of another size (io_exec_chunk_alloc()).
	 */
	node = llist_del_all(&q->pull_pool);
	while (node) {
		chunk = llist_entry(node, struct io_chunk, pool);
		node = node->next;
		kfree(chunk);
		nr++;
	}
	atomic_sub(nr, &q->nr_pull_pool);
}

static void io_lease_tw(struct io_tw_req tw_req, io_tw_token_t tw)
{
	struct io_chunk *chunk = io_req_chunk(tw_req.req);

	WRITE_ONCE(chunk->kick_seen, READ_ONCE(chunk->kick_sent));
	/* Dekker pair: executor's produced/return_ready stores / kick_seen load. */
	smp_mb();
	io_chunk_post(chunk, IO_SPARE_POST_LEASE, tw.cancel);
	io_chunk_returned(chunk, tw.cancel);
}

/* Ensure helper allocation succeeds before taking a slot away from rescue. */
static bool io_spare_reserve_req(struct io_ring_ctx *ctx)
{
	return !io_req_cache_empty(ctx) || __io_alloc_req_refill(ctx);
}

/*
 * Taken-back copies go out in one batch, sharing a submit state and plug as
 * the inline path would have (per-copy batches cost twice an inline issue).
 * They precede later drains: io_init_req() would otherwise queue them behind
 * that drain (io_uring.c:1800-1813,1682-1685). Tokens keep the later drain
 * blocked while the copies are issued.
 */
static unsigned int io_spare_copies_start(struct io_ring_ctx *ctx, unsigned int nr)
{
	unsigned int drain = ctx->int_flags &
			     (IO_RING_F_DRAIN_ACTIVE | IO_RING_F_DRAIN_NEXT);

	ctx->int_flags &= ~(IO_RING_F_DRAIN_ACTIVE | IO_RING_F_DRAIN_NEXT);
	io_submit_copies_start(ctx, nr);
	return drain;
}

static void io_spare_copies_end(struct io_ring_ctx *ctx, unsigned int drain)
{
	io_submit_copies_end(ctx);
	ctx->int_flags |= drain;
}

/* The file the owner resolved for a slot at delegation, or NULL (fixed file). */
static struct file *io_chunk_slot_file(struct io_chunk *chunk, unsigned int i)
{
	u8 k = chunk->fidx[i];

	if (k == IO_SPARE_FILE_BAD)
		return ERR_PTR(-EBADF);
	return k == IO_SPARE_NO_FILE ? NULL : chunk->files[k];
}

/*
 * Between io_spare_copies_start() and io_spare_copies_end(). The copy uses
 * the file resolved at delegation (io_submit_copied_sqe_file()): the fd may
 * name another file by now, and inline submission would have used this one.
 */
static void io_spare_submit_copy(struct io_ring_ctx *ctx,
				 const struct io_uring_sqe *sqe, struct file *file,
				 bool cancel)
{
	if (cancel || percpu_ref_is_dying(&ctx->refs)) {
		io_add_aux_cqe(ctx, sqe->user_data, -ECANCELED, 0);
		atomic64_inc(&ctx->spare->cancelled);
	} else if (!io_spare_eligible(sqe, true)) {
		io_add_aux_cqe(ctx, sqe->user_data, -EINVAL, 0);
	} else if (IS_ERR(file)) {
		io_add_aux_cqe(ctx, sqe->user_data, PTR_ERR(file), 0);
	} else if (!io_spare_reserve_req(ctx)) {
		io_add_aux_cqe(ctx, sqe->user_data, -ENOMEM, 0);
	} else {
		/* Init errors have already posted their CQE in the normal path. */
		io_submit_copied_sqe_file(ctx, sqe, file);
	}
	/* A CQE or a request of the ring: no longer a delegated SQE without one. */
	io_spare_inflight_done(ctx->spare, 1);
}

/* q->lock serializes every pull head store with claim and takeover. */
static void io_spare_publish_head(struct io_spare_q *q, u32 want)
{
	struct io_chunk *chunk;
	u32 limit = want, cur = READ_ONCE(q->ctx->rings->sq.head);
	unsigned int i;

	lockdep_assert_held(&q->lock);
	if (atomic_read(&q->nr_rsv_chunks))
		list_for_each_entry(chunk, &q->pull, list) {
			if (!atomic_read(&chunk->rsv))
				continue;
			for (i = 0; i < chunk->n; i++)
				if (smp_load_acquire(&chunk->slot[i]) == IO_SPARE_RESERVED &&
				    (s32)(chunk->start + i - limit) < 0)
					limit = chunk->start + i;
		}
	if (WARN_ON_ONCE((s32)(limit - cur) < 0))
		return;
	trace_io_uring_spare_head(q->ctx, IO_W_HOLDER(atomic64_read(&q->lease)),
				  want, limit);
	/* Pairs with the producer's head acquire, as io_commit_sqring() does. */
	smp_store_release(&q->ctx->rings->sq.head, limit);
}

enum io_spare_takeover_mode {
	IO_SPARE_TAKE_SUBMIT,
	IO_SPARE_TAKE_CLOSE,
	IO_SPARE_TAKE_UNREGISTER,
};

/* q->lock held: only the successful RESERVED transition returns a reservation. */
static void io_spare_reserved_done(struct io_chunk *chunk)
{
	if (atomic_dec_and_test(&chunk->rsv))
		atomic_dec(&chunk->q->nr_rsv_chunks);
}

/* Snapshots count actual FREE slots, rather than stale rescue list entries. */
static unsigned int io_spare_free_left(struct io_spare_q *q)
{
	struct io_chunk *chunk;
	unsigned int i, nr = 0;

	lockdep_assert_held(&q->lock);
	list_for_each_entry(chunk, &q->rescue, rescue)
		for (i = 0; i < chunk->n; i++) {
			u8 state = READ_ONCE(chunk->slot[i]);

			nr += state == IO_SPARE_FREE || state == IO_SPARE_CANCEL;
		}
	/* Copy winners may exist before the publisher installs its rescue entry. */
	list_for_each_entry(chunk, &q->pull, list) {
		if (chunk->copy_done)
			continue;
		for (i = 0; i < chunk->n; i++) {
			u8 state = smp_load_acquire(&chunk->slot[i]);

			nr += state == IO_SPARE_FREE || state == IO_SPARE_CANCEL;
		}
	}
	return nr;
}

static bool io_spare_zp_same(struct io_spare_q *q)
{
	u64 w;
	bool same;

	if (!q->zp_snap.valid)
		return false;
	spin_lock(&q->lock);
	w = atomic64_read(&q->lease);
	same = q->zp_snap.cursor == IO_W_CURSOR(w) &&
	       q->zp_snap.tail == smp_load_acquire(&q->ctx->rings->sq.tail) &&
	       q->zp_snap.nr_rsv_chunks == atomic_read(&q->nr_rsv_chunks) &&
	       q->zp_snap.free == io_spare_free_left(q) &&
	       q->zp_cq_tail == READ_ONCE(q->ctx->cached_cq_tail) &&
	       !io_local_work_pending(q->ctx) && !task_work_pending(current) &&
	       !task_sigpending(current);
	spin_unlock(&q->lock);
	return same;
}

static void io_spare_zero_progress(struct io_spare_q *q)
{
	spin_lock(&q->lock);
	q->zp_snap.cursor = IO_W_CURSOR(atomic64_read(&q->lease));
	q->zp_snap.tail = smp_load_acquire(&q->ctx->rings->sq.tail);
	q->zp_snap.nr_rsv_chunks = atomic_read(&q->nr_rsv_chunks);
	q->zp_snap.free = io_spare_free_left(q);
	q->zp_cq_tail = READ_ONCE(q->ctx->cached_cq_tail);
	q->zp_snap.valid = true;
	spin_unlock(&q->lock);
	atomic64_inc(&q->zero_progress);
}

/*
 * uring_lock held. Request refill may sleep (io_uring.c:255), so allocate
 * before q->lock; file puts and SQE submission likewise belong after it.
 * The list reference pins a claimed chunk until its fin has been consumed.
 */
static bool io_spare_takeover_locked(struct io_ring_ctx *ctx,
				     struct io_spare_q *q,
				     enum io_spare_takeover_mode mode)
{
	struct io_spare_rescue_entry *stash = q->rescue_buf;
	struct io_kiocb *prealloc[IO_SPARE_MAX_SQES];
	struct io_chunk *chunk, *next;
	bool close = mode == IO_SPARE_TAKE_CLOSE, progress = false, zero = false;
	u64 w = atomic64_read(&q->lease), nw, old;
	u32 cursor;
	unsigned int got, used, i, drain, limit;

	lockdep_assert_held(&ctx->uring_lock);
	for (;;) {
		if (mode == IO_SPARE_TAKE_SUBMIT && !IO_W_HOLDER(w))
			break;
		if (mode != IO_SPARE_TAKE_SUBMIT)
			q->gen = (IO_W_GEN(w) + 1) & 0xffffff;
		nw = IO_W(0, mode == IO_SPARE_TAKE_SUBMIT ? IO_W_GEN(w) : q->gen,
			  IO_W_CURSOR(w));
		old = atomic64_cmpxchg(&q->lease, w, nw);
		if (old == w) {
			if (IO_W_HOLDER(w)) {
				q->took_over = true;
				atomic64_inc(&q->takeovers);
				trace_io_uring_spare_lease(ctx, NULL, IO_SPARE_LEASE_TAKEOVER,
							  IO_W_CURSOR(w), mode);
			}
			break;
		}
		w = old;
	}
	/*
	 * No lessee and no pull chunk: nothing to withdraw, take or expose. No
	 * executor can publish meanwhile (that needs W, and acquiring it needs
	 * uring_lock), so the lockless list check is exact and the submit stays
	 * off q->lock and the shared sq_flags line. The ender of a lease clears
	 * LEASED itself.
	 */
	if (mode == IO_SPARE_TAKE_SUBMIT && !IO_W_HOLDER(w) && list_empty(&q->pull)) {
		ctx->cached_sq_head = IO_W_CURSOR(w);
		return false;
	}
	atomic_andnot(IORING_SQ_LEASED, &ctx->rings->sq_flags);
	cursor = IO_W_CURSOR(atomic64_read(&q->lease));
	for (;;) {
		LIST_HEAD(withdrawn);
		LIST_HEAD(retire);

		got = used = 0;
		limit = close ? 0 : min_t(unsigned int, q->n_max,
					      atomic_read(&q->nr_rsv_chunks) * q->n_max);
		limit = io_spare_dbg_alloc_limit(q, limit);
		while (got < limit && io_alloc_req(ctx, &prealloc[got]))
			got++;
		if (got)
			io_get_task_refs(got);
		spin_lock(&q->lock);
		list_for_each_entry_safe(chunk, next, &q->pull, list) {
			unsigned int taken = 0;

			if (READ_ONCE(chunk->state) == IO_CHUNK_PUBLISHED &&
			    chunk->start == cursor &&
			    cmpxchg(&chunk->state, IO_CHUNK_PUBLISHED,
				    IO_CHUNK_WITHDRAWN) == IO_CHUNK_PUBLISHED) {
				list_move_tail(&chunk->list, &withdrawn);
				q->nr_chunks--;
				if (atomic_xchg(&chunk->rsv, 0))
					atomic_dec(&q->nr_rsv_chunks);
				atomic_sub(chunk->n, &q->live);
				atomic64_inc(&q->withdraw_owner);
				trace_io_uring_spare_pull_publish(ctx, chunk->exec,
							 chunk->start, chunk->n,
							 IO_SPARE_PULL_WITHDRAW_OWNER);
				q->took_over = progress = true;
				continue;
			}
			if (READ_ONCE(chunk->state) == IO_CHUNK_WITHDRAWN ||
			    (s32)(cursor - chunk->start) < (s32)chunk->n)
				continue;
			for (i = 0; i < chunk->n && atomic_read(&chunk->rsv); i++) {
				struct file *file;
				struct io_uring_sqe copy;

				if (READ_ONCE(chunk->slot[i]) != IO_SPARE_RESERVED)
					continue;
				if (!close && used == got)
					break;
				/* The SQ producer may reuse the slot as soon as head passes it. */
				if (!close)
					memcpy(&copy, &ctx->sq_sqes[(chunk->start + i) &
						       (ctx->sq_entries - 1)], sizeof(copy));
				if (cmpxchg(&chunk->slot[i], IO_SPARE_RESERVED,
					    IO_SPARE_OWNER) != IO_SPARE_RESERVED)
					continue;
				io_spare_reserved_done(chunk);
				taken++;
				q->took_over = progress = true;
				if (close) {
					atomic_dec(&q->live);
					continue;
				}
				file = io_chunk_slot_file(chunk, i);
				stash[used].sqe = copy;
				stash[used].req = prealloc[used];
				stash[used++].file = file && !IS_ERR(file) ? get_file(file) : file;
				atomic64_inc(&q->reserved_taken);
			}
			if (taken)
				trace_io_uring_spare_rescue(ctx, chunk->seq, taken,
							    close ? taken : 0,
							    IO_SPARE_RESCUE_TAIL);
			if (!chunk->copy_done && !atomic_read(&chunk->rsv)) {
				unsigned int free = 0;

				/*
				 * The last copy CAS may precede a preempted publisher's
				 * rescue-list store. No new FREE can appear once rsv is 0.
				 */
				for (i = 0; i < chunk->n; i++) {
					u8 state = smp_load_acquire(&chunk->slot[i]);

					free += state == IO_SPARE_FREE || state == IO_SPARE_CANCEL;
				}
				atomic_set(&chunk->unvisited, free);
				chunk->copy_done = true;
				if (free)
					list_add_tail(&chunk->rescue, &q->rescue);
			}
			if (chunk->fin_seen && !atomic_read(&chunk->rsv)) {
				list_del_init(&chunk->rescue);
				list_add_tail(&chunk->rescue, &retire);
				progress = true;
			}
		}
		spin_unlock(&q->lock);
		list_for_each_entry_safe(chunk, next, &withdrawn, list) {
			list_del_init(&chunk->list);
			/* The unchanged checker counts withdrawals as whole owner rescues. */
			trace_io_uring_spare_rescue(ctx, chunk->seq, chunk->n, 0,
						    IO_SPARE_RESCUE_PENDING);
			while (chunk->nr_files)
				fput(chunk->files[--chunk->nr_files]);
			trace_io_uring_spare_retire(ctx, chunk->seq, chunk->n, 0,
						    IO_SPARE_RETIRE_RESCUE);
			io_pull_chunk_put(chunk);
		}
		if (used) {
			drain = io_spare_copies_start(ctx, used);
			for (i = 0; i < used; i++) {
				io_submit_copied_sqe_req(ctx, stash[i].req,
							 &stash[i].sqe, stash[i].file);
				if (stash[i].file && !IS_ERR(stash[i].file))
					fput(stash[i].file);
			}
			io_spare_copies_end(ctx, drain);
			io_spare_inflight_done(q, used);
		}
		for (i = used; i < got; i++)
			io_spare_unused_req(ctx, prealloc[i]);
		if (got != used)
			current->io_uring->cached_refs += got - used;
		list_for_each_entry_safe(chunk, next, &retire, rescue) {
			list_del_init(&chunk->rescue);
			io_chunk_retire(chunk, IO_SPARE_RETIRE_FIN);
		}
		if ((ctx->int_flags & IO_RING_F_DRAIN_ACTIVE) && !close)
			io_spare_queue_deferred(ctx);
		if (close || !atomic_read(&q->nr_rsv_chunks) || used < got)
			break;
		if (!got) {
			io_spare_zero_progress(q);
			zero = true;
			break;
		}
	}
	if (progress && !zero)
		q->zp_snap.valid = false;
	ctx->cached_sq_head = cursor;
	return progress;
}

bool io_spare_pull(struct io_ring_ctx *ctx)
{
	return ctx->spare && READ_ONCE(ctx->spare->pull_ok);
}

void io_spare_submit_takeover(struct io_ring_ctx *ctx, unsigned int nr)
{
	struct io_spare_q *q = ctx->spare;

	q->tail_entry = smp_load_acquire(&ctx->rings->sq.tail);
	q->took_over = false;
	clear_bit(IO_RTOK_TAKEOVER, &q->rbits);
	io_spare_takeover_locked(ctx, q, IO_SPARE_TAKE_SUBMIT);
}

unsigned int io_spare_submit_entries(struct io_ring_ctx *ctx)
{
	/* As __io_sqring_entries(): a bogus tail must not wrap onto consumed SQEs. */
	return min(ctx->spare->tail_entry - ctx->cached_sq_head, ctx->sq_entries);
}

bool io_spare_took_over(struct io_ring_ctx *ctx)
{
	return ctx->spare->took_over;
}

void io_spare_commit_head(struct io_ring_ctx *ctx)
{
	struct io_spare_q *q = ctx->spare;

	lockdep_assert_held(&ctx->uring_lock);
	spin_lock(&q->lock);
	atomic64_set(&q->lease, IO_W(0, q->gen, ctx->cached_sq_head));
	io_spare_publish_head(q, ctx->cached_sq_head);
	spin_unlock(&q->lock);
}

/*
 * Owner, uring_lock: inline-first (spec 14.2). A lease pays only for runs of
 * at least n_min; below that every SQE would cost a cross-core hop (QD 1-2).
 * backlog is what the application handed this enter (to_submit). grp->nr_offers
 * follows every change; detach clears the offer itself.
 */
static void io_spare_offer(struct io_spare_q *q, unsigned int backlog)
{
	u8 offer = READ_ONCE(q->attached) && q->pull_ok &&
		   q->mode != IORING_SPARE_MODE_NEVER && backlog >= q->n_min;

	if (offer == q->offer || !q->grp)
		return;
	WRITE_ONCE(q->offer, offer);
	if (offer)
		atomic_inc(&q->grp->nr_offers);
	else
		atomic_dec(&q->grp->nr_offers);
}

int io_spare_submit_ret(struct io_ring_ctx *ctx, unsigned int nr, int ret)
{
	struct io_spare_q *q = ctx->spare;
	s32 accepted = READ_ONCE(ctx->rings->sq.head) - (q->tail_entry - nr);

	ret = clamp_t(s32, accepted, 0, nr);
	if (nr && !q->owner_wait)
		io_spare_offer(q, nr);
	if (q->offer)
		io_spare_pull_wake(q);
	return nr && !ret ? -EAGAIN : ret;
}

static void io_chunk_returned(struct io_chunk *chunk, bool cancel)
{
	struct io_ring_ctx *ctx = chunk->q->ctx;
	unsigned int drain;
	u64 returned;

	/* Pairs with io_exec_return_slots() publishing immutable handback masks. */
	if (!smp_load_acquire(&chunk->return_ready) || chunk->returned_done)
		return;
	chunk->returned_done = true;
	returned = chunk->returned;
	if (!returned)
		return;
	drain = io_spare_copies_start(ctx, hweight64(returned));
	while (returned) {
		unsigned int i = __ffs64(returned);

		returned &= returned - 1;
		io_spare_submit_copy(ctx, &chunk->sqes[i], io_chunk_slot_file(chunk, i),
				     cancel || (chunk->returned_cancel & BIT_ULL(i)));
	}
	io_spare_copies_end(ctx, drain);
}

static void io_fin_tw(struct io_tw_req tw_req, io_tw_token_t tw)
{
	struct io_chunk *chunk = io_req_chunk(tw_req.req);
	struct io_spare_q *q = chunk->q;
	unsigned int i, discarded = 0;

	/* FIFO fin push follows every executor write and every lease/bounce push. */
	io_chunk_post(chunk, IO_SPARE_POST_FIN, tw.cancel);
	io_chunk_returned(chunk, tw.cancel);
	if (chunk->kind == IO_CHUNK_PULL) {
		chunk->fin_seen = true;
		if (atomic_read(&chunk->rsv) && tw.cancel) {
			spin_lock(&q->lock);
			for (i = 0; i < chunk->n; i++)
				if (cmpxchg(&chunk->slot[i], IO_SPARE_RESERVED,
					    IO_SPARE_OWNER) == IO_SPARE_RESERVED) {
					io_spare_reserved_done(chunk);
					atomic_dec(&q->live);
					discarded++;
				}
			spin_unlock(&q->lock);
			if (discarded)
				trace_io_uring_spare_rescue(q->ctx, chunk->seq, discarded,
							    discarded, IO_SPARE_RESCUE_TAIL);
		}
		if (atomic_read(&chunk->rsv)) {
			set_bit(IO_RTOK_TAKEOVER, &q->rbits);
			atomic_or(IORING_SQ_TASKRUN, &q->ctx->rings->sq_flags);
			return;
		}
	}
	/* Async requests are counted by their port: nothing else uses the chunk. */
	io_chunk_retire(chunk, IO_SPARE_RETIRE_FIN);
}

static void io_spare_init_token(struct io_ring_ctx *ctx, struct io_kiocb *req,
				struct io_chunk *chunk, io_req_tw_func_t func)
{
	/* Cached requests include poisoned pointers; reset all of them. */
	memset(req, 0, sizeof(*req));
	req->ctx = ctx;
	req->tctx = current->io_uring;
	req->opcode = IORING_OP_NOP;
	req->flags = REQ_F_CQE_SKIP;
	req->io_task_work.func = func;
	req->big_cqe.extra1 = (unsigned long)chunk;
}

/*
 * Executor (EXEC_FINISH), at fin of a pull chunk it issued whole and whose
 * every CQE went through the port journal: retire it here. The owner's fin
 * task_work was a forced wake per chunk (tw.c: a non-lazy add claims the
 * wait cycle), which undid the port's completion coalescing, and all it did
 * for such a chunk was list bookkeeping on lines this core wrote. A chunk
 * the owner has a stake in keeps the owner's fin, ordered behind its other
 * task_work: a slot it rescued or was handed back (taken < n), CQEs in the
 * chunk buffer (journal full) or a kick it has to see, a reissue bounce
 * adopted on its side. taken == n also means the scan dropped the chunk's
 * file references already (io_exec_chunk()) and that no slot was RESERVED
 * at any point after the copy, so no takeover names this chunk.
 */
static bool io_exec_retire(struct io_chunk *chunk)
{
	struct io_spare_q *q = chunk->q;

	if (chunk->kind != IO_CHUNK_PULL ||
	    !(READ_ONCE(q->flags) & IORING_SPARE_F_EXEC_FINISH) ||
	    chunk->taken != chunk->n || chunk->produced || chunk->kick_sent ||
	    chunk->bounced || READ_ONCE(chunk->return_ready))
		return false;
	trace_io_uring_spare_retire(q->ctx, chunk->seq, chunk->n, 0,
				    IO_SPARE_RETIRE_FIN);
	spin_lock(&q->lock);
	list_del(&chunk->list);
	list_del_init(&chunk->rescue);
	q->nr_chunks--;
	/* Under q->lock: the owner's retire updates the same estimate. */
	if (chunk->n && chunk->t_done > chunk->t_claim)
		io_spare_ewma(&q->cost_exec,
			      div_u64(chunk->t_done - chunk->t_claim, chunk->n));
	spin_unlock(&q->lock);
	while (chunk->nr_files)
		fput(chunk->files[--chunk->nr_files]);
	io_pull_chunk_put(chunk);
	return true;
}

/* Returns true if the chunk was retired or fin was queued; it must not be touched afterwards. */
static bool io_chunk_maybe_fin(struct io_chunk *chunk)
{
	struct io_kiocb *fin;

	if (!chunk->scanned || chunk->handled != chunk->taken)
		return false;
	list_del(&chunk->open);
	fin = chunk->fin;
	trace_io_uring_spare_fin(chunk->q->ctx, chunk->seq, chunk->taken,
				 chunk->handled, chunk->produced, chunk->async);
	if (io_exec_retire(chunk))
		return true;
	/* Final access: FIFO push publishes all writes to the owner's fin tw. */
	io_req_local_work_add(fin, 0);
	return true;
}

static void io_chunk_kick(struct io_chunk *chunk)
{
	/* A chunk of at most IO_SPARE_KICK_BATCH has no lease: fin posts it all. */
	if (!chunk->lease)
		return;
	chunk->kicked = chunk->produced;
	/* Dekker pair: owner's kick_seen-store / produced-or-handback-load barrier. */
	smp_mb();
	if (READ_ONCE(chunk->kick_seen) == chunk->kick_sent) {
		WRITE_ONCE(chunk->kick_sent, chunk->kick_sent + 1);
		atomic64_inc(&chunk->q->kicks);
		trace_io_uring_spare_kick(chunk->q->ctx, chunk->seq, chunk->produced,
					  chunk->kick_sent);
		io_req_local_work_add(chunk->lease, 0);
	}
}

static void io_chunk_record(struct io_chunk *chunk, u64 data, s32 res, u32 flags)
{
	unsigned int p = chunk->produced;

	chunk->cqes[p] = (struct io_cqe) { .user_data = data, .res = res,
					 .flags = flags };
	if (res == -ECANCELED)
		atomic64_inc(&chunk->q->cancelled);
	/* Pairs with io_chunk_post() acquiring produced before reading CQEs. */
	smp_store_release(&chunk->produced, p + 1);
	trace_io_uring_spare_complete(chunk->q->ctx, chunk->seq, p, data, res);
	/*
	 * Within a long scan or drain, hand over every IO_SPARE_KICK_BATCH CQEs
	 * so the owner reaps them while the rest of the chunk is still issued;
	 * kicking only at the end idles both sides when QD / n_max is small.
	 * The last CQE of a full chunk is left to fin.
	 */
	if (p + 1 - chunk->kicked >= IO_SPARE_KICK_BATCH && p + 1 != chunk->n)
		io_chunk_kick(chunk);
}

/*
 * Kick per executor batch, not per CQE (docs/12 5.1): at the end of a chunk
 * scan and of a completion drain, every IO_SPARE_KICK_BATCH CQEs in between,
 * and only for a chunk that is still open, since fin posts everything itself.
 * Every produced store is thus followed by a kick attempt or by fin before
 * the executor leaves the chunk.
 */
static void io_chunk_flush(struct io_chunk *chunk)
{
	if (chunk->produced != chunk->kicked)
		io_chunk_kick(chunk);
}

/* A file borrowed from the chunk's table is the chunk's to put, at retire. */
static void io_exec_put_file(struct io_kiocb *req)
{
	if (!(req->flags & REQ_F_EXEC_FILE))
		io_put_file(req);
}

/* Before a request leaves the executor for the owner: a reference of its own. */
static void io_exec_own_file(struct io_kiocb *req)
{
	if (req->flags & REQ_F_EXEC_FILE) {
		get_file(req->file);
		req->flags &= ~REQ_F_EXEC_FILE;
	}
}

/*
 * The executor whose private caches this request may use: the issuing
 * executor itself, in task context. The owner's tctx has no executor, and an
 * IRQ interrupting an executor must not touch its caches.
 */
static struct io_spare_exec *io_spare_req_exec(struct io_kiocb *req)
{
	struct io_uring_task *tctx = current->io_uring;

	if (!in_task() || !(req->flags & REQ_F_EXEC) || !tctx || req->tctx != tctx)
		return NULL;
	return tctx->spare_exec;
}

struct io_alloc_cache *io_spare_rw_cache(struct io_kiocb *req)
{
	struct io_spare_exec *exec = io_spare_req_exec(req);

	return exec ? &exec->rw_cache : NULL;
}

static struct io_kiocb *io_exec_req_alloc(struct io_spare_exec *exec)
{
	struct io_kiocb *req;

	if (!exec->nr_cached) {
		if (!kmem_cache_alloc_bulk(req_cachep, GFP_KERNEL,
					   IO_SPARE_REQ_BATCH,
					   (void **)exec->req_cache))
			return NULL;
		exec->nr_cached = IO_SPARE_REQ_BATCH;
	}
	req = exec->req_cache[--exec->nr_cached];
	/* Preserve the full __GFP_ZERO state, including all command unions. */
	memset(req, 0, sizeof(*req));
	return req;
}

static void io_exec_req_cache_put(struct io_spare_exec *exec,
				  struct io_kiocb *req)
{
	if (exec && exec->nr_cached < IO_SPARE_REQ_CACHE)
		exec->req_cache[exec->nr_cached++] = req;
	else
		kmem_cache_free(req_cachep, req);
}

static void io_exec_cache_free(struct io_spare_exec *exec)
{
	while (exec->nr_cached)
		kmem_cache_free(req_cachep, exec->req_cache[--exec->nr_cached]);
	while (exec->nr_chunk_cache)
		kfree(exec->chunk_cache[--exec->nr_chunk_cache]);
	io_alloc_cache_free(&exec->rw_cache, io_rw_cache_free);
}

/*
 * Holder: a pull chunk from its private cache, refilled from the ring's pool
 * in one llist_del_all() (any producers, any consumers: a holder change
 * mid-refill only splits the list). The cache is executor-private and may
 * hold chunks of another ring or of an earlier registration: only a chunk
 * of this ring's size is reused, the rest are freed. Else kmalloc().
 */
static struct io_chunk *io_exec_chunk_alloc(struct io_spare_exec *exec,
					    struct io_spare_q *q)
{
	struct io_chunk *chunk;

	if (!exec->nr_chunk_cache) {
		struct llist_node *node = llist_del_all(&q->pull_pool);
		unsigned int nr = 0;

		while (node) {
			chunk = llist_entry(node, struct io_chunk, pool);
			node = node->next;
			nr++;
			if (exec->nr_chunk_cache < IO_SPARE_CHUNK_CACHE &&
			    chunk->size == q->chunk_size)
				exec->chunk_cache[exec->nr_chunk_cache++] = chunk;
			else
				kfree(chunk);
		}
		atomic_sub(nr, &q->nr_pull_pool);
	}
	while (exec->nr_chunk_cache) {
		chunk = exec->chunk_cache[--exec->nr_chunk_cache];
		if (chunk->size == q->chunk_size)
			return chunk;
		kfree(chunk);
	}
	return kmalloc(q->chunk_size, GFP_KERNEL_ACCOUNT);
}

static void io_exec_req_free(struct io_kiocb *req, bool put_file)
{
	struct io_spare_exec *exec = io_spare_req_exec(req);
	struct io_ring_ctx *ctx = req->ctx;

	if (req_has_async_data(req))
		io_rw_spare_free(req);
	if (put_file)
		io_exec_put_file(req);
	/* Exact same-task io_put_task() fast path (io_uring.c:596-597). */
	req->tctx->cached_refs++;
	/* file_node and buf_node are borrowed, never put by an executor. */
	io_exec_req_cache_put(exec, req);
	percpu_ref_put(&ctx->refs);
}

static void io_exec_adopt(struct io_tw_req tw_req, io_tw_token_t tw)
{
	struct io_kiocb *req = tw_req.req;

	lockdep_assert_held(&req->ctx->uring_lock);
	if (req->file_node)
		req->file_node->refs++;
	if ((req->flags & REQ_F_BUF_NODE) && req->buf_node)
		req->buf_node->refs++;
	req->ctx->nr_req_allocated++;
	io_spare_inflight_done(req->ctx->spare, 1);
	io_req_task_submit(tw_req, tw);
}

/*
 * Executor: give one of its requests to the owner before queueing it there,
 * so a queued request is the owner's already (docs/12 4.7): the owner's task
 * ref is taken here, the executor's own goes back to its cache.
 */
static void io_spare_req_give(struct io_kiocb *req, struct io_spare_grp *grp)
{
	struct task_struct *owner = req->ctx->submitter_task;
	struct io_uring_task *owner_tctx = owner->io_uring;

	req->creds = get_cred(grp->creds);
	req->flags |= REQ_F_CREDS;
	percpu_counter_add(&owner_tctx->inflight, 1);
	get_task_struct(owner);
	current->io_uring->cached_refs++;
	req->tctx = owner_tctx;
}

static void io_exec_bounce(struct io_kiocb *req, int reason)
{
	struct io_chunk *chunk = io_req_chunk(req);

	trace_io_uring_spare_bounce(req->ctx, chunk->seq, req->cqe.user_data, reason);
	io_exec_own_file(req);
	io_spare_req_give(req, chunk->q->grp);
	req->flags &= ~(REQ_F_EXEC | REQ_F_REISSUE);
	memset(&req->big_cqe, 0, sizeof(req->big_cqe));
	req->io_task_work.func = io_exec_adopt;
	chunk->handled++;
	chunk->bounced = true;
	atomic64_inc(&chunk->q->bounced);
	/* Adoption must precede fin, which releases the borrowed resource nodes. */
	io_req_task_work_add(req);
	io_chunk_maybe_fin(chunk);
}

/*
 * Async completions of executor-issued requests.
 *
 * An issued request that went async holds two references: the issue call's,
 * dropped by its executor when the call returns, and the completion's,
 * dropped by whoever finishes the completion. The finisher is chosen when
 * the completion arrives (io_spare_rw_done()): the owner if it is waiting on
 * the CQ, else the executor if it runs and polls its port, else the owner.
 * The executor stores the CQE in the port's journal, the owner posts it
 * directly; either way only the owner touches the CQ. The request object is
 * always freed like the executor's own allocation (io_spare_async_free()),
 * never cached by the owner. No executor ever waits for the owner: an
 * exiting one leaves the rest of its completions to the owner.
 */
static struct io_spare_port *io_req_port(struct io_kiocb *req)
{
	/* Set before issue; extra1 keeps the chunk for the issue call itself. */
	return (struct io_spare_port *)(unsigned long)req->big_cqe.extra2;
}

/* Whether the executor is on a CPU now; a hint, task_structs are RCU-freed. */
static bool io_spare_exec_running(struct io_spare_exec *exec)
{
	struct task_struct *task;
	bool running;

	rcu_read_lock();
	task = READ_ONCE(exec->task);
	running = task && task_curr(task);
	rcu_read_unlock();
	return running;
}

/*
 * State precedes QUEUED's fully ordered RMW. The pop callback clears it and
 * rechecks after smp_mb__after_atomic(): no node can be in work_list twice
 * (mpscq.h:107-120). Ordinary irq_work may signal an eventfd (tw.c:174).
 */
static bool io_spare_rescue_token(struct io_spare_q *q,
				   struct io_spare_exec *exec)
{
	bool queued;

	if (!q->rtoken)
		return false;
	queued = !test_and_set_bit(IO_RTOK_QUEUED, &q->rbits);
	trace_io_uring_spare_rtoken(q->ctx, exec ? exec->exec_id : 0, queued);
	if (!queued)
		return false;
	if (exec && in_task() &&
	    io_spare_dbg_exec(q, IORING_SPARE_DBG_EXEC_TOKEN_CLAIMED, 0, exec)) {
		/* No node was pushed: abandon the claim so exit/irq_work may enqueue. */
		clear_bit(IO_RTOK_QUEUED, &q->rbits);
		smp_mb__after_atomic();
		return true;
	}
	atomic64_inc(&q->token_push);
	io_req_local_work_add(q->rtoken, 0);
	return false;
}

static void io_spare_notify_fn(struct irq_work *work)
{
	struct io_spare_q *q = container_of(work, struct io_spare_q, notify_work);

	io_spare_rescue_token(q, NULL);
}

static void io_spare_rtoken_tw(struct io_tw_req tw_req, io_tw_token_t tw)
{
	struct io_spare_q *q = (void *)(unsigned long)tw_req.req->big_cqe.extra1;
	struct io_ring_ctx *ctx = q->ctx;
	bool drain;

	clear_bit(IO_RTOK_QUEUED, &q->rbits);
	/* Pairs with every producer's ordered test_and_set_bit above. */
	smp_mb__after_atomic();
	if (tw.cancel)
		return;
	q->zp_snap.valid = false;
	drain = test_and_clear_bit(IO_RTOK_DRAIN, &q->rbits);
	if (drain || (ctx->int_flags & IO_RING_F_DRAIN_ACTIVE))
		io_spare_queue_deferred(ctx);
	if (q->pull_ok && io_spare_pull_wait(q)) {
		set_bit(IO_RTOK_TAKEOVER, &q->rbits);
		/* __io_run_local_work() already cleared this at tw.c:332. */
		atomic_or(IORING_SQ_TASKRUN, &ctx->rings->sq_flags);
	}
}

/*
 * Last reference: free it as its executor would, from whichever task drops
 * it. Only now may the iterator go, since the issue call can still touch it
 * after the completion (io_req_rw_cleanup()).
 */
static void io_spare_async_free(struct io_kiocb *req)
{
	struct io_spare_exec *exec = io_spare_req_exec(req);
	struct io_spare_port *port = io_req_port(req);
	struct io_ring_ctx *ctx = req->ctx;

	req->flags &= ~REQ_F_REFCOUNT;
	io_rw_spare_finish(req, false);
	if (req_has_async_data(req))
		io_rw_spare_free(req);
	io_exec_put_file(req);
	/* The executor's task ref, as io_put_task() (io_uring.c) puts it. */
	if (likely(req->tctx->task == current)) {
		req->tctx->cached_refs++;
	} else {
		percpu_counter_sub(&req->tctx->inflight, 1);
		if (unlikely(atomic_read(&req->tctx->in_cancel)))
			wake_up(&req->tctx->wait);
		put_task_struct(req->tctx->task);
	}
	io_exec_req_cache_put(exec, req);
	/* The borrowed resource nodes stay frozen until here (io_spare_frozen()). */
	smp_mb__before_atomic();
	atomic_dec(&port->outstanding);
	percpu_ref_put(&ctx->refs);
}

static void io_spare_reissue_tw(struct io_tw_req tw_req, io_tw_token_t tw);

/* Drop the issue or the completion reference of an async executor request. */
static void io_spare_async_put(struct io_kiocb *req)
{
	if (!req_ref_put_and_test(req))
		return;
	if (req->flags & REQ_F_REISSUE) {
		/* Given to the owner by whoever finished it: reissue it there. */
		req->io_task_work.func = io_spare_reissue_tw;
		io_req_task_work_add(req);
		return;
	}
	io_spare_async_free(req);
}

/*
 * Owner: a completion asked for a reissue. Adopt the request like a bounce,
 * so it holds the node refs itself, and let the normal completion punt it
 * to the owner's io-wq (io_free_batch_list()).
 */
static void io_spare_reissue_tw(struct io_tw_req tw_req, io_tw_token_t tw)
{
	struct io_kiocb *req = tw_req.req;
	struct io_spare_port *port = io_req_port(req);
	struct io_ring_ctx *ctx = req->ctx;

	lockdep_assert_held(&ctx->uring_lock);
	trace_io_uring_spare_async(ctx, req->cqe.user_data, req->cqe.res,
				   IO_SPARE_ASYNC_REISSUE);
	/* The chunk may retire before the reissue completes: own the file. */
	io_exec_own_file(req);
	req->flags &= ~(REQ_F_EXEC | REQ_F_REFCOUNT);
	memset(&req->big_cqe, 0, sizeof(req->big_cqe));
	if (req->file_node)
		req->file_node->refs++;
	if ((req->flags & REQ_F_BUF_NODE) && req->buf_node)
		req->buf_node->refs++;
	ctx->nr_req_allocated++;
	/* The ring's request now: the drain gate counts it there. */
	io_spare_inflight_done(port->q, 1);
	smp_mb__before_atomic();
	atomic_dec(&port->outstanding);
	if (tw.cancel) {
		req->flags &= ~REQ_F_REISSUE;
		req_set_fail(req);
		io_req_set_res(req, -ECANCELED, 0);
	}
	io_req_rw_complete(tw_req, tw);
}

/*
 * Owner, not in cancel mode: take over the executor's task ref of a request
 * to reissue, the owner-side counterpart of io_spare_req_give().
 */
static void io_spare_req_take(struct io_kiocb *req, struct io_spare_grp *grp)
{
	struct io_uring_task *tctx = req->tctx;

	WARN_ON_ONCE(current != req->ctx->submitter_task);
	/* The remote path of io_put_task(). */
	percpu_counter_sub(&tctx->inflight, 1);
	if (unlikely(atomic_read(&tctx->in_cancel)))
		wake_up(&tctx->wait);
	put_task_struct(tctx->task);
	io_get_task_refs(1);
	req->tctx = current->io_uring;
	req->creds = get_cred(grp->creds);
	req->flags |= REQ_F_CREDS;
}

/*
 * Owner: finish a completion its executor does not take, posting the CQE
 * directly. Only the completion's reference is dropped: the request may still
 * be in its executor's issue call.
 */
static void io_spare_owner_finish(struct io_kiocb *req, bool cancel)
{
	struct io_spare_port *port = io_req_port(req);
	struct io_ring_ctx *ctx = req->ctx;

	lockdep_assert_held(&ctx->uring_lock);
	if (req->flags & REQ_F_REISSUE) {
		if (!cancel) {
			atomic64_inc(&port->q->bounced);
			trace_io_uring_spare_bounce(ctx, 0, req->cqe.user_data,
						    IO_SPARE_BOUNCE_REISSUE);
			io_spare_req_take(req, port->q->grp);
			io_spare_async_put(req);
			return;
		}
		req->flags &= ~REQ_F_REISSUE;
		req_set_fail(req);
		io_req_set_res(req, -ECANCELED, 0);
	}
	io_rw_spare_notify(req);
	io_add_aux_cqe(ctx, req->cqe.user_data, req->cqe.res, req->cqe.flags);
	io_spare_inflight_done(port->q, 1);
	trace_io_uring_spare_async(ctx, req->cqe.user_data, req->cqe.res,
				   IO_SPARE_ASYNC_OWNER);
	port->q->async_owner++;
	io_spare_async_put(req);
}

static void io_spare_rw_owner(struct io_tw_req tw_req, io_tw_token_t tw)
{
	io_spare_owner_finish(tw_req.req, tw.cancel);
}

/* Queue a completion to the owner, as any DEFER_TASKRUN completion is queued. */
static void io_spare_route_owner(struct io_kiocb *req)
{
	req->io_task_work.func = io_spare_rw_owner;
	__io_req_task_work_add(req, IOU_F_TWQ_LAZY_WAKE);
}

/* Any context: route every completion queued to the port to the owner, oldest first. */
static void io_spare_port_steal(struct io_spare_port *port)
{
	struct llist_node *node = llist_reverse_order(llist_del_all(&port->done));
	unsigned int nr = 0;

	while (node) {
		struct io_kiocb *req = container_of(node, struct io_kiocb,
						    io_task_work.node);

		node = node->next;
		io_spare_route_owner(req);
		nr++;
	}
	if (nr)
		atomic64_add(nr, &port->q->async_steal);
}

/*
 * Any context, usually the completion IRQ. Whoever is idle finishes it: the
 * owner if it waits on the CQ, as it would only sleep otherwise; else the
 * executor if it runs and polls the port, keeping the work off the busy
 * owner; else the owner, as a plain DEFER_TASKRUN completion.
 */
void io_spare_rw_done(struct io_kiocb *req)
{
	struct io_spare_port *port = io_req_port(req);
	struct io_ring_ctx *ctx = req->ctx;
	/*
	 * EXEC_FINISH: a running executor polling the port finishes even what
	 * the owner waits for; its flush wakes the owner (io_spare_lazy_wake()).
	 * The owner's wait path leaves such ports alone (io_spare_port_stranded()).
	 */
	bool exec_finish = port->q->flags & IORING_SPARE_F_EXEC_FINISH;

	/* The port lives in the ring, and req's own ref may go once it is queued. */
	percpu_ref_get(&ctx->refs);
	if ((exec_finish || atomic_read(&ctx->cq_wait_nr) < 0) &&
	    READ_ONCE(port->active) && io_spare_exec_running(port->exec)) {
		llist_add(&req->io_task_work.node, &port->done);
		/*
		 * Dekker pairs: done add / active load with io_exec_port_deactivate(),
		 * and done add / cq_wait_nr load with the owner's cq_wait_nr store ->
		 * set_current_state() -> io_spare_wait_unserved()'s done load.
		 */
		smp_mb();
		/* Deactivated, or the owner began to wait, since the checks above. */
		if (unlikely(!READ_ONCE(port->active) ||
			     (!exec_finish && atomic_read(&ctx->cq_wait_nr) >= 0)))
			io_spare_port_steal(port);
	} else {
		/* Earlier ones an executor off CPU has left go first. */
		if (!llist_empty(&port->done) && (!READ_ONCE(port->active) ||
		    !io_spare_exec_running(port->exec)))
			io_spare_port_steal(port);
		io_spare_route_owner(req);
	}
	percpu_ref_put(&ctx->refs);
}

/*
 * uring_lock held: post the journal entries stored since the last post. The
 * owner from its token, harvest or wait; the executor itself when it could
 * take the lock (io_exec_port_flush()). Returns the number posted.
 */
static unsigned int io_spare_port_post(struct io_spare_port *port, int src,
				       unsigned int max)
{
	struct io_ring_ctx *ctx = port->q->ctx;
	unsigned int from = port->posted, p, i;

	/* Pairs with the executor's release of produced in io_exec_port_reap(). */
	p = smp_load_acquire(&port->produced);
	if (p == from)
		return 0;
	/* An executor bounds its hold of uring_lock; the owner posts everything. */
	if (p - from > max)
		p = from + max;
	trace_io_uring_spare_post(ctx, 0, from, p, src);
	for (i = from; i != p; i++) {
		struct io_cqe *cqe = &port->journal[i & (IO_SPARE_JOURNAL - 1)];

		io_add_aux_cqe(ctx, cqe->user_data, cqe->res, cqe->flags);
	}
	io_spare_inflight_done(port->q, p - from);
	/* Pairs with the executor's acquire before it reuses posted entries. */
	smp_store_release(&port->posted, p);
	return p - from;
}

static void io_spare_port_tw(struct io_tw_req tw_req, io_tw_token_t tw)
{
	struct io_spare_port *port = io_req_port(tw_req.req);

	WRITE_ONCE(port->kick_seen, READ_ONCE(port->kick_sent));
	/* Dekker pair: executor's produced store / kick_seen load (io_exec_port_kick()). */
	smp_mb();
	io_spare_port_post(port, IO_SPARE_POST_PORT, UINT_MAX);
}

/*
 * Count nr more CQEs towards a waiter's min_events, as nr lazy task_work
 * adds would (the countdown of io_req_local_work_add(), wait.h).
 */
static void io_spare_lazy_wake(struct io_ring_ctx *ctx, int nr)
{
	int old = atomic_read(&ctx->cq_wait_nr);

	do {
		if (nr <= 0 || old <= 0)
			return;
	} while (!atomic_try_cmpxchg(&ctx->cq_wait_nr, &old, max(old - nr, 0)));
	if (old <= nr)
		wake_up_state(ctx->submitter_task, TASK_INTERRUPTIBLE);
}

/*
 * Executor: let the owner post the journal. Like a chunk lease, the token is
 * pushed only once the owner has picked up the previous push, so it is never
 * queued twice; a queued token posts everything stored before it runs.
 */
static void io_exec_port_kick(struct io_spare_port *port, int nr)
{
	/* Dekker pair: owner's kick_seen store / produced load (io_spare_port_tw()). */
	smp_mb();
	if (READ_ONCE(port->kick_seen) == port->kick_sent) {
		WRITE_ONCE(port->kick_sent, port->kick_sent + 1);
		port->kicks++;
		io_req_local_work_add(port->token, IOU_F_TWQ_LAZY_WAKE);
		nr--;
	}
	io_spare_lazy_wake(port->q->ctx, nr);
}

/*
 * Executor: finish the completions queued to the port and store their CQEs
 * for the owner; what the journal has no room for goes to the owner instead.
 * Returns the number taken.
 */
static unsigned int io_exec_port_reap(struct io_spare_port *port)
{
	struct io_spare_q *q = port->q;
	struct io_ring_ctx *ctx = q->ctx;
	struct llist_node *node;
	bool cancel = percpu_ref_is_dying(&ctx->refs);
	unsigned int p = port->produced, nr = 0, stored = 0, room;

	/* Test hook: an executor held here with completions queued is "off CPU" for the owner's steal. */
	if (!llist_empty(&port->done) && READ_ONCE(port->active))
		io_spare_dbg_exec(q, IORING_SPARE_DBG_EXEC_BEFORE_REAP, 0, port->exec);
	node = llist_del_all(&port->done);
	if (!node)
		return 0;
	/* Pairs with io_spare_port_post() releasing the entries it has posted. */
	room = IO_SPARE_JOURNAL - (p - smp_load_acquire(&port->posted));
	node = llist_reverse_order(node);
	while (node) {
		struct io_kiocb *req = container_of(node, struct io_kiocb,
						    io_task_work.node);

		node = node->next;
		nr++;
		if (req->flags & REQ_F_REISSUE) {
			if (!cancel) {
				atomic64_inc(&q->bounced);
				trace_io_uring_spare_bounce(ctx, 0, req->cqe.user_data,
							    IO_SPARE_BOUNCE_REISSUE);
				io_spare_req_give(req, q->grp);
				io_spare_async_put(req);
				continue;
			}
			req->flags &= ~REQ_F_REISSUE;
			req_set_fail(req);
			io_req_set_res(req, -ECANCELED, 0);
		}
		if (!room) {
			io_spare_route_owner(req);
			continue;
		}
		io_rw_spare_notify(req);
		port->journal[p++ & (IO_SPARE_JOURNAL - 1)] = (struct io_cqe) {
			.user_data = req->cqe.user_data, .res = req->cqe.res,
			.flags = req->cqe.flags };
		trace_io_uring_spare_async(ctx, req->cqe.user_data, req->cqe.res,
					   IO_SPARE_ASYNC_EXEC);
		room--;
		stored++;
		/* The port is held with a ctx ref: freeing may drop the request's. */
		io_spare_async_put(req);
	}
	if (stored) {
		/* Pairs with io_spare_port_post() acquiring produced. */
		smp_store_release(&port->produced, p);
		port->async_exec += stored;
		if (!port->batch)
			port->unflushed_since = local_clock();
		port->batch += stored;
		io_exec_port_flush_maybe(port);
	}
	return nr;
}

/*
 * Executor: take uring_lock for a direct post if it can be had within
 * flush_spin_ns. A trylock that fails mostly meets a sibling posting its own
 * few CQEs (a fraction of a microsecond), sometimes the owner's local work or
 * harvest; kicking the owner instead delayed those CQEs until it woke and cost
 * it the posting (a fifth of all CQEs at three executors, round 3).
 */
static bool io_exec_lock_for_post(struct io_ring_ctx *ctx)
{
	unsigned int spin_ns = READ_ONCE(io_spare_flush_spin_ns), spins = 256;
	u64 deadline;

	if (mutex_trylock(&ctx->uring_lock))
		return true;
	if (!spin_ns)
		return false;
	/* ktime, not local_clock(): an unpinned executor may migrate meanwhile. */
	deadline = ktime_get_ns() + spin_ns;
	do {
		cpu_relax();
		if (!mutex_is_locked(&ctx->uring_lock) && mutex_trylock(&ctx->uring_lock))
			return true;
	} while (ktime_get_ns() < deadline && --spins);
	return false;
}

/*
 * Executor: post the journal entries it stored since the last post itself,
 * if uring_lock can be had without waiting (the owner is in user space or
 * asleep: it holds the lock only while it submits, runs task_work or
 * rescues); otherwise kick the owner to post them. One poster at a time
 * either way, the owner's own lock serializing both. OWNER_POST never tries.
 */
static void io_exec_port_flush(struct io_spare_port *port)
{
	struct io_spare_q *q = port->q;
	struct io_ring_ctx *ctx = q->ctx;
	unsigned int nr, posted;

	if (!port->batch)
		return;
	port->batch = 0;
	/* The owner may have harvested meanwhile: count what is really unposted. */
	nr = port->produced - smp_load_acquire(&port->posted);
	if (!nr)
		return;
	/*
	 * A drain waits in io_queue_deferred(), which only the owner's flush
	 * re-runs: while one is active the owner must post, so it sees the
	 * inflight count fall.
	 */
	if (!(q->flags & IORING_SPARE_F_OWNER_POST) &&
	    !(READ_ONCE(ctx->int_flags) & IO_RING_F_DRAIN_ACTIVE) &&
	    io_exec_lock_for_post(ctx)) {
		/* The flag changes only under uring_lock: the check above was a hint. */
		if (ctx->int_flags & IO_RING_F_DRAIN_ACTIVE) {
			mutex_unlock(&ctx->uring_lock);
			io_exec_port_kick(port, nr);
			return;
		}
		posted = io_spare_port_post(port, IO_SPARE_POST_DIRECT,
					    IO_SPARE_DIRECT_MAX);
		io_spare_commit_cqes(ctx);
		mutex_unlock(&ctx->uring_lock);
		port->direct += posted;
		/*
		 * Dekker pair with io_cqring_wait(): the CQ tail store above is a
		 * release only; it must be visible before the waiter count is read,
		 * as the owner stores cq_wait_nr, then set_current_state() (full
		 * barrier), then loads the tail. mpscq_push()'s xchg does this for
		 * task_work adds.
		 */
		smp_mb();
		/* As lazy task_work adds would count for a waiter. */
		io_spare_lazy_wake(ctx, posted);
		/* What the bound left waits for the next flush point. */
		port->batch = nr - posted;
		return;
	}
	io_exec_port_kick(port, nr);
}

/*
 * Executor, at a flush point that is not a drain: post the journal, unless
 * (EXEC_FINISH) the owner sleeps on a deep queue and the batch is still small
 * and young: then a few more completions gather first, so the owner wakes
 * once per batch rather than per completion wave. Age-bounded, so a trickle
 * still posts within flush_delay_us; a shallow queue posts at once. An owner
 * that waits for a count (q->wait_batched) is woken only once that many are
 * posted (io_spare_lazy_wake()): posting at once costs it no wake and gives
 * it its batch sooner. Depth is this port's outstanding requests or, with
 * flush_ring_depth, the ring's delegated-live count.
 * Dekker pair with io_spare_wait_unserved(): produced store -> smp_mb() ->
 * cq_wait_nr load here, cq_wait_nr store -> barrier -> produced load there,
 * so an owner that saw nothing to harvest is woken by this flush or the next.
 */
static void io_exec_port_flush_maybe(struct io_spare_port *port)
{
	struct io_spare_q *q = port->q;
	struct io_ring_ctx *ctx = q->ctx;

	if (!port->batch)
		return;
	if ((q->flags & IORING_SPARE_F_EXEC_FINISH) &&
	    !(READ_ONCE(q->wait_batched) && READ_ONCE(io_spare_batch_post)) &&
	    port->batch < READ_ONCE(io_spare_flush_batch) &&
	    (READ_ONCE(io_spare_flush_ring_depth) ? atomic_read(&q->live) :
	     atomic_read(&port->outstanding)) >= IO_SPARE_FLUSH_DEEP_QD) {
		smp_mb();
		if (atomic_read(&ctx->cq_wait_nr) >= 0 &&
		    local_clock() - port->unflushed_since <
		    (u64)READ_ONCE(io_spare_flush_delay_us) * NSEC_PER_USEC)
			return;
	}
	io_exec_port_flush(port);
}

/*
 * Executor: a completion it finished while scanning the chunk. Its CQE goes
 * to the port journal, posted directly or by the owner (io_exec_port_flush());
 * only a full journal falls back to the chunk's own buffer and lease.
 */
static void io_exec_done(struct io_chunk *chunk, u64 data, s32 res, u32 flags)
{
	struct io_spare_port *port = chunk->port;
	unsigned int p = port->produced;

	if (IO_SPARE_JOURNAL - (p - smp_load_acquire(&port->posted)) == 0) {
		io_chunk_record(chunk, data, res, flags);
		return;
	}
	port->journal[p & (IO_SPARE_JOURNAL - 1)] = (struct io_cqe) {
		.user_data = data, .res = res, .flags = flags };
	if (res == -ECANCELED)
		atomic64_inc(&chunk->q->cancelled);
	/* Pairs with io_spare_port_post() acquiring produced. */
	smp_store_release(&port->produced, p + 1);
	trace_io_uring_spare_complete(chunk->q->ctx, chunk->seq,
				      (p & (IO_SPARE_JOURNAL - 1)) | IO_SPARE_TRACE_JOURNAL,
				      data, res);
	if (++port->batch >= IO_SPARE_KICK_BATCH)
		io_exec_port_flush(port);
}

/* Executor, at claim: completions of this ring's requests may now come to it. */
static void io_exec_port_activate(struct io_spare_exec *exec,
				  struct io_spare_port *port)
{
	if (port->active)
		return;
	/* Reaps and kicks touch the port after the frees that drop request refs. */
	percpu_ref_get(&port->q->ctx->refs);
	WRITE_ONCE(port->held, true);
	list_add_tail(&port->node, &exec->ports);
	WRITE_ONCE(port->active, true);
}

/*
 * Executor: completions go to the owner from now on. Reap what was queued
 * before the store became visible, then let go of the ring.
 */
static void io_exec_port_deactivate(struct io_spare_port *port)
{
	struct io_ring_ctx *ctx = port->q->ctx;

	WRITE_ONCE(port->active, false);
	/* Dekker pair with io_spare_rw_done(): active store / done load. */
	smp_mb();
	io_exec_port_reap(port);
	io_exec_port_flush(port);
	list_del_init(&port->node);
	/* Registration may reuse the port only once nothing here touches it. */
	smp_store_release(&port->held, false);
	percpu_ref_put(&ctx->refs);
}

/*
 * Executor: reap every port it polls. An idle port stays (claims would only
 * pick it up again) unless its ring is detached or going away, which must
 * not wait for this executor to sleep.
 */
static unsigned int io_exec_ports_reap(struct io_spare_exec *exec)
{
	struct io_spare_port *port, *next;
	unsigned int nr = 0;

	list_for_each_entry_safe(port, next, &exec->ports, node) {
		if (!llist_empty(&port->done))
			nr += io_exec_port_reap(port);
		else if (!atomic_read(&port->outstanding) &&
			 (!READ_ONCE(port->q->attached) ||
			  percpu_ref_is_dying(&port->q->ctx->refs))) {
			io_exec_port_deactivate(port);
			continue;
		}
		/* Every drain ends with the journal posted or the owner kicked, or gathering (EXEC_FINISH). */
		io_exec_port_flush_maybe(port);
	}
	return nr;
}

static void io_exec_ports_release(struct io_spare_exec *exec)
{
	struct io_spare_port *port, *next;

	list_for_each_entry_safe(port, next, &exec->ports, node)
		io_exec_port_deactivate(port);
}

static bool io_spare_write(u8 opcode)
{
	return opcode == IORING_OP_WRITE || opcode == IORING_OP_WRITE_FIXED;
}

static bool io_spare_eligible(const struct io_uring_sqe *sqe, bool executor)
{
	u8 opcode = READ_ONCE(sqe->opcode);
	u8 flags = READ_ONCE(sqe->flags);
	u16 personality = READ_ONCE(sqe->personality);
	u64 attr = READ_ONCE(sqe->attr_type_mask);
	u64 off = READ_ONCE(sqe->off);

	if (opcode >= IORING_OP_LAST)
		return false;
	opcode = array_index_nospec(opcode, IORING_OP_LAST);
	/* ASYNC asks for an async worker: an executor is one, so it is ignored. */
	if (flags & ~(IOSQE_FIXED_FILE | IOSQE_ASYNC) || personality || attr ||
	    off == U64_MAX)
		return false;
	if (opcode != IORING_OP_READ && opcode != IORING_OP_READ_FIXED &&
	    !io_spare_write(opcode))
		return false;
	if (io_spare_write(opcode) && rlimit(RLIMIT_FSIZE) != RLIM_INFINITY)
		return false;
	return !executor || !io_issue_defs[opcode].is_128;
}

/* The force_nonblock checks of io_write() that fail on every issue (rw.c). */
static bool io_spare_write_punts(struct file *file)
{
	if (!S_ISREG(file_inode(file)->i_mode))
		return false;
	return !(file->f_mode & FMODE_NOWAIT) ||
	       (!(READ_ONCE(file->f_flags) & O_DIRECT) &&
		!(file->f_op->fop_flags & FOP_BUFFER_WASYNC));
}

/*
 * Owner side. A write the executor could only bounce, such as a buffered
 * write to ext4 (no FOP_BUFFER_WASYNC), stays inline when executors may not
 * block (NO_BLOCK); otherwise the executor issues it blocking after its scan.
 * This is a hint: a stale file is harmless, the executor re-checks everything
 * and bounces what it must.
 */
static bool io_spare_delegable(struct io_ring_ctx *ctx,
			       const struct io_uring_sqe *sqe)
{
	unsigned int fd = READ_ONCE(sqe->fd);
	struct io_rsrc_node *node;
	struct file *file;
	bool punts;

	if (!io_spare_eligible(sqe, false))
		return false;
	if (!io_spare_write(READ_ONCE(sqe->opcode)) ||
	    !(ctx->spare->flags & IORING_SPARE_F_NO_BLOCK))
		return true;
	if (READ_ONCE(sqe->flags) & IOSQE_FIXED_FILE) {
		/* The table is frozen while attached; a miss fails in the executor. */
		node = io_rsrc_node_lookup(&ctx->file_table.data, fd);
		return !node || !io_spare_write_punts(io_slot_file(node));
	}
	/* No reference: files are SLAB_TYPESAFE_BY_RCU, a recycled one only misleads. */
	rcu_read_lock();
	file = files_lookup_fd_raw(current->files, fd);
	punts = file && io_spare_write_punts(file);
	rcu_read_unlock();
	return !punts;
}

/* q->lock is NOT needed: only the submitter reads/advances the SQ head. */
static const struct io_uring_sqe *io_spare_peek(struct io_ring_ctx *ctx,
					      unsigned int offset)
{
	unsigned int head = (ctx->cached_sq_head + offset) & (ctx->sq_entries - 1);

	/* Same indexing as io_get_sqe(), without its static-key optimization. */
	if (!(ctx->flags & IORING_SETUP_NO_SQARRAY)) {
		head = READ_ONCE(ctx->sq_array[head]);
		if (head >= ctx->sq_entries)
			return NULL;
		head = array_index_nospec(head, ctx->sq_entries);
	}
	if (ctx->flags & IORING_SETUP_SQE128)
		head <<= 1;
	return &ctx->sq_sqes[head];
}

static void io_spare_ready(struct io_spare_q *q, unsigned int min_events,
			   bool wait)
{
	struct io_ring_ctx *ctx = q->ctx;
	struct io_rings *rings;
	bool ready;

	rcu_read_lock();
	rings = io_get_rings(ctx);
	ready = min_events &&
		READ_ONCE(rings->cq.tail) - READ_ONCE(rings->cq.head) >= min_events;
	rcu_read_unlock();
	q->ready_hits = ready ? min(q->ready_hits + 1, 2U) : 0;
	trace_io_uring_spare_signal(ctx, wait, min_events, q->ready_hits);
}

void io_spare_wait_start(struct io_ring_ctx *ctx, unsigned int min_events)
{
	struct io_spare_q *q = ctx->spare;
	u64 now;

	if (!q || current != ctx->submitter_task)
		return;
	/*
	 * Owner utilization for the executors' plug decision: the share of the
	 * wait-to-wait cycle just ended that was not spent asleep on the CQ
	 * (io_spare_wait_woke() accounts the sleeps), EWMA over eight cycles.
	 */
	now = ktime_get_ns();
	if (q->t_sleep) {
		q->blocked_acc += now - q->t_sleep;
		q->t_sleep = 0;
	}
	if (q->t_wait_last && now > q->t_wait_last) {
		u64 wall = now - q->t_wait_last;
		u64 blocked = min(q->blocked_acc, wall);
		u32 busy = div64_u64((wall - blocked) << 10, wall);

		WRITE_ONCE(q->owner_busy, (READ_ONCE(q->owner_busy) * 7 + busy) >> 3);
	}
	q->t_wait_last = now;
	q->blocked_acc = 0;
	io_spare_ready(q, min_events, true);
	/*
	 * An owner that waits for a count is woken once that many CQEs have been
	 * posted (io_spare_lazy_wake()): executors then post at once instead of
	 * coalescing for it (io_exec_port_flush_maybe()). Sticky, stored once.
	 */
	if (min_events > 1 && !READ_ONCE(q->wait_batched))
		WRITE_ONCE(q->wait_batched, 1);
	if (q->pull_ok) {
		/* tw.c:332 clears TASKRUN before rtoken marks this entry's takeover. */
		if (test_and_clear_bit(IO_RTOK_TAKEOVER, &q->rbits))
			io_spare_wait_takeover(ctx);
		if (io_spare_pull_work(q, atomic64_read(&q->lease)))
			io_spare_pull_wake(q);
	}
}

void io_spare_submit_start(struct io_ring_ctx *ctx, unsigned int nr)
{
	struct io_spare_q *q = ctx->spare;

	lockdep_assert_held(&ctx->uring_lock);
	if (!q || current != ctx->submitter_task)
		return;
	/* Entry hook is also needed for repeated equal-sized SQ_REWIND batches. */
	q->sampled = true;
	q->sample_end = ctx->cached_sq_head + nr;
	q->short_end = ctx->cached_sq_head;
	q->t_submit = local_clock();
	q->t_delegate = 0;
	q->n_deleg_sub = 0;
	io_spare_ready(q, 1, false);
	/* Must precede io_submit_state_start(): copied submits start their own batch. */
	if (READ_ONCE(q->nr_pending) &&
	    (!q->attached || READ_ONCE(q->nr_pending) >= q->u_pending))
		io_spare_rescue_locked(ctx, false, false);
}

/*
 * Owner, after the submission loop: what the SQEs it issued inline cost it
 * per SQE, flush of their completions included. Short submissions carry the
 * syscall's fixed part, so only a batch's worth is sampled.
 */
void io_spare_submit_end(struct io_ring_ctx *ctx, unsigned int submitted)
{
	struct io_spare_q *q = ctx->spare;
	unsigned int n;
	u64 total;

	if (!q || current != ctx->submitter_task || !q->t_submit)
		return;
	total = local_clock() - q->t_submit;
	q->t_submit = 0;
	if (submitted <= q->n_deleg_sub)
		return;
	n = submitted - q->n_deleg_sub;
	if (n >= 4 && total > q->t_delegate)
		io_spare_ewma(&q->cost_inline, div_u64(total - q->t_delegate, n));
}

/*
 * The run length from which starting a chunk pays: n SQEs delegated cost the
 * owner cost_chunk + n * IO_SPARE_COPY_NS and save n * cost_inline. The
 * registered n_min caps it (and is it, in ALWAYS mode or with FIXED_NMIN).
 */
static unsigned int io_spare_threshold(struct io_spare_q *q)
{
	unsigned int saving;

	if (q->mode == IORING_SPARE_MODE_ALWAYS ||
	    (q->flags & IORING_SPARE_F_FIXED_NMIN))
		return q->n_min;
	if (q->cost_inline <= IO_SPARE_COPY_NS)
		return q->n_max + 1;
	saving = q->cost_inline - IO_SPARE_COPY_NS;
	return clamp_t(unsigned int, q->cost_chunk / saving + 1, 1, q->n_min);
}

/*
 * Owner: reference the files the first n SQEs of the run name, one reference
 * per distinct file, as inline submission takes one per request at submit
 * time. A closed fd (inline fails it with -EBADF) or a fifth distinct file
 * ends the run before that SQE. Returns the usable run length.
 */
static unsigned int io_spare_run_files(struct io_ring_ctx *ctx,
				       struct io_spare_run *run, unsigned int n)
{
	unsigned int i, k;

	run->nr_files = 0;
	for (i = 0; i < n; i++) {
		const struct io_uring_sqe *sqe = io_spare_peek(ctx, i);
		struct file *file;

		if (READ_ONCE(sqe->flags) & IOSQE_FIXED_FILE) {
			run->fidx[i] = IO_SPARE_NO_FILE;
			continue;
		}
		/* A file the run already references needs no second reference. */
		rcu_read_lock();
		file = files_lookup_fd_raw(current->files, READ_ONCE(sqe->fd));
		for (k = 0; k < run->nr_files && run->files[k] != file; k++)
			;
		rcu_read_unlock();
		if (file && k < run->nr_files) {
			run->fidx[i] = k;
			continue;
		}
		file = fget(READ_ONCE(sqe->fd));
		if (!file)
			break;
		for (k = 0; k < run->nr_files && run->files[k] != file; k++)
			;
		if (k < run->nr_files) {
			fput(file);
		} else if (k == IO_SPARE_CHUNK_FILES) {
			fput(file);
			break;
		} else {
			run->files[k] = file;
			run->nr_files = k + 1;
		}
		run->fidx[i] = k;
	}
	return i;
}

/* The run's references that did not move into a chunk. */
static void io_spare_run_put(struct io_spare_run *run)
{
	while (run->nr_files) {
		struct file *file = run->files[--run->nr_files];

		if (file)
			fput(file);
	}
}

/*
 * Under q->lock: how many of the run's first n SQEs can join chunk, whose
 * file table must hold their files. A joining file's reference moves to the
 * chunk (the run's slot is cleared); fidx is remapped in place.
 */
static unsigned int io_spare_run_merge(struct io_chunk *chunk,
				       struct io_spare_run *run, unsigned int n)
{
	u8 map[IO_SPARE_CHUNK_FILES];
	unsigned int i, j, k;

	for (k = 0; k < run->nr_files; k++) {
		for (j = 0; j < chunk->nr_files &&
		     chunk->files[j] != run->files[k]; j++) {
		}
		map[k] = j < chunk->nr_files ? j : IO_SPARE_NO_FILE;
	}
	for (i = 0; i < n; i++) {
		k = run->fidx[i];
		if (k == IO_SPARE_NO_FILE)
			continue;
		if (map[k] == IO_SPARE_NO_FILE) {
			if (chunk->nr_files == IO_SPARE_CHUNK_FILES)
				break;
			map[k] = chunk->nr_files;
			chunk->files[chunk->nr_files++] = run->files[k];
			run->files[k] = NULL;
		}
		run->fidx[i] = map[k];
	}
	return i;
}

/*
 * Owner: add the run's first SQEs to the ring's last chunk while no executor
 * has claimed it. The chunk's cost is paid already, so a run too short to
 * start a chunk still leaves the owner. Appends are under q->lock, as the
 * claim and the rescue scan that read n are. Returns the SQEs appended.
 */
static unsigned int io_spare_append(struct io_ring_ctx *ctx,
				    struct io_spare_run *run, unsigned int n,
				    unsigned int left, bool *stop)
{
	struct io_spare_q *q = ctx->spare;
	struct io_chunk *tail = NULL;
	const struct io_uring_sqe *sqe;
	unsigned int copied = 0, base = 0, room = 0;

	spin_lock(&q->lock);
	if (!list_empty(&q->pending)) {
		tail = list_last_entry(&q->pending, struct io_chunk, list);
		room = q->n_max - tail->n;
		if (room)
			room = io_spare_run_merge(tail, run, min(n, room));
		if (!room)
			tail = NULL;
	}
	if (tail) {
		base = tail->n;
		memset(tail->slot + base, IO_SPARE_FREE, room);
		while (copied < room) {
			if (!io_get_sqe(ctx, &sqe)) {
				*stop = true;
				break;
			}
			memcpy(&tail->sqes[base + copied], sqe, sizeof(*sqe));
			tail->fidx[base + copied] = run->fidx[copied];
			copied++;
		}
		tail->n = base + copied;
	}
	spin_unlock(&q->lock);
	if (!tail)
		return 0;
	current->io_uring->cached_refs += copied;
	atomic64_add(copied, &q->delegated);
	atomic_add(copied, &q->live);
	q->appended += copied;
	trace_io_uring_spare_append(ctx, tail->seq, base, copied);
	/* A sleeper is on its way to this chunk since its publication; ALWAYS adds for backlog. */
	io_spare_wake(q, left, q->mode == IORING_SPARE_MODE_ALWAYS);
	return copied;
}

/*
 * Returns true if a sleeper was woken. force (ALWAYS, after a publish) wakes
 * only for group backlog beyond the awake executors and the wakes already in
 * flight: an awake executor polls nr_pending and claims by itself, so waking
 * a sleeper for every chunk mostly woke executors that found nothing (98% of
 * wakes with three rings sharing two executors).
 */
static bool io_spare_wake(struct io_spare_q *q, unsigned int demand, bool force)
{
	struct io_spare_grp *grp = q->grp;
	int credit, awake, asleep;

	if (!force && q->ready_hits < 2 && demand < q->n_max)
		return false;
	for (;;) {
		credit = atomic_read(&grp->wake_credit);
		awake = atomic_read(&grp->nr_awake);
		asleep = atomic_read(&grp->nr_live) - awake;
		if (force) {
			if (atomic_read(&grp->nr_pending) <= awake + credit)
				return false;
		} else if (asleep <= READ_ONCE(q->nr_pending) + credit) {
			return false;
		}
		if (credit >= asleep)
			return false;
		if (atomic_cmpxchg(&grp->wake_credit, credit, credit + 1) == credit)
			break;
	}
	atomic64_inc(&q->wakes);
	trace_io_uring_spare_wake(q->ctx, IO_SPARE_WAKE_CREDIT, awake,
				  atomic_read(&grp->nr_live), credit + 1);
	/* Where the work is: the woken executor tries this ring first. */
	spin_lock(&grp->lock);
	grp->hint = q;
	spin_unlock(&grp->lock);
	wake_up_nr(&grp->wq, 1);
	return true;
}

/* The owner keeps the SQ head inline: counted for fdinfo, traced per call. */
static unsigned int io_spare_skip(struct io_spare_q *q, int reason,
				  unsigned int left)
{
	q->skip[reason]++;
	trace_io_uring_spare_skip(q->ctx, reason, left);
	return 0;
}

unsigned int io_spare_delegate(struct io_ring_ctx *ctx, unsigned int left,
			       bool *stop)
{
	struct io_spare_q *q = ctx->spare;
	struct io_spare_run *run = q->run;
	const struct io_uring_sqe *sqe;
	struct io_chunk *chunk;
	struct io_kiocb *lease, *fin;
	unsigned int n, i, copied = 0, thr;
	u64 t0;

	lockdep_assert_held(&ctx->uring_lock);
	if (!READ_ONCE(q->attached) || READ_ONCE(q->dead) ||
	    q->mode == IORING_SPARE_MODE_NEVER || !left)
		return 0;
	/* All loop iterations of one submission have the same end cursor. */
	if (!q->sampled || q->sample_end != ctx->cached_sq_head + left) {
		q->sampled = true;
		q->sample_end = ctx->cached_sq_head + left;
		q->short_end = ctx->cached_sq_head;
		io_spare_ready(q, 1, false);
	}
	if (ctx->submit_state.link.head || ctx->bpf_filters ||
	    (ctx->int_flags & (IO_RING_F_DRAIN_ACTIVE | IO_RING_F_DRAIN_NEXT |
			  IO_RING_F_OP_RESTRICTED)))
		return io_spare_skip(q, IO_SPARE_SKIP_STATE, left);
	/*
	 * The inline fallback calls this once per SQE. Wake only for work this
	 * call could hand over: a full chunk budget or an ineligible head
	 * would otherwise wake an executor per SQE that finds nothing.
	 */
	if (READ_ONCE(q->nr_chunks) >= q->u_chunks)
		return io_spare_skip(q, IO_SPARE_SKIP_BUDGET, left);
	/* Inside a run this submission already found short: stay inline, O(1). */
	if ((s32)(q->short_end - ctx->cached_sq_head) > 0)
		return io_spare_skip(q, IO_SPARE_SKIP_SHORT, left);
	sqe = io_spare_peek(ctx, 0);
	if (!sqe || !io_spare_delegable(ctx, sqe))
		return io_spare_skip(q, IO_SPARE_SKIP_INELIGIBLE, left);
	/* Measure the run before any wake. */
	for (n = 1; n < min(left, q->n_max); n++) {
		sqe = io_spare_peek(ctx, n);
		if (!sqe || !io_spare_delegable(ctx, sqe))
			break;
	}
	t0 = local_clock();
	/*
	 * A run too short to pay for a chunk of its own (io_spare_threshold())
	 * may still join the ring's last chunk while no executor has claimed
	 * it; otherwise it stays inline.
	 */
	thr = io_spare_threshold(q);
	if (n < thr && ((q->flags & IORING_SPARE_F_NO_ACCUMULATE) ||
			!READ_ONCE(q->nr_pending))) {
		q->short_end = ctx->cached_sq_head + n;
		return io_spare_skip(q, IO_SPARE_SKIP_SHORT, left);
	}
	/* ALWAYS publishes anyway and wakes after that, once, for real backlog. */
	if (!atomic_read(&q->grp->nr_awake) && q->mode != IORING_SPARE_MODE_ALWAYS &&
	    !READ_ONCE(q->nr_pending)) {
		io_spare_wake(q, left, false);
		return io_spare_skip(q, IO_SPARE_SKIP_ASLEEP, left);
	}
	/* Files are referenced now, as inline submission would at this point. */
	n = io_spare_run_files(ctx, run, n);
	if (!n)
		return io_spare_skip(q, IO_SPARE_SKIP_INELIGIBLE, left);
	if (!(q->flags & IORING_SPARE_F_NO_ACCUMULATE) && READ_ONCE(q->nr_pending)) {
		copied = io_spare_append(ctx, run, n, left, stop);
		if (copied || *stop) {
			io_spare_run_put(run);
			q->t_delegate += local_clock() - t0;
			q->n_deleg_sub += copied;
			return copied;
		}
	}
	if (n < thr) {
		io_spare_run_put(run);
		q->short_end = ctx->cached_sq_head + n;
		return io_spare_skip(q, IO_SPARE_SKIP_SHORT, left);
	}
	if (READ_ONCE(q->nr_pending) >= q->u_pending) {
		io_spare_run_put(run);
		return io_spare_skip(q, IO_SPARE_SKIP_PENDING, left);
	}
	chunk = io_spare_chunk_get(q);
	if (!chunk) {
		io_spare_run_put(run);
		return io_spare_skip(q, IO_SPARE_SKIP_NOMEM, left);
	}
	/* Only the header and the used slots need clearing; CQEs are written before use. */
	memset(chunk, 0, offsetof(struct io_chunk, data));
	/* Appends may grow any chunk past a kick batch: every chunk gets a lease. */
	if (!io_alloc_req(ctx, &lease))
		goto nomem;
	if (!io_alloc_req(ctx, &fin)) {
		/* Not initialized or task-referenced yet, return directly to cache. */
		wq_stack_add_head(&lease->comp_list, &ctx->submit_state.free_list);
		goto nomem;
	}
	chunk->q = q;
	chunk->sqes = (struct io_uring_sqe *)chunk->data;
	chunk->cqes = (struct io_cqe *)(chunk->sqes + q->n_max);
	chunk->slot = (u8 *)(chunk->cqes + q->n_max);
	chunk->fidx = chunk->slot + q->n_max;
	chunk->copy = PTR_ALIGN((void *)(chunk->fidx + q->n_max), 8);
	memset(chunk->slot, IO_SPARE_FREE, n);
	chunk->lease = lease;
	chunk->fin = fin;
	INIT_LIST_HEAD(&chunk->list);
	INIT_LIST_HEAD(&chunk->rescue);
	io_spare_init_token(ctx, lease, chunk, io_lease_tw);
	io_spare_init_token(ctx, fin, chunk, io_fin_tw);
	io_get_task_refs(2);
	/* The run's references become the chunk's. */
	for (i = 0; i < run->nr_files; i++)
		chunk->files[i] = run->files[i];
	chunk->nr_files = run->nr_files;
	q->files += run->nr_files;
	run->nr_files = 0;
	while (copied < n) {
		if (!io_get_sqe(ctx, &sqe)) {
			*stop = true;
			break;
		}
		chunk->fidx[copied] = run->fidx[copied];
		memcpy(&chunk->sqes[copied++], sqe, sizeof(*sqe));
	}
	current->io_uring->cached_refs += copied;
	if (!copied) {
		io_req_complete_defer(lease);
		io_req_complete_defer(fin);
		goto free_chunk;
	}
	chunk->n = copied;
	chunk->seq = ++q->seq;
	/* Before publication: a claim, fin and retire may follow at once. */
	trace_io_uring_spare_delegate(ctx, chunk->seq, copied, left,
				      READ_ONCE(q->nr_pending) + 1,
				      READ_ONCE(q->nr_chunks) + 1);
	spin_lock(&q->lock);
	list_add_tail(&chunk->list, &q->pending);
	q->nr_pending++;
	q->nr_chunks++;
	atomic_inc(&q->grp->nr_pending);
	spin_unlock(&q->lock);
	atomic64_add(copied, &q->delegated);
	atomic_add(copied, &q->live);
	atomic64_inc(&q->chunks);
	/*
	 * A policy wake already sends a sleeper to this chunk. Otherwise every
	 * executor may have gone to sleep since the checks above: wq_has_sleeper()'s
	 * barrier pairs with the executor's nr_awake-- -> smp_mb__after_atomic()
	 * -> nr_pending recheck, so either it sees this chunk or we see
	 * nr_awake == 0. Any still-awake executor claims it itself.
	 */
	if (!io_spare_wake(q, left, q->mode == IORING_SPARE_MODE_ALWAYS) &&
	    wq_has_sleeper(&q->grp->wq) && !atomic_read(&q->grp->nr_awake)) {
		atomic64_inc(&q->wakes);
		trace_io_uring_spare_wake(ctx, IO_SPARE_WAKE_PUBLISH, 0,
					  atomic_read(&q->grp->nr_live),
					  atomic_read(&q->grp->wake_credit));
		spin_lock(&q->grp->lock);
		q->grp->hint = q;
		spin_unlock(&q->grp->lock);
		wake_up_nr(&q->grp->wq, 1);
	}
	t0 = local_clock() - t0;
	q->t_delegate += t0;
	q->n_deleg_sub += copied;
	/* What the chunk cost beyond its copies. */
	io_spare_ewma(&q->cost_chunk, t0 > copied * IO_SPARE_COPY_NS ?
		      t0 - copied * IO_SPARE_COPY_NS : 0);
	return copied;
nomem:
	io_spare_run_put(run);
	io_spare_chunk_put(q, chunk);
	return io_spare_skip(q, IO_SPARE_SKIP_NOMEM, left);
free_chunk:
	/* The chunk holds the references now; retire's loop is for published chunks. */
	while (chunk->nr_files)
		fput(chunk->files[--chunk->nr_files]);
	io_spare_chunk_put(q, chunk);
	return 0;
}

/* A CANCEL marker also needs a single traversal winner, exactly like FREE. */
static int io_spare_take(u8 *slot, u8 state)
{
	u8 old = cmpxchg(slot, IO_SPARE_FREE, state);

	if (old == IO_SPARE_CANCEL)
		old = cmpxchg(slot, IO_SPARE_CANCEL, state);
	return old;
}

/* Per-chunk counter only: no per-slot atomic on a line the owner reads. */
static void io_spare_slot_taken_locked(struct io_chunk *chunk)
{
	if (atomic_dec_and_test(&chunk->unvisited))
		list_del_init(&chunk->rescue);
}

/*
 * Executor side: no q->lock. At zero the chunk's rescue entry goes stale; the
 * owner's rescue scan prunes it and retire unlinks it, both under q->lock.
 * Taking the lock here was one of four acquisitions per chunk.
 */
static void io_spare_slot_taken(struct io_chunk *chunk)
{
	atomic_dec(&chunk->unvisited);
}

/*
 * Executor: whether a request that would block may be issued blocking after
 * the scan, io-wq style, instead of bounced to the owner. Pollable files are
 * the owner's: their wait is a poll arm on its task_work.
 */
static bool io_exec_may_block(struct io_chunk *chunk, struct io_kiocb *req)
{
	return !(chunk->q->flags & IORING_SPARE_F_NO_BLOCK) &&
	       !(req->flags & REQ_F_NOWAIT) && !io_file_can_poll(req);
}

static void io_exec_defer_block(struct io_chunk *chunk, struct io_kiocb *req)
{
	wq_list_add_tail(&req->comp_list, &chunk->retry);
}

/*
 * Executor: issue one prepared request of slot i, nonblocking during the scan
 * or blocking afterwards (retry), and finish what completes at once.
 */
static void io_exec_issue(struct io_chunk *chunk, struct io_kiocb *req,
			  unsigned int i, bool blocking)
{
	struct io_ring_ctx *ctx = chunk->q->ctx;
	const struct io_uring_sqe *sqe = &chunk->sqes[i];
	unsigned int flags = blocking ? IO_URING_F_UNLOCKED | IO_URING_F_IOWQ :
					IO_URING_F_NONBLOCK | IO_URING_F_UNLOCKED;
	int ret;

	io_spare_dbg_exec(chunk->q, IORING_SPARE_DBG_EXEC_IN_ISSUE, i, chunk->exec);

	/*
	 * A buffered read is split at its copy: this executor does the page
	 * cache lookup and keeps the folios, the owner copies them into the
	 * user buffer when it posts the CQE. The data then sits in the cache
	 * of the core that reads it, instead of in ours (64 lines a 4 KiB
	 * request would otherwise drag across cores). Blocking, the lookup
	 * brings the data in first; the copy still happens on the owner.
	 */
	if (!io_spare_write(req->opcode) && !io_rw_spare_progress(req)) {
		struct folio_batch fbatch;
		loff_t pos;
		int len = io_rw_spare_pin(req, &fbatch, IO_SPARE_COPY_FOLIOS, &pos,
					  !blocking);

		if (len > 0) {
			struct io_spare_copy *cp = &chunk->copy[i];
			unsigned int k;

			cp->file = req->file;
			cp->fput = !(req->flags & (REQ_F_FIXED_FILE | REQ_F_EXEC_FILE));
			cp->pos = pos;
			cp->len = len;
			cp->nr = folio_batch_count(&fbatch);
			for (k = 0; k < cp->nr; k++)
				cp->folios[k] = fbatch.folios[k];
			trace_io_uring_spare_issue(ctx, chunk->seq, i, sqe->user_data,
						   sqe->opcode, blocking ?
						   IO_SPARE_ISSUE_BLOCKED :
						   IO_SPARE_ISSUE_DEFERRED, len);
			/* The access is done here, as filemap_read() would notify. */
			io_rw_spare_finish(req, true);
			/* The owner's copy sets the real count; the entry names the slot. */
			io_chunk_record(chunk, sqe->user_data, len, IO_SPARE_CQE_COPY | i);
			/* The file reference moved to the descriptor. */
			io_exec_req_free(req, !cp->fput);
			chunk->handled++;
			return;
		}
		if (len == 0) {
			/* At or past EOF: nothing to copy, complete inline. */
			io_rw_spare_finish(req, false);
			trace_io_uring_spare_issue(ctx, chunk->seq, i, sqe->user_data,
						   sqe->opcode, IO_SPARE_ISSUE_INLINE, 0);
			io_exec_done(chunk, sqe->user_data, 0, 0);
			io_exec_req_free(req, true);
			chunk->handled++;
			return;
		}
		if (len == -EAGAIN) {
			ret = -EAGAIN;
			if (req->flags & REQ_F_NOWAIT)
				goto fail;
			if (!blocking && io_exec_may_block(chunk, req)) {
				io_exec_defer_block(chunk, req);
				return;
			}
			trace_io_uring_spare_issue(ctx, chunk->seq, i, sqe->user_data,
						   sqe->opcode, IO_SPARE_ISSUE_BOUNCE, 0);
			io_exec_bounce(req, IO_SPARE_BOUNCE_EAGAIN);
			return;
		}
		if (len != -EOPNOTSUPP) {
			ret = len;
			goto fail;
		}
		/* Not a read to split (O_DIRECT, other file systems): issue it here. */
	}
	/* A request that may go async outlives the chunk: its own file reference. */
	io_exec_own_file(req);
	/*
	 * An async completion may be finished, by the owner, before the issue
	 * call returns, and the call may still touch the request and its
	 * iterator afterwards. Hold a ref across it, as io-wq does; the port
	 * routes the completion (io_spare_rw_done()).
	 */
	req->big_cqe.extra2 = (unsigned long)chunk->port;
	__io_req_set_refcount(req, 2);
	do {
		ret = io_spare_issue(req, flags);
		if (ret != -EAGAIN || !blocking || (req->flags & REQ_F_NOWAIT))
			break;
		/* Stopping or killed: bounce below, the owner's io-wq finishes it. */
		if (test_bit(IO_SPARE_STOP, &chunk->exec->state) ||
		    fatal_signal_pending(current))
			break;
		/* As io_wq_submit_work(): a blocking issue is retried until it goes. */
		cond_resched();
	} while (1);
	if (ret == IOU_ISSUE_SKIP_COMPLETE) {
		trace_io_uring_spare_issue(ctx, chunk->seq, i, sqe->user_data,
					   sqe->opcode, IO_SPARE_ISSUE_ASYNC, 0);
		/* Before our put, which may be the last: the port counts it, not the chunk. */
		atomic_inc(&chunk->port->outstanding);
		chunk->async++;
		chunk->handled++;
		io_spare_async_put(req);
		return;
	}
	/* No completion callback is pending: the request is ours alone again. */
	req->flags &= ~REQ_F_REFCOUNT;
	if (ret == -EAGAIN) {
		/* RWF_NOWAIT: -EAGAIN is the result, as in io_queue_async(). */
		if (req->flags & REQ_F_NOWAIT)
			goto fail;
		if (!blocking && io_exec_may_block(chunk, req)) {
			io_exec_defer_block(chunk, req);
			return;
		}
		trace_io_uring_spare_issue(ctx, chunk->seq, i, sqe->user_data,
					   sqe->opcode, IO_SPARE_ISSUE_BOUNCE, 0);
		io_exec_bounce(req, IO_SPARE_BOUNCE_EAGAIN);
		return;
	}
	if (ret == IOU_COMPLETE) {
		io_rw_spare_finish(req, false);
		trace_io_uring_spare_issue(ctx, chunk->seq, i, sqe->user_data,
					   sqe->opcode, blocking ? IO_SPARE_ISSUE_BLOCKED :
					   IO_SPARE_ISSUE_INLINE, req->cqe.res);
		io_exec_done(chunk, req->cqe.user_data, req->cqe.res, req->cqe.flags);
		io_exec_req_free(req, true);
		chunk->handled++;
		return;
	}
fail:
	io_req_set_res(req, ret, 0);
	if (req_has_async_data(req)) {
		io_rw_fail(req);
		io_rw_spare_finish(req, false);
	}
	trace_io_uring_spare_issue(ctx, chunk->seq, i, sqe->user_data, sqe->opcode,
				   IO_SPARE_ISSUE_FAILED, req->cqe.res);
	io_exec_done(chunk, req->cqe.user_data, req->cqe.res, req->cqe.flags);
	io_exec_req_free(req, true);
	chunk->handled++;
}

/* True once a request has consumed one of the scan's reserved ctx refs. */
static bool io_exec_one(struct io_chunk *chunk, unsigned int i)
{
	/* Immutable after owner publication; validate this local snapshot once. */
	struct io_uring_sqe sqe = chunk->sqes[i];
	struct io_ring_ctx *ctx = chunk->q->ctx;
	struct io_kiocb *req;
	bool bounce = false;
	int ret;

	if (!io_spare_eligible(&sqe, true)) {
		ret = -EINVAL;
		goto record;
	}
	if (chunk->kind == IO_CHUNK_PULL && chunk->fidx[i] == IO_SPARE_FILE_BAD) {
		ret = -EBADF;
		goto record;
	}
	req = io_exec_req_alloc(chunk->exec);
	if (!req) {
		ret = -ENOMEM;
		goto record;
	}
	io_get_task_refs(1);
	req->ctx = ctx;
	req->tctx = current->io_uring;
	req->opcode = sqe.opcode;
	/* IOSQE_ASYNC is served by being here; the flag means io-wq to the owner's paths. */
	req->flags = (__force io_req_flags_t)(sqe.flags & IOSQE_FIXED_FILE) | REQ_F_EXEC;
	req->cqe.user_data = sqe.user_data;
	req->cqe.fd = sqe.fd;
	req->big_cqe.extra1 = (unsigned long)chunk;
	/* The slot, for the retry after the scan. */
	req->work.cancel_seq = i;
	if (sqe.flags & IOSQE_FIXED_FILE) {
		req->file_node = io_rsrc_node_lookup(&ctx->file_table.data, sqe.fd);
		if (req->file_node) {
			req->file = io_slot_file(req->file_node);
			req->flags |= (__force io_req_flags_t)io_slot_flags(req->file_node);
		}
	} else if (chunk->fidx[i] != IO_SPARE_NO_FILE) {
		/* Referenced by the owner at delegation, as inline submission would have. */
		req->file = chunk->files[chunk->fidx[i]];
		req->flags |= REQ_F_EXEC_FILE;
	} else if (chunk->kind == IO_CHUNK_PUSH) {
		req->file = fget(sqe.fd);
	}
	if (!req->file) {
		ret = -EBADF;
		goto fail;
	}
	if (io_is_uring_fops(req->file)) {
		io_exec_put_file(req);
		req->file = NULL;
		req->flags &= ~REQ_F_EXEC_FILE;
		bounce = true;
	} else if (FMODE_FSNOTIFY_HSM(req->file->f_mode) ||
		   (io_spare_write(req->opcode) &&
		    ((READ_ONCE(req->file->f_flags) & O_APPEND) ||
		     (sqe.rw_flags & RWF_APPEND)))) {
		bounce = true;
	}
	if (req->opcode == IORING_OP_READ_FIXED ||
	    req->opcode == IORING_OP_WRITE_FIXED) {
		req->buf_index = sqe.buf_index;
		req->buf_node = io_rsrc_node_lookup(&ctx->buf_table, req->buf_index);
		/* Even a missing node must bypass io_find_buf_node()'s locking path. */
		req->flags |= REQ_F_BUF_NODE;
		if (!req->buf_node) {
			ret = -EFAULT;
			goto fail;
		}
	}
	ret = io_issue_defs[req->opcode].prep(req, &sqe);
	if (ret)
		goto fail;
	/* Adoption submits prepared requests; even rejected files need prep first. */
	if (bounce) {
		trace_io_uring_spare_issue(ctx, chunk->seq, i, sqe.user_data,
					   sqe.opcode, IO_SPARE_ISSUE_BOUNCE, 0);
		io_exec_bounce(req, IO_SPARE_BOUNCE_FILE);
		return true;
	}
	io_exec_issue(chunk, req, i, false);
	return true;
fail:
	io_req_set_res(req, ret, 0);
	if (req_has_async_data(req)) {
		io_rw_fail(req);
		io_rw_spare_finish(req, false);
	}
	trace_io_uring_spare_issue(ctx, chunk->seq, i, sqe.user_data, sqe.opcode,
				   IO_SPARE_ISSUE_FAILED, req->cqe.res);
	io_exec_done(chunk, req->cqe.user_data, req->cqe.res, req->cqe.flags);
	io_exec_req_free(req, true);
	chunk->handled++;
	return true;
record:
	trace_io_uring_spare_issue(ctx, chunk->seq, i, sqe.user_data, sqe.opcode,
				   IO_SPARE_ISSUE_FAILED, ret);
	io_exec_done(chunk, sqe.user_data, ret, 0);
	chunk->handled++;
	return false;
}

/*
 * Executor, after the nonblocking scan: the requests that would have blocked
 * are issued blocking now, in slot order, as io-wq would have issued them for
 * the owner. Off CPU meanwhile, this executor counts as stalled: the owner's
 * wait harvests what it stored and takes over its port.
 */
static void io_exec_retry(struct io_chunk *chunk)
{
	struct io_wq_work_node *node = chunk->retry.first;

	INIT_WQ_LIST(&chunk->retry);
	while (node) {
		struct io_kiocb *req = container_of(node, struct io_kiocb, comp_list);

		node = node->next;
		atomic64_inc(&chunk->q->blocked);
		io_exec_issue(chunk, req, req->work.cancel_seq, true);
	}
}

/* No chunk can be reclaimed while q->lock protects traversal/copying. */
static void io_exec_return_slots(struct io_chunk *chunk)
{
	struct io_spare_q *q = chunk->q;
	unsigned int i;

	if (chunk->return_ready)
		return;
	spin_lock(&q->lock);
	/* A debug KILL may stop a pull copy before its normal rescue publication. */
	if (chunk->kind == IO_CHUNK_PULL && !chunk->copy_done) {
		unsigned int free = 0;

		for (i = 0; i < chunk->n; i++)
			free += READ_ONCE(chunk->slot[i]) == IO_SPARE_FREE ||
				READ_ONCE(chunk->slot[i]) == IO_SPARE_CANCEL;
		atomic_set(&chunk->unvisited, free);
		chunk->copy_done = true;
		if (free)
			list_add_tail(&chunk->rescue, &q->rescue);
	}
	for (i = 0; i < chunk->n; i++) {
		int old = io_spare_take(&chunk->slot[i], IO_SPARE_OWNER);

		if (old != IO_SPARE_FREE && old != IO_SPARE_CANCEL)
			continue;
		chunk->returned |= BIT_ULL(i);
		if (old == IO_SPARE_CANCEL)
			chunk->returned_cancel |= BIT_ULL(i);
		io_spare_slot_taken_locked(chunk);
	}
	spin_unlock(&q->lock);
	if (chunk->returned) {
		atomic64_add(hweight64(chunk->returned), &q->handback);
		trace_io_uring_spare_handback(q->ctx, chunk->seq,
					      hweight64(chunk->returned),
					      hweight64(chunk->returned_cancel));
		/* Pairs with io_chunk_returned() acquiring the immutable handback. */
		smp_store_release(&chunk->return_ready, true);
		/* Return unissued work promptly, without waiting for this chunk's I/O. */
		io_chunk_kick(chunk);
	}
}

/*
 * Executor, at a plug flush point: flush now, or keep plugging for an idle
 * owner (io_spare_plug_batch_idle)? The owner is idle when it is waiting on
 * the CQ and has been asleep for most of its recent cycles (q->owner_busy
 * below plug_idle_busy); cq_wait_nr and the estimate are read as hints.
 */
static bool io_exec_plug_flush_now(struct io_spare_q *q, unsigned int plugged,
				   unsigned int plug_batch)
{
	unsigned int idle_batch = READ_ONCE(io_spare_plug_batch_idle);

	if (idle_batch && plugged >= idle_batch)
		return true;
	if (atomic_read(&q->ctx->cq_wait_nr) < 0)
		return true;
	return READ_ONCE(q->owner_busy) >=
	       READ_ONCE(io_spare_plug_idle_busy) * 1024 / 100;
}

static void io_exec_chunk(struct io_chunk *chunk)
{
	struct io_spare_exec *exec = chunk->exec;
	struct io_spare_q *q = chunk->q;
	struct io_ring_ctx *ctx = q->ctx;
	struct io_spare_port *port = chunk->port;	/* fin may free the chunk */
	struct blk_plug plug;
	unsigned int i, unused_refs = chunk->n, plugged = 0;
	unsigned int plug_batch = READ_ONCE(io_spare_plug_batch);
	bool ahead_tried = false;

	/* A chunk claimed ahead was not marked when the previous one ended. */
	WRITE_ONCE(exec->busy, true);
	/*
	 * A chunk held ahead may have seen its port deactivated by a drain in
	 * between (ring detached or dying, nothing outstanding): the port, and
	 * the ctx reference it holds, must outlive this scan's final flush.
	 */
	io_exec_port_activate(exec, port);
	/* Each allocated request takes one; unissued slots are refunded below. */
	percpu_ref_get_many(&ctx->refs, unused_refs);
	if (plug_batch)
		blk_start_plug(&plug);
	for (i = 0; i < chunk->n; i++) {
		bool cancel = percpu_ref_is_dying(&ctx->refs);
		int old;

		/*
		 * Keep dying-ring cancellation on the sole journal producer;
		 * a live detach instead hands unissued slots back to the owner.
		 * Finish scanning before fin, which must be the last chunk access.
		 * Not signal_pending(): a pending task_work notification must not
		 * hand back the remainder.
		 */
		if (!cancel && (READ_ONCE(q->dead) || fatal_signal_pending(current) ||
				test_bit(IO_SPARE_STOP, &exec->state))) {
			io_exec_return_slots(chunk);
			break;
		}
		old = io_spare_take(&chunk->slot[i], IO_SPARE_EXEC);
		if (old == IO_SPARE_OWNER) {
			if (chunk->kind == IO_CHUNK_PULL)
				continue;
			break;
		}
		if (WARN_ON_ONCE(old == IO_SPARE_RESERVED))
			continue;
		if (WARN_ON_ONCE(old != IO_SPARE_FREE && old != IO_SPARE_CANCEL))
			break;
		io_spare_slot_taken(chunk);
		chunk->taken++;
		if (cancel || old == IO_SPARE_CANCEL) {
			trace_io_uring_spare_issue(ctx, chunk->seq, i,
						   chunk->sqes[i].user_data,
						   chunk->sqes[i].opcode,
						   IO_SPARE_ISSUE_CANCELLED, -ECANCELED);
			io_exec_done(chunk, chunk->sqes[i].user_data, -ECANCELED, 0);
			chunk->handled++;
		} else {
			/* One slot's claim -> prep -> issue precedes the next claim. */
			unused_refs -= io_exec_one(chunk, i);
			/* Finish our async completions as they come, not after the scan. */
			if (!llist_empty(&chunk->port->done))
				io_exec_port_reap(chunk->port);
			/*
			 * Holder: SQEs the owner stored since this chunk began go to
			 * an idle sibling now, not after this chunk (io_exec_publish_more()).
			 */
			if (READ_ONCE(io_spare_early_publish) &&
			    chunk->kind == IO_CHUNK_PULL && exec->lease_q == q &&
			    !exec->ahead && exec->may_ahead && i + 1 < chunk->n &&
			    (READ_ONCE(q->flags) & IORING_SPARE_F_PULL_HANDOFF))
				io_exec_publish_more(exec, q);
			/*
			 * Preemption does not flush a plug (only a sleep does), so a
			 * preempted executor would hold everything plugged so far.
			 * Bound that to plug_batch requests for a loaded owner, to
			 * plug_batch_idle (0: the chunk) for an idle one (see the tunable).
			 */
			if (plug_batch && ++plugged >= plug_batch &&
			    io_exec_plug_flush_now(q, plugged, plug_batch)) {
				blk_flush_plug(&plug, false);
				plugged = 0;
			}
		}
		/*
		 * Near the end of this chunk, claim the ring's next one now. An
		 * owner about to wait then finds it claimed and shares its tail
		 * (split) instead of taking it back whole moments before this
		 * executor would have reached it. Not in the last chunk before
		 * reselection: a chunk held ahead postpones it, and claiming
		 * ahead every time would keep a backlogged ring forever.
		 */
		if (chunk->kind == IO_CHUNK_PUSH && !ahead_tried &&
		    !exec->ahead && exec->may_ahead &&
		    i + IO_SPARE_KICK_BATCH + 1 >= chunk->n &&
		    READ_ONCE(q->nr_pending)) {
			ahead_tried = true;
			exec->ahead = io_exec_claim(exec, q);
		}
	}
	if (plug_batch)
		blk_finish_plug(&plug);
	if (unused_refs)
		percpu_ref_put_many(&ctx->refs, unused_refs);
	chunk->t_done = local_clock();
	io_exec_retry(chunk);
	/*
	 * A pull chunk this executor issued whole: no owner copy can still name
	 * its files (rescue takes FREE slots, handback needs a returned one) and
	 * every request that may outlive the scan holds its own reference
	 * (io_exec_own_file()). Drop the chunk's references on the core that
	 * took them, not at retire on the owner's (a cache line per chunk).
	 */
	if (chunk->kind == IO_CHUNK_PULL && chunk->taken == chunk->n)
		while (chunk->nr_files)
			fput(chunk->files[--chunk->nr_files]);
	chunk->scanned = true;
	/* Async requests count as handled at issue, so fin follows the scan. */
	if (!io_chunk_maybe_fin(chunk))
		io_chunk_flush(chunk);
	/* What the scan stored in the journal goes out with the chunk (port, not chunk: fin ran). */
	io_exec_port_flush_maybe(port);
	/* A chunk claimed ahead is held too: off CPU, the owner may take it back. */
	WRITE_ONCE(exec->busy, exec->ahead != NULL);
}

/* The queue transfers execution only; the pull list retains the chunk ref. */
static struct io_chunk *io_spare_handoff_pop(struct io_spare_q *q)
{
	struct io_chunk *chunk;

	lockdep_assert_held(&q->lock);
	if (list_empty(&q->handoff))
		return NULL;
	chunk = list_first_entry(&q->handoff, struct io_chunk, handoff);
	list_del_init(&chunk->handoff);
	q->nr_handoff--;
	atomic_dec(&q->grp->nr_handoff);
	return chunk;
}

/* Holder, idle: has the oldest queued hand-off waited out its grace period? */
static bool io_spare_handoff_stale(struct io_spare_q *q)
{
	struct io_chunk *chunk;
	bool stale = false;

	spin_lock(&q->lock);
	chunk = list_first_entry_or_null(&q->handoff, struct io_chunk, handoff);
	if (chunk)
		stale = local_clock() - chunk->handoff_at >=
			(u64)READ_ONCE(io_spare_handoff_grace_us) * NSEC_PER_USEC;
	spin_unlock(&q->lock);
	return stale;
}

/* The caller retains its selection ctx reference through execution. */
static bool io_exec_take_handoff(struct io_spare_exec *exec, struct io_spare_q *q)
{
	struct io_chunk *chunk = NULL;
	struct io_spare_exec *offered;

	spin_lock(&q->lock);
	if (q->attached && !q->dead && q->grp == exec->grp) {
		chunk = io_spare_handoff_pop(q);
		if (chunk) {
			offered = chunk->handoff_to;
			chunk->handoff_to = NULL;
			chunk->exec = exec;
			chunk->port = READ_ONCE(q->ports[exec->exec_id - 1]);
		}
	}
	spin_unlock(&q->lock);
	if (!chunk)
		return false;
	io_exec_port_activate(exec, chunk->port);
	list_add_tail(&chunk->open, &exec->open);
	WRITE_ONCE(exec->busy, true);
	/* Keep the target reserved until the executing side is marked busy. */
	atomic_set_release(&offered->offered, 0);
	chunk->t_claim = local_clock();
	chunk->port->claims++;
	trace_io_uring_spare_claim(q->ctx, chunk->seq, chunk->n);
	io_exec_chunk(chunk);
	return true;
}

/* Releasing a selection must not strand work still attributed to this holder. */
static void io_exec_handoff_drain(struct io_spare_exec *exec, struct io_spare_q *q)
{
	unsigned int nr = READ_ONCE(q->nr_handoff);

	while (nr-- && io_exec_take_handoff(exec, q))
		;
}

/* Idle siblings are hints; a missed take is covered by the holder's drain. */
static bool io_exec_handoff(struct io_spare_exec *exec, struct io_chunk *chunk,
			    bool mid_chunk)
{
	struct io_spare_grp *grp = exec->grp;
	struct io_spare_q *q = chunk->q;
	struct io_spare_port *port = chunk->port;	/* the publisher's, until a take */
	struct io_spare_exec *next = NULL;
	unsigned int i, pass, passes = mid_chunk ? 1 : 2;

	if (chunk->n < READ_ONCE(q->n_min) || grp->nr_exec < 2)
		return false;
	/*
	 * An awake idle sibling first (takes within a few us); else wake a
	 * sleeper. Mid-chunk (io_exec_publish_more()) only the former: the
	 * publisher cannot take a unit back from a sleeper before its own chunk
	 * ends, and the unit would wait for the wake.
	 */
	for (pass = 0; pass < passes && !next; pass++) {
		for (i = 0; i < grp->nr_exec; i++) {
			struct io_spare_exec *sibling = &grp->exec[i];

			if (i == exec->exec_id - 1 || !READ_ONCE(sibling->task) ||
			    test_bit(IO_SPARE_STOP, &sibling->state) ||
			    test_bit(IO_SPARE_PARK, &sibling->state))
				continue;
			if (pass == 0 ? (!READ_ONCE(sibling->awake) || READ_ONCE(sibling->busy))
				      : READ_ONCE(sibling->awake))
				continue;
			if (atomic_cmpxchg(&sibling->offered, 0, 1))
				continue;
			/* A taker may have become busy while releasing its previous offer. */
			if (pass == 0 && READ_ONCE(sibling->busy)) {
				atomic_set(&sibling->offered, 0);
				continue;
			}
			next = sibling;
			break;
		}
	}
	if (!next)
		return false;
	spin_lock(&q->lock);
	if (!q->attached || q->dead || q->grp != grp ||
	    atomic64_read(&q->lease) != exec->lease_w) {
		spin_unlock(&q->lock);
		atomic_set(&next->offered, 0);
		return false;
	}
	chunk->handoff_to = next;
	chunk->handoff_at = local_clock();
	list_add_tail(&chunk->handoff, &q->handoff);
	q->nr_handoff++;
	atomic_inc(&grp->nr_handoff);
	/* Under q->lock: re-registration may hand this port to a new executor once we unlock. */
	port->handoffs++;
	spin_unlock(&q->lock);
	/* No chunk access after publication: a taker may already have finished it. */
	if (!mid_chunk)
		WRITE_ONCE(exec->busy, false);
	/* Pairs with the sleeper's counter check after dropping nr_awake. */
	if (!READ_ONCE(next->awake) || wq_has_sleeper(&grp->wq)) {
		spin_lock(&grp->lock);
		if (READ_ONCE(q->attached) && READ_ONCE(q->grp) == grp)
			grp->hint = q;
		spin_unlock(&grp->lock);
		atomic64_inc(&q->wakes);
		wake_up_nr(&grp->wq, 1);
	}
	return true;
}

static unsigned int io_exec_drain(struct io_spare_exec *exec, bool cancel)
{
	struct io_uring_task *tctx = current->io_uring;
	struct io_tw_state tw = { .cancel = cancel };
	struct io_chunk *chunk;
	unsigned int nr = 0;

	/* Clear before popping; a later producer must retain its notification. */
	if (test_thread_flag(TIF_NOTIFY_SIGNAL))
		clear_notify_signal();
	while (!mpscq_empty(&tctx->task_list)) {
		struct llist_node *node = mpscq_pop(&tctx->task_list, &tctx->task_head);
		struct io_kiocb *req;

		if (!node) {
			cond_resched();
			continue;
		}
		req = container_of(node, struct io_kiocb, io_task_work.node);
		WARN_ON_ONCE(!(req->flags & REQ_F_EXEC));
		tw.cancel = cancel || percpu_ref_is_dying(&req->ctx->refs);
		req->io_task_work.func((struct io_tw_req) { req }, tw);
		nr++;
	}
	/* Async completions come through the ports, not this task's list. */
	nr += io_exec_ports_reap(exec);
	/* One kick per chunk for this drain; finished chunks have left the list. */
	if (nr)
		list_for_each_entry(chunk, &exec->open, open)
			io_chunk_flush(chunk);
	if (task_work_pending(current))
		task_work_run();
	return nr;
}

/* grp->lock protects membership; no q lock or other lock is taken here. */
static bool io_spare_pull_available(struct io_spare_q *q, u64 w, u64 now)
{
	return READ_ONCE(q->offer) && READ_ONCE(q->attached) && !READ_ONCE(q->dead) &&
	       !IO_W_HOLDER(w) && !time_before64(now, READ_ONCE(q->hold_until));
}

/* Sibling of the holder: an offered ring whose lease another executor holds. */
static bool io_spare_lease_elsewhere(struct io_spare_q *q, struct io_spare_exec *exec)
{
	unsigned int holder = IO_W_HOLDER(atomic64_read(&q->lease));

	return holder && holder != exec->exec_id && READ_ONCE(q->offer) &&
	       READ_ONCE(q->attached) && !READ_ONCE(q->dead);
}

static unsigned int io_spare_pull_pending(struct io_spare_q *q, u64 now)
{
	u64 w = atomic64_read(&q->lease);
	u32 tail;

	if (!io_spare_pull_available(q, w, now))
		return 0;
	tail = smp_load_acquire(&q->ctx->rings->sq.tail);
	return min_t(u32, tail - IO_W_CURSOR(w), q->ctx->sq_entries);
}

/* Cold sleep/reselection check. nr_offers alone also counts empty SQs. */
static bool io_spare_group_work(struct io_spare_grp *grp, struct io_spare_q *skip)
{
	struct io_spare_q *q;
	bool work = false;
	u64 now = ktime_get_ns();

	spin_lock(&grp->lock);
	list_for_each_entry(q, &grp->ctx_list, grp_node) {
		if (q != skip &&
		    (READ_ONCE(q->nr_pending) || READ_ONCE(q->nr_handoff) ||
		     io_spare_pull_pending(q, now))) {
			work = true;
			break;
		}
	}
	spin_unlock(&grp->lock);
	return work;
}

static void io_spare_pull_wake(struct io_spare_q *q)
{
	struct io_spare_grp *grp = q->grp;
	int credit, asleep;

	if (!grp || !READ_ONCE(q->offer) || IO_W_HOLDER(atomic64_read(&q->lease)))
		return;
	/* Lingering siblings of other rings' holders reselect on this, not per pass. */
	atomic_inc(&grp->pull_gen);
	for (;;) {
		if (atomic_read(&grp->nr_awake))
			return;
		credit = atomic_read(&grp->wake_credit);
		asleep = atomic_read(&grp->nr_live);
		if (credit || credit >= asleep)
			return;
		if (atomic_cmpxchg(&grp->wake_credit, credit, credit + 1) == credit)
			break;
	}
	spin_lock(&grp->lock);
	grp->hint = q;
	spin_unlock(&grp->lock);
	atomic64_inc(&q->wakes);
	wake_up_nr(&grp->wq, 1);
}

static bool io_exec_lease_acquire(struct io_spare_exec *exec, struct io_spare_q *q)
{
	struct io_ring_ctx *ctx = q->ctx;
	u64 w, nw;

	/* A held lease fails under the lock anyway: no uring_lock round trip for it. */
	if (!q->pull_ok || !READ_ONCE(q->offer) || exec->lease_q ||
	    IO_W_HOLDER(atomic64_read(&q->lease)) ||
	    time_before64(ktime_get_ns(), READ_ONCE(q->hold_until)) ||
	    !mutex_trylock(&ctx->uring_lock))
		return false;
	w = atomic64_read(&q->lease);
	if (!q->attached || q->dead || q->grp != exec->grp ||
	    IO_W_HOLDER(w) || IO_W_GEN(w) != q->gen ||
	    ctx->submit_state.link.head ||
	    (ctx->int_flags & (IO_RING_F_DRAIN_ACTIVE | IO_RING_F_DRAIN_NEXT |
			      IO_RING_F_OP_RESTRICTED)))
		goto fail;
	nw = IO_W(exec->exec_id, q->gen, IO_W_CURSOR(w));
	if (atomic64_cmpxchg(&q->lease, w, nw) != w)
		goto fail;
	exec->lease_w = nw;
	/* The caller retains its selection ctx reference until after this is cleared. */
	WRITE_ONCE(exec->lease_q, q);
	atomic_or(IORING_SQ_LEASED, &ctx->rings->sq_flags);
	atomic64_inc(&q->lease_acquires);
	trace_io_uring_spare_lease(ctx, exec, IO_SPARE_LEASE_ACQUIRE,
				 IO_W_CURSOR(nw), 0);
	mutex_unlock(&ctx->uring_lock);
	return true;
fail:
	mutex_unlock(&ctx->uring_lock);
	return false;
}

/* Returns KILL at either release-window injection, after leaving that exact state. */
static bool io_exec_lease_drop(struct io_spare_exec *exec, bool taskrun)
{
	struct io_spare_q *q = exec->lease_q;
	struct io_rings *rings;
	u64 w = exec->lease_w;
	bool killed = false;

	if (!q)
		return false;
	if (atomic64_cmpxchg(&q->lease, w, IO_W(0, IO_W_GEN(w), IO_W_CURSOR(w))) == w) {
		rcu_read_lock();
		rings = io_get_rings(q->ctx);
		atomic_andnot(IORING_SQ_LEASED, &rings->sq_flags);
		if (taskrun)
			atomic_or(IORING_SQ_TASKRUN, &rings->sq_flags);
		rcu_read_unlock();
		/* Dekker pair: app tail-store -> mb -> flags-load (sqpoll.c:414-428). */
		smp_mb();
		atomic64_inc(taskrun ? &q->handbacks : &q->releases);
		trace_io_uring_spare_lease(q->ctx, exec, taskrun ?
			IO_SPARE_LEASE_HANDBACK : IO_SPARE_LEASE_RELEASE,
			IO_W_CURSOR(w), taskrun);
		killed = io_spare_dbg_exec(q, IORING_SPARE_DBG_EXEC_RELEASE_WINDOW, 0, exec);
	}
	if (killed)
		return true;
	WRITE_ONCE(exec->lease_q, NULL);
	if (taskrun || atomic_read(&q->nr_rsv_chunks) || !list_empty(&q->rescue))
		return io_spare_rescue_token(q, exec);
	return false;
}

enum io_spare_pull_result {
	IO_PULL_IDLE, IO_PULL_WORK, IO_PULL_BACK, IO_PULL_EXIT,
};

/* All fget() and allocation precede publication, and never run under q->lock. */
static struct io_chunk *io_exec_pull_alloc(struct io_spare_exec *exec,
					 struct io_spare_q *q, u32 cursor, u32 tail)
{
	struct io_ring_ctx *ctx = q->ctx;
	struct io_chunk *chunk;
	int fds[IO_SPARE_MAX_SQES];
	unsigned int nr_fds = 0, i, k, n = min_t(u32, tail - cursor, q->n_max);

	chunk = io_exec_chunk_alloc(exec, q);
	if (!chunk)
		return NULL;
	memset(chunk, 0, offsetof(struct io_chunk, data));
	chunk->size = q->chunk_size;
	chunk->q = q;
	chunk->kind = IO_CHUNK_PULL;
	chunk->start = cursor;
	chunk->sqes = (struct io_uring_sqe *)chunk->data;
	chunk->cqes = (struct io_cqe *)(chunk->sqes + q->n_max);
	chunk->slot = (u8 *)(chunk->cqes + q->n_max);
	chunk->fidx = chunk->slot + q->n_max;
	chunk->copy = PTR_ALIGN((void *)(chunk->fidx + q->n_max), 8);
	INIT_LIST_HEAD(&chunk->list);
	INIT_LIST_HEAD(&chunk->rescue);
	INIT_LIST_HEAD(&chunk->handoff);
	INIT_LIST_HEAD(&chunk->open);
	refcount_set(&chunk->refs, 1);
	percpu_ref_get(&ctx->refs);
	/* tw.c:276-287,310-322 only invoke callbacks, never tctx or request free. */
	chunk->lease = &chunk->lease_tok;
	chunk->fin = &chunk->fin_tok;
	chunk->lease->ctx = chunk->fin->ctx = ctx;
	chunk->lease->flags = chunk->fin->flags = REQ_F_CQE_SKIP;
	chunk->lease->io_task_work.func = io_lease_tw;
	chunk->fin->io_task_work.func = io_fin_tw;
	chunk->lease->big_cqe.extra1 = chunk->fin->big_cqe.extra1 = (unsigned long)chunk;
	for (i = 0; i < n; i++) {
		const struct io_uring_sqe *sqe = &ctx->sq_sqes[(cursor + i) &
							 (ctx->sq_entries - 1)];
		struct file *file = NULL;
		u8 fidx = IO_SPARE_NO_FILE;

		if (!io_spare_eligible(sqe, true) || READ_ONCE(sqe->attr_ptr))
			break;
		if ((READ_ONCE(sqe->opcode) == IORING_OP_READ_FIXED ||
		     READ_ONCE(sqe->opcode) == IORING_OP_WRITE_FIXED) &&
		    !io_rsrc_node_lookup(&ctx->buf_table, READ_ONCE(sqe->buf_index)))
			break;
		if (READ_ONCE(sqe->flags) & IOSQE_FIXED_FILE) {
			struct io_rsrc_node *node = io_rsrc_node_lookup(&ctx->file_table.data,
								 READ_ONCE(sqe->fd));

			if (node)
				file = io_slot_file(node);
		} else {
			int fd = READ_ONCE(sqe->fd);

			for (k = 0; k < nr_fds && fds[k] != fd; k++)
				;
			if (k < nr_fds) {
				/* Previous slots of this fd have the immutable lookup result. */
				unsigned int j;

				for (j = 0; j < i; j++)
					if (chunk->sqes[j].fd == fd &&
					    !(chunk->sqes[j].flags & IOSQE_FIXED_FILE))
						break;
				fidx = chunk->fidx[j];
				if (fidx != IO_SPARE_FILE_BAD)
					file = chunk->files[fidx];
			} else {
				fds[nr_fds++] = fd;
				file = fget(fd);
				if (file) {
					for (k = 0; k < chunk->nr_files &&
					     chunk->files[k] != file; k++)
						;
					if (k < chunk->nr_files) {
						fput(file);
					} else if (k == IO_SPARE_CHUNK_FILES) {
						fput(file);
						break;
					} else {
						chunk->files[chunk->nr_files++] = file;
					}
					fidx = k;
				} else {
					fidx = IO_SPARE_FILE_BAD;
				}
			}
		}
		if (file && (q->flags & IORING_SPARE_F_NO_BLOCK) &&
		    io_spare_write(READ_ONCE(sqe->opcode)) && io_spare_write_punts(file))
			break;
		chunk->fidx[i] = fidx;
		/* Only used to deduplicate fd numbers here; copied afresh after claim. */
		chunk->sqes[i].fd = READ_ONCE(sqe->fd);
		chunk->sqes[i].flags = READ_ONCE(sqe->flags);
	}
	chunk->n = i;
	return chunk;
}

/*
 * Holder: publish the unit [cursor, cursor + k), k <= n_max, claim it and copy
 * its SQEs. Returns IO_PULL_WORK with *out the claimed chunk, ready to be
 * handed off or executed; IO_PULL_IDLE when nothing was published (nothing
 * eligible at the cursor, the ring at u_chunks, no memory), the lessee's
 * streaks updated; IO_PULL_BACK when the lease was lost meanwhile (lease_q
 * cleared); IO_PULL_EXIT when a debug stop ended the copy (STOP set). From the
 * thread loop (io_exec_pull()) and, for an idle sibling, from the holder's own
 * chunk scan (io_exec_publish_more()).
 */
static enum io_spare_pull_result io_exec_publish(struct io_spare_exec *exec,
						 struct io_spare_q *q, u32 cursor,
						 u32 tail, struct io_chunk **out)
{
	struct io_ring_ctx *ctx = q->ctx;
	struct io_spare_port *port = q->ports[exec->exec_id - 1];
	struct io_chunk *chunk;
	u64 nw;
	unsigned int i, free = 0;
	bool withdrew = false, full;

	/*
	 * Pin preparation too: after detach, register.c:512 would otherwise
	 * permit resize/resource updates while we read the SQ and the tables.
	 * Dekker pair with detach: our nr_publishers increment -> mb -> W load
	 * here, the owner's fully ordered takeover CAS of W -> io_spare_frozen()'s
	 * nr_publishers load there. Either the owner stays frozen for us, or we
	 * see the new W and back off. No uring_lock: the owner holds it for every
	 * submit and local work run, and a failed trylock per unit would hand the
	 * lease back that often. Reserve before allocation, so owner takeover
	 * never waits on kmalloc.
	 */
	atomic_inc(&q->nr_publishers);
	smp_mb__after_atomic();
	if (atomic64_read(&q->lease) != exec->lease_w ||
	    !READ_ONCE(q->attached) || READ_ONCE(q->dead)) {
		/* Detach is followed by the owner's takeover, which clears LEASED. */
		atomic_dec(&q->nr_publishers);
		WRITE_ONCE(exec->lease_q, NULL);
		return IO_PULL_BACK;
	}
	chunk = io_exec_pull_alloc(exec, q, cursor, tail);
	if (!chunk) {
		atomic_dec(&q->nr_publishers);
		return IO_PULL_IDLE;
	}
	exec->publishing = chunk;
	if (!chunk->n) {
		if (++q->inelig_streak >= 4)
			WRITE_ONCE(q->hold_until, ktime_get_ns() + NSEC_PER_MSEC);
		io_pull_publisher_put(exec);
		return IO_PULL_IDLE;
	}
	if (q->inelig_streak)
		q->inelig_streak = 0;
	if (io_spare_dbg_exec(q, IORING_SPARE_DBG_EXEC_BEFORE_PUBLISH, 0, exec)) {
		goto killed;
	}
	spin_lock(&q->lock);
	full = q->nr_chunks >= q->u_chunks;
	if (atomic64_read(&q->lease) != exec->lease_w || full) {
		spin_unlock(&q->lock);
		atomic64_inc(&q->abort_publish);
		trace_io_uring_spare_pull_publish(ctx, exec, cursor, chunk->n,
						IO_SPARE_PULL_ABORTED);
		io_pull_publisher_put(exec);
		if (full)
			return IO_PULL_IDLE;
		WRITE_ONCE(exec->lease_q, NULL);
		return IO_PULL_BACK;
	}
	chunk->state = IO_CHUNK_PUBLISHED;
	chunk->seq = ++q->seq;
	memset(chunk->slot, IO_SPARE_RESERVED, chunk->n);
	atomic_set(&chunk->rsv, chunk->n);
	refcount_inc(&chunk->refs); /* list, in addition to the preparation publisher */
	list_add_tail(&chunk->list, &q->pull);
	q->nr_chunks++;
	atomic_inc(&q->nr_rsv_chunks);
	atomic_add(chunk->n, &q->live);
	trace_io_uring_spare_delegate(ctx, chunk->seq, chunk->n, tail - cursor,
				    q->nr_pending, q->nr_chunks);
	trace_io_uring_spare_pull_publish(ctx, exec, cursor, chunk->n,
					IO_SPARE_PULL_PUBLISHED);
	spin_unlock(&q->lock);
	port->delegated += chunk->n;
	port->chunks++;
	if (io_spare_dbg_exec(q, IORING_SPARE_DBG_EXEC_BEFORE_CLAIM, 0, exec))
		goto killed;
	nw = IO_W(exec->exec_id, IO_W_GEN(exec->lease_w), cursor + chunk->n);
	if (atomic64_cmpxchg(&q->lease, exec->lease_w, nw) != exec->lease_w) {
		if (io_spare_dbg_exec(q, IORING_SPARE_DBG_EXEC_BEFORE_WITHDRAW, 0, exec))
			goto killed;
		spin_lock(&q->lock);
		if (cmpxchg(&chunk->state, IO_CHUNK_PUBLISHED, IO_CHUNK_WITHDRAWN) ==
		    IO_CHUNK_PUBLISHED) {
			list_del_init(&chunk->list);
			q->nr_chunks--;
			atomic_set(&chunk->rsv, 0);
			atomic_dec(&q->nr_rsv_chunks);
			atomic_sub(chunk->n, &q->live);
			withdrew = true;
			atomic64_inc(&q->withdraw_exec);
		}
		spin_unlock(&q->lock);
		if (withdrew) {
			trace_io_uring_spare_pull_publish(ctx, exec, cursor, chunk->n,
						IO_SPARE_PULL_WITHDRAW_SELF);
			trace_io_uring_spare_rescue(ctx, chunk->seq, chunk->n, 0,
						    IO_SPARE_RESCUE_PENDING);
			trace_io_uring_spare_retire(ctx, chunk->seq, chunk->n, 0,
						    IO_SPARE_RETIRE_RESCUE);
			/* Only the withdrawal winner releases the immutable file table. */
			while (chunk->nr_files)
				fput(chunk->files[--chunk->nr_files]);
			io_pull_chunk_put(chunk); /* list; publisher still protects it */
			/* Dekker pair with owner DRAIN_ACTIVE-store -> mb -> live-load. */
			smp_mb();
			if (READ_ONCE(ctx->int_flags) & IO_RING_F_DRAIN_ACTIVE) {
				set_bit(IO_RTOK_DRAIN, &q->rbits);
				if (io_spare_rescue_token(q, exec))
					goto killed;
			}
		}
		io_pull_publisher_put(exec);
		WRITE_ONCE(exec->lease_q, NULL);
		return IO_PULL_BACK;
	}
	exec->lease_w = nw;
	WRITE_ONCE(chunk->state, IO_CHUNK_CLAIMED);
	chunk->exec = exec;
	chunk->port = port;
	WRITE_ONCE(exec->busy, true);
	chunk->t_claim = local_clock();
	/*
	 * The claim (statistics and trace, once per executed chunk) belongs to
	 * the executing side: this publisher without hand-off; with it, the
	 * taker (io_exec_take_handoff()) or this publisher, after the copy.
	 */
	if (!(q->flags & IORING_SPARE_F_PULL_HANDOFF)) {
		io_exec_port_activate(exec, chunk->port);
		list_add_tail(&chunk->open, &exec->open);
		port->claims++;
		trace_io_uring_spare_claim(ctx, chunk->seq, chunk->n);
	}
	trace_io_uring_spare_pull_publish(ctx, exec, cursor, chunk->n,
					IO_SPARE_PULL_CLAIMED);
	for (i = 0; i < chunk->n; i++) {
		if (io_spare_dbg_exec(q, IORING_SPARE_DBG_EXEC_MID_COPY, i, exec))
			goto killed;
		if (i + 2 < chunk->n)
			prefetch(&ctx->sq_sqes[(cursor + i + 2) & (ctx->sq_entries - 1)]);
		memcpy(&chunk->sqes[i], &ctx->sq_sqes[(cursor + i) &
							 (ctx->sq_entries - 1)], 64);
		if (cmpxchg(&chunk->slot[i], IO_SPARE_RESERVED, IO_SPARE_FREE) !=
		    IO_SPARE_RESERVED)
			continue;
		if (atomic_dec_and_test(&chunk->rsv))
			atomic_dec(&q->nr_rsv_chunks);
		free++;
	}
	if (io_spare_dbg_exec(q, IORING_SPARE_DBG_EXEC_BEFORE_HEAD, 0, exec))
		goto killed;
	spin_lock(&q->lock);
	if (atomic64_read(&q->lease) == exec->lease_w && q->grp == exec->grp)
		io_spare_publish_head(q, cursor + chunk->n);
	/* Takeover can expose a fully copied chunk while we are off CPU here. */
	if (!chunk->copy_done) {
		atomic_set(&chunk->unvisited, free);
		chunk->copy_done = true;
		if (free)
			list_add_tail(&chunk->rescue, &q->rescue);
	}
	spin_unlock(&q->lock);
	io_pull_publisher_put(exec);
	/* The pull-list ref protects the chunk through execution or handoff. */
	*out = chunk;
	return IO_PULL_WORK;
killed:
	/* A stopped copy still needs the executor's handback and fin path. */
	chunk = exec->publishing;
	if ((q->flags & IORING_SPARE_F_PULL_HANDOFF) && chunk &&
	    READ_ONCE(chunk->state) == IO_CHUNK_CLAIMED) {
		list_add_tail(&chunk->open, &exec->open);
		/* Its fin follows from this executor: claimed, not handed off. */
		port->claims++;
		trace_io_uring_spare_claim(ctx, chunk->seq, chunk->n);
	}
	set_bit(IO_SPARE_STOP, &exec->state);
	return IO_PULL_EXIT;
}

/* One unit per call: the thread loop also services completions and STOP. */
static enum io_spare_pull_result io_exec_pull(struct io_spare_exec *exec,
						     struct io_spare_q *q)
{
	struct io_ring_ctx *ctx = q->ctx;
	struct io_chunk *chunk;
	u32 cursor, tail;

	if (!exec->lease_q && !io_exec_lease_acquire(exec, q))
		return IO_PULL_BACK;
	if (atomic64_read(&q->lease) != exec->lease_w) {
		WRITE_ONCE(exec->lease_q, NULL);
		return IO_PULL_BACK;
	}
	cursor = IO_W_CURSOR(exec->lease_w);
	/* Detached idle selections may overlap resize (register.c:597-700). */
	rcu_read_lock();
	tail = smp_load_acquire(&io_get_rings(ctx)->sq.tail);
	rcu_read_unlock();
	if (cursor == tail) {
		/* Give the sibling its grace; a chunk nobody took is ours again. */
		if (READ_ONCE(q->nr_handoff) && io_spare_handoff_stale(q) &&
		    io_exec_take_handoff(exec, q))
			return IO_PULL_WORK;
		return IO_PULL_IDLE;
	}
	if (!READ_ONCE(q->offer) || !READ_ONCE(q->attached) || READ_ONCE(q->dead) ||
	    test_bit(IO_SPARE_PARK, &exec->state))
		goto handback;
	/*
	 * Inline-first (spec 14.2), lessee side: the application moves the tail
	 * by whole batches, so tail - cursor is its backlog. After a few short
	 * units in a row the lease goes back and stays off for a while; the
	 * owner's submissions then keep the offer off (io_spare_offer()) until a
	 * batch of n_min arrives.
	 */
	if (tail - cursor < q->n_min) {
		if (++q->short_streak >= IO_SPARE_SHORT_UNITS) {
			q->short_streak = 0;
			WRITE_ONCE(q->hold_until, ktime_get_ns() + NSEC_PER_MSEC);
			goto handback;
		}
	} else if (q->short_streak) {
		q->short_streak = 0;
	}
	switch (io_exec_publish(exec, q, cursor, tail, &chunk)) {
	case IO_PULL_WORK:
		break;
	case IO_PULL_IDLE:
		goto handback;
	case IO_PULL_BACK:
		return IO_PULL_BACK;
	case IO_PULL_EXIT:
		return IO_PULL_EXIT;
	}
	if (q->flags & IORING_SPARE_F_PULL_HANDOFF) {
		if (io_exec_handoff(exec, chunk, false))
			return IO_PULL_WORK;
		io_exec_port_activate(exec, chunk->port);
		list_add_tail(&chunk->open, &exec->open);
		chunk->port->claims++;
		trace_io_uring_spare_claim(ctx, chunk->seq, chunk->n);
	}
	io_exec_chunk(chunk);
	return IO_PULL_WORK;
handback:
	if (io_exec_lease_drop(exec, true)) {
		set_bit(IO_SPARE_STOP, &exec->state);
		return IO_PULL_EXIT;
	}
	return IO_PULL_BACK;
}

/* An awake sibling with nothing to do takes a hand-off within a few us. */
static bool io_exec_sibling_idle(struct io_spare_exec *exec)
{
	struct io_spare_grp *grp = exec->grp;
	unsigned int i;

	for (i = 0; i < grp->nr_exec; i++) {
		struct io_spare_exec *sibling = &grp->exec[i];

		if (i != exec->exec_id - 1 && READ_ONCE(sibling->task) &&
		    READ_ONCE(sibling->awake) && !READ_ONCE(sibling->busy) &&
		    !atomic_read(&sibling->offered) &&
		    !test_bit(IO_SPARE_STOP, &sibling->state) &&
		    !test_bit(IO_SPARE_PARK, &sibling->state))
			return true;
	}
	return false;
}

/*
 * Holder, inside its own chunk scan: SQEs the owner stored since this chunk
 * began would otherwise wait for its end, a chunk time, while a sibling sits
 * idle (the single publisher's serialization: a third of the chunks ran on the
 * holder, and the pickup of a new batch took a median 4.6 us at three
 * executors). Publish one unit for such a sibling now; the rest of this chunk
 * follows a unit later. Backlogs below n_min are left to the thread loop and
 * its inline-first streaks. A unit the hinted sibling no longer wants (it got
 * busy meanwhile) is kept as this executor's next chunk (exec->ahead).
 */
static bool io_exec_publish_more(struct io_spare_exec *exec, struct io_spare_q *q)
{
	struct io_chunk *chunk;
	u32 cursor = IO_W_CURSOR(exec->lease_w), tail;

	if (atomic64_read(&q->lease) != exec->lease_w)
		return false;
	rcu_read_lock();
	tail = smp_load_acquire(&io_get_rings(q->ctx)->sq.tail);
	rcu_read_unlock();
	if (tail - cursor < q->n_min || !READ_ONCE(q->offer) ||
	    !READ_ONCE(q->attached) || READ_ONCE(q->dead) ||
	    READ_ONCE(q->nr_chunks) >= q->u_chunks ||
	    test_bit(IO_SPARE_PARK, &exec->state) || !io_exec_sibling_idle(exec))
		return false;
	if (io_exec_publish(exec, q, cursor, tail, &chunk) != IO_PULL_WORK)
		return false;
	chunk->port->early++;
	if (io_exec_handoff(exec, chunk, true))
		return true;
	io_exec_port_activate(exec, chunk->port);
	list_add_tail(&chunk->open, &exec->open);
	chunk->port->claims++;
	chunk->port->early_kept++;
	trace_io_uring_spare_claim(q->ctx, chunk->seq, chunk->n);
	exec->ahead = chunk;
	return true;
}

static struct io_spare_q *io_exec_select(struct io_spare_grp *grp)
{
	struct io_spare_q *q, *best = NULL;
	unsigned int max_pending = 0;

	spin_lock(&grp->lock);
	/* An owner's wake names its ring: no scan of every ring's claim line then. */
	if (grp->hint &&
	    (READ_ONCE(grp->hint->nr_pending) || READ_ONCE(grp->hint->nr_handoff))) {
		best = grp->hint;
		max_pending = READ_ONCE(best->nr_pending) + READ_ONCE(best->nr_handoff);
		grp->hint = NULL;
	} else {
		list_for_each_entry(q, &grp->ctx_list, grp_node) {
			unsigned int pending = READ_ONCE(q->nr_pending) +
					       READ_ONCE(q->nr_handoff);

			if (pending > max_pending) {
				best = q;
				max_pending = pending;
			}
		}
	}
	if (!best && atomic_read(&grp->nr_offers)) {
		unsigned int most = 0;
		u64 now = ktime_get_ns();

		list_for_each_entry(q, &grp->ctx_list, grp_node) {
			u64 w = atomic64_read(&q->lease);
			unsigned int pending;

			if (!io_spare_pull_available(q, w, now))
				continue;
			pending = smp_load_acquire(&q->ctx->rings->sq.tail) - IO_W_CURSOR(w);
			if (!best || pending > most) {
				best = q;
				most = pending;
			}
		}
	}
	/* This is a one-element ctx snapshot; release grp->lock before q->lock. */
	if (best && !percpu_ref_tryget(&best->ctx->refs))
		best = NULL;
	spin_unlock(&grp->lock);
	if (best)
		trace_io_uring_spare_select(best->ctx, max_pending);
	return best;
}

static struct io_chunk *io_exec_claim(struct io_spare_exec *exec,
				      struct io_spare_q *q)
{
	struct io_chunk *chunk = NULL;

	spin_lock(&q->lock);
	if (q->attached && !q->dead && q->grp == exec->grp &&
	    !list_empty(&q->pending)) {
		chunk = list_first_entry(&q->pending, struct io_chunk, list);
		list_move_tail(&chunk->list, &q->inflight);
		q->nr_pending--;
		atomic_dec(&exec->grp->nr_pending);
		atomic_set(&chunk->unvisited, chunk->n);
		list_add_tail(&chunk->rescue, &q->rescue);
		chunk->exec = exec;
		list_add_tail(&chunk->open, &exec->open);
	}
	spin_unlock(&q->lock);
	if (chunk) {
		chunk->t_claim = local_clock();
		/* Same group under q->lock: registration made a port for every executor. */
		chunk->port = READ_ONCE(q->ports[exec - exec->grp->exec]);
		io_exec_port_activate(exec, chunk->port);
		/* Owner rescue harvests only from a busy executor that is off CPU. */
		WRITE_ONCE(exec->busy, true);
		chunk->port->claims++;
		trace_io_uring_spare_claim(q->ctx, chunk->seq, chunk->n);
	}
	return chunk;
}

/*
 * Executor, holding ctx refs of old and next: serve next instead of old. An
 * owner about to wait leaves its unclaimed chunks to an executor serving its
 * ring on a CPU and sleeps (io_spare_rescue_pick()); once none serves it, it
 * must take them back. Dekker pair with io_spare_wait_unserved(): serving
 * store / cq_wait_nr load here, cq_wait_nr store / serving load there, each
 * with a full barrier between. Reselecting the same ring leaves no gap.
 */
static void io_exec_serve(struct io_spare_exec *exec, struct io_spare_q *old,
			  struct io_spare_q *next)
{
	struct io_ring_ctx *ctx;

	WRITE_ONCE(exec->serving, next);
	if (!old || old == next)
		return;
	ctx = old->ctx;
	smp_mb();
	if (READ_ONCE(old->nr_pending) && atomic_read(&ctx->cq_wait_nr) >= 0)
		wake_up_state(ctx->submitter_task, TASK_INTERRUPTIBLE);
}

static void io_exec_cancel(struct io_spare_exec *exec)
{
	struct io_uring_task *tctx = current->io_uring;
	struct io_chunk *chunk, *next;

	exec->ahead = NULL;	/* on exec->open like the rest */
	list_for_each_entry_safe(chunk, next, &exec->open, open) {
		io_exec_return_slots(chunk);
		chunk->scanned = true;
		io_chunk_maybe_fin(chunk);
	}
	/*
	 * Requests still in flight are left to the owner: their completions go
	 * there once the ports are released, and they hold this task's refs, so
	 * the tctx lives on with the task (__io_uring_free()), as for the SQPOLL
	 * thread. Nothing here waits for an owner, which may itself wait for us
	 * in de_thread(), or be gone with this task holding the ring's files.
	 */
	io_exec_ports_release(exec);
	io_exec_drain(exec, true);
	io_uring_drop_tctx_refs(current);
	WARN_ON_ONCE(!list_empty(&exec->open));
	/*
	 * FAST has no io-wq, poll, timeout or WAITQ backend: the io_wq is unused.
	 * Still mark it exiting first, as io_uring_cancel_generic() does, since
	 * io_wq_put_and_exit() expects that (io-wq.c).
	 */
	if (tctx->io_wq)
		io_wq_exit_start(tctx->io_wq);
	io_uring_clean_tctx(tctx);
}

#ifdef CONFIG_PREEMPT_NOTIFIERS
static void io_spare_pn_sched_out(struct preempt_notifier *pn,
				 struct task_struct *next)
{
	struct io_spare_exec *exec = container_of(pn, struct io_spare_exec, pn);
	struct io_spare_q *q = READ_ONCE(exec->lease_q);

	/* preempt.h:360: rq lock and IRQs off; eventfd signalling must wait. */
	if (q && !(READ_ONCE(q->flags) & IORING_SPARE_F_NO_NOTIFIER))
		irq_work_queue(&q->notify_work);
}

static void io_spare_pn_sched_in(struct preempt_notifier *pn, int cpu)
{
}

static struct preempt_ops io_spare_pn_ops = {
	.sched_out = io_spare_pn_sched_out,
	.sched_in = io_spare_pn_sched_in,
};
#endif

static int io_spare_thread(void *data)
{
	struct io_spare_exec *exec = data;
	struct io_spare_grp *grp = exec->grp;
	const struct cred *old_creds;
	struct io_spare_q *selected = NULL;
	unsigned int selected_chunks = 0, pull_gen_seen = 0;
	u64 selected_at = 0, idle_at, cancel_at, sibling_scan_at = 0;
	char name[TASK_COMM_LEN];
	DEFINE_WAIT(wait);

	if (!current->io_uring)
		goto out;
	/* io_spare_req_exec(): this thread's requests may use its private caches. */
	current->io_uring->spare_exec = exec;
#ifdef CONFIG_PREEMPT_NOTIFIERS
	preempt_notifier_init(&exec->pn, &io_spare_pn_ops);
	preempt_notifier_register(&exec->pn);
#endif
	snprintf(name, sizeof(name), "iou-spr-%d", exec->owner_pid);
	set_task_comm(current, name);
	if (exec->cpu >= 0)
		set_cpus_allowed_ptr(current, cpumask_of(exec->cpu));
	else
		set_cpus_allowed_ptr(current, grp->mask);
	old_creds = override_creds(grp->creds);
	audit_uring_entry(IORING_OP_NOP);
	audit_uring_exit(true, 0);
	atomic_inc(&grp->nr_awake);
	WRITE_ONCE(exec->awake, true);
	/* A wake can reserve credit before a newly created task first runs. */
	atomic_dec_if_positive(&grp->wake_credit);
	idle_at = ktime_get_ns();
	for (;;) {
		struct io_chunk *chunk;
		bool slept, credited;
		unsigned int reaped;
		u64 now;

		reaped = io_exec_drain(exec, false);
		if (signal_pending(current)) {
			struct ksignal ksig;

			if (get_signal(&ksig))
				break;
		}
		if (test_bit(IO_SPARE_STOP, &exec->state))
			break;
		now = ktime_get_ns();
		/*
		 * The selection budget for chunks claimed or published ahead of the
		 * loop (io_exec_chunk(), io_exec_publish_more()): none once
		 * reselection is due, so a chunk held ahead cannot postpone it.
		 */
		exec->may_ahead = selected && selected_chunks < 8 &&
				  now - selected_at < IO_SPARE_RESELECT_NS &&
				  !test_bit(IO_SPARE_PARK, &exec->state);
		/* A takeover invalidates the whole W, including an old attachment. */
		if (exec->lease_q && atomic64_read(&exec->lease_q->lease) != exec->lease_w) {
			io_exec_handoff_drain(exec, selected);
			WRITE_ONCE(exec->lease_q, NULL);
			io_exec_serve(exec, selected, NULL);
			percpu_ref_put(&selected->ctx->refs);
			selected = NULL;
		}
		/* Completions reach us only while the owner is busy: stay for more. */
		if (reaped)
			idle_at = now;
		/*
		 * A lessee with nothing else to serve keeps its lease for another
		 * period: checking the group under grp->lock on every pass after the
		 * period ended would cost a lock round trip per unit.
		 */
		if (selected && exec->lease_q && !exec->ahead &&
		    !test_bit(IO_SPARE_PARK, &exec->state) &&
		    (selected_chunks >= 8 || now - selected_at >= IO_SPARE_RESELECT_NS) &&
		    !io_spare_group_work(grp, selected)) {
			selected_chunks = 0;
			selected_at = now;
		}
		/* A chunk claimed ahead belongs to the selected ring: finish it first. */
		if (selected && !exec->ahead && (selected_chunks >= 8 ||
		    now - selected_at >= IO_SPARE_RESELECT_NS ||
		    test_bit(IO_SPARE_PARK, &exec->state))) {
			struct io_spare_q *next = NULL;

			io_exec_handoff_drain(exec, selected);
			if (exec->lease_q && io_exec_lease_drop(exec, true))
				break;
			/* Select before letting go: the same ring stays served. */
			/* Snapshot before the scan: a bump during it must still end a stay. */
			pull_gen_seen = atomic_read(&grp->pull_gen);
			if (!test_bit(IO_SPARE_PARK, &exec->state) &&
			    (atomic_read(&grp->nr_pending) || atomic_read(&grp->nr_handoff) ||
			     atomic_read(&grp->nr_offers)))
				next = io_exec_select(grp);
			io_exec_serve(exec, selected, next);
			percpu_ref_put(&selected->ctx->refs);
			selected = next;
			selected_chunks = 0;
			selected_at = now;
		}
		/* Lingering executors poll a counter, not grp->lock. */
		if (!selected && !test_bit(IO_SPARE_PARK, &exec->state) &&
		    (atomic_read(&grp->nr_pending) || atomic_read(&grp->nr_handoff) ||
		     atomic_read(&grp->nr_offers))) {
			pull_gen_seen = atomic_read(&grp->pull_gen);
			selected = io_exec_select(grp);
			selected_chunks = 0;
			selected_at = now;
			/* Its owner may now wait instead of taking chunks back. */
			io_exec_serve(exec, NULL, selected);
		}
		if (exec->ahead) {
			chunk = exec->ahead;
			exec->ahead = NULL;
			/* Its cost sample starts now, not at the early claim. */
			chunk->t_claim = local_clock();
		} else {
			/* The holder keeps copying while siblings take its queued chunks. */
			if (selected && exec->lease_q != selected &&
			    READ_ONCE(selected->nr_handoff) &&
			    io_exec_take_handoff(exec, selected)) {
				exec->empty_wakes = 0;
				selected_chunks++;
				exec->busy_end = ktime_get_ns();
				idle_at = exec->busy_end;
				cond_resched();
				continue;
			}
			/* A lessee lingers with selected held: no q->lock trip per poll. */
			chunk = selected && READ_ONCE(selected->nr_pending) ?
				io_exec_claim(exec, selected) : NULL;
		}
		if (chunk) {
			/*
			 * Size linger to the idle gap between bursts (docs/12 5.3).
			 * Claim-to-claim time would shrink it with the chunk size,
			 * and back-to-back claims inside a burst must not shrink it.
			 */
			if (exec->busy_end && now - exec->busy_end > exec->linger_ns / 2)
				exec->linger_ns = min(2 * (now - exec->busy_end),
						      grp->linger_ns);
			exec->empty_wakes = 0;
			selected_chunks++;
			exec->may_ahead = selected_chunks < 8 &&
					  now - selected_at < IO_SPARE_RESELECT_NS;
			io_exec_chunk(chunk);
			idle_at = exec->busy_end = ktime_get_ns();
			cond_resched();
			continue;
		}
		if (selected && selected->pull_ok) {
			enum io_spare_pull_result result = io_exec_pull(exec, selected);

			if (result == IO_PULL_EXIT)
				break;
			if (result == IO_PULL_WORK) {
				exec->empty_wakes = 0;
				selected_chunks++;
				idle_at = exec->busy_end = ktime_get_ns();
				cond_resched();
				continue;
			}
			if (result == IO_PULL_IDLE) {
				u32 cursor = IO_W_CURSOR(exec->lease_w);
				u32 tail;

				if (!test_bit(IO_SPARE_PARK, &exec->state) &&
				    now - idle_at < exec->linger_ns && !need_resched()) {
					cpu_relax();
					continue;
				}
				if (io_exec_lease_drop(exec, false))
					break;
				/* Paired with the app's tail-store -> mb -> LEASED-load. */
				rcu_read_lock();
				tail = smp_load_acquire(&io_get_rings(selected->ctx)->sq.tail);
				rcu_read_unlock();
				if (cursor != tail &&
				    io_exec_lease_acquire(exec, selected))
					continue;
			}
			/*
			 * Another executor holds the lease of this offered ring:
			 * stay selected and linger, polling its hand-off counter
			 * and the lease word (both read-shared), instead of
			 * releasing the selection and reselecting on every pass
			 * (grp->lock, a ctx ref, uring_lock trylock in acquire).
			 * Work for another ring ends the stay at once: a hand-off or
			 * push chunk queued elsewhere (group counters above this
			 * ring's), or an owner's submit on a ring without a holder
			 * (pull_gen). Those group counters are written per chunk by
			 * the holder and the takers: read them every few us, not per
			 * pass, so the spin does not keep pulling their line away
			 * from the writers. The periodic reselection above still runs.
			 */
			if (result == IO_PULL_BACK && !exec->lease_q &&
			    io_spare_lease_elsewhere(selected, exec) &&
			    !test_bit(IO_SPARE_PARK, &exec->state) &&
			    now - idle_at < exec->linger_ns && !need_resched()) {
				if (now - sibling_scan_at < IO_SPARE_SIBLING_SCAN_NS) {
					cpu_relax();
					continue;
				}
				sibling_scan_at = now;
				if (atomic_read(&grp->pull_gen) == pull_gen_seen &&
				    atomic_read(&grp->nr_handoff) == READ_ONCE(selected->nr_handoff) &&
				    atomic_read(&grp->nr_pending) == READ_ONCE(selected->nr_pending)) {
					cpu_relax();
					continue;
				}
			}
		}
		if (selected) {
			io_exec_handoff_drain(exec, selected);
			io_exec_serve(exec, selected, NULL);
			percpu_ref_put(&selected->ctx->refs);
			selected = NULL;
		}
		if (!test_bit(IO_SPARE_PARK, &exec->state) &&
		    now - idle_at < exec->linger_ns && !need_resched()) {
			cpu_relax();
			continue;
		}
		/* Asleep we poll nothing: the owners finish our completions meanwhile. */
		io_exec_ports_release(exec);
		prepare_to_wait_exclusive(&grp->wq, &wait, TASK_INTERRUPTIBLE);
		WRITE_ONCE(exec->awake, false);
		atomic_dec(&grp->nr_awake);
		/*
		 * Pairs with wq_has_sleeper() in io_spare_delegate(): the owner reads
		 * nr_awake after publishing nr_pending, we read nr_pending after
		 * dropping nr_awake. atomic_dec_if_positive() below is not a barrier
		 * when it does not decrement.
		 */
		smp_mb__after_atomic();
		/* Reap a reservation overtaken by an independent completion wake. */
		atomic_dec_if_positive(&grp->wake_credit);
		slept = false;
		if (!test_bit(IO_SPARE_STOP, &exec->state) &&
		    (test_bit(IO_SPARE_PARK, &exec->state) ||
		     (!atomic_read(&grp->nr_pending) &&
		      !atomic_read(&grp->nr_handoff) &&
		      (!atomic_read(&grp->nr_offers) || !io_spare_group_work(grp, NULL)))) &&
		    mpscq_empty(&current->io_uring->task_list) &&
		    !task_work_pending(current) && !signal_pending(current)) {
			atomic64_inc(&grp->sleeps);
			trace_io_uring_spare_exec_sleep(exec->linger_ns, now - idle_at);
			schedule();
			slept = true;
		}
		finish_wait(&grp->wq, &wait);
		atomic_inc(&grp->nr_awake);
		WRITE_ONCE(exec->awake, true);
		/* Consuming a credit means the owner woke us for a published chunk. */
		credited = atomic_dec_if_positive(&grp->wake_credit) >= 0;
		idle_at = ktime_get_ns();
		if (slept) {
			unsigned int pending = atomic_read(&grp->nr_pending);
			/*
			 * An empty wake found neither a chunk nor task_work to run
			 * (docs/12 5.3). Completions never wake an executor: while
			 * it sleeps, the owners finish them.
			 */
			bool empty = !pending &&
				     !atomic_read(&grp->nr_handoff) &&
				     (!atomic_read(&grp->nr_offers) ||
				      !io_spare_group_work(grp, NULL)) &&
				     mpscq_empty(&current->io_uring->task_list) &&
				     !task_work_pending(current);

			if (!empty) {
				exec->empty_wakes = 0;
			} else if (credited) {
				/*
				 * The chunk existed but an owner rescue or another
				 * executor took it first. That is not an idle wake:
				 * with linger 0 every later wake loses the same race
				 * and this executor never claims again, so stay for
				 * the next burst instead.
				 */
				atomic64_inc(&grp->empty_wakes);
				exec->empty_wakes = 0;
				exec->linger_ns = grp->linger_ns;
			} else {
				atomic64_inc(&grp->empty_wakes);
				if (++exec->empty_wakes >= 2)
					exec->linger_ns = 0;
			}
			trace_io_uring_spare_exec_wake(idle_at - now, pending, empty);
		}
	}
	WRITE_ONCE(exec->awake, false);
	if (selected)
		io_exec_handoff_drain(exec, selected);
	if (exec->lease_q) {
		struct io_spare_q *q = exec->lease_q;
		struct io_rings *rings;

		/* Leave W/chunk states for takeover; no ACK is needed from this task. */
		rcu_read_lock();
		rings = io_get_rings(q->ctx);
		atomic_andnot(IORING_SQ_LEASED, &rings->sq_flags);
		atomic_or(IORING_SQ_TASKRUN, &rings->sq_flags);
		rcu_read_unlock();
		trace_io_uring_spare_lease(q->ctx, exec, IO_SPARE_LEASE_DROP,
					 IO_W_CURSOR(exec->lease_w), IO_SPARE_STOP);
		io_spare_rescue_token(q, exec);
		WRITE_ONCE(exec->lease_q, NULL);
	}
	io_pull_publisher_put(exec);
	if (selected) {
		io_exec_serve(exec, selected, NULL);
		percpu_ref_put(&selected->ctx->refs);
	}
#ifdef CONFIG_PREEMPT_NOTIFIERS
	preempt_notifier_unregister(&exec->pn);
#endif
	atomic_dec(&grp->nr_awake);
	atomic_dec(&grp->nr_live);
	atomic_dec_if_positive(&grp->wake_credit);
	cancel_at = ktime_get_ns();
	io_exec_cancel(exec);
	trace_io_uring_spare_exec_exit(ktime_get_ns() - cancel_at);
	revert_creds(old_creds);
	goto exited;
out:
	atomic_dec(&grp->nr_live);
	atomic_dec_if_positive(&grp->wake_credit);
exited:
	io_exec_cache_free(exec);
	spin_lock(&grp->lock);
	WRITE_ONCE(exec->task, NULL);
	spin_unlock(&grp->lock);
	put_task_struct(current);
	complete(&exec->exited);
	io_spare_grp_put(grp);
	do_exit(0);
}

/* Called with io_spare_mutex, never with uring_lock or q->lock. */
static void io_spare_stop(struct io_spare_grp *grp)
{
	unsigned int i;

	spin_lock(&grp->lock);
	for (i = 0; i < grp->nr_exec; i++) {
		struct io_spare_exec *exec = &grp->exec[i];

		set_bit(IO_SPARE_STOP, &exec->state);
		if (exec->task)
			wake_up_process(exec->task);
	}
	spin_unlock(&grp->lock);
	wake_up_all(&grp->wq);
}

static struct io_spare_grp *io_spare_create(struct io_ring_ctx *ctx,
					    struct io_uring_spare_reg *reg)
{
	struct io_spare_grp *grp;
	cpumask_var_t mask, allowed;
	unsigned int i;
	int cpu = -1, ret = -ENOMEM;

	if (!reg->nr_exec || reg->nr_exec > IO_SPARE_MAX_EXEC ||
	    reg->linger_us > 1000 || (!reg->cpumask && reg->cpumask_len))
		return ERR_PTR(-EINVAL);
	ret = security_uring_sqpoll();
	if (ret)
		return ERR_PTR(ret);
	if (!zalloc_cpumask_var(&mask, GFP_KERNEL))
		return ERR_PTR(-ENOMEM);
	if (!alloc_cpumask_var(&allowed, GFP_KERNEL)) {
		free_cpumask_var(mask);
		return ERR_PTR(-ENOMEM);
	}
	cpuset_cpus_allowed(current, allowed);
	if (!reg->cpumask) {
		/*
		 * No mask: stay on the registrant's NUMA node. Every chunk, CQE
		 * and buffered-read buffer crosses between owner and executor;
		 * across sockets that costs several times more (handoff.c).
		 */
		cpumask_and(mask, cpumask_of_node(numa_node_id()), allowed);
		cpumask_and(mask, mask, cpu_online_mask);
		if (cpumask_empty(mask))
			cpumask_and(mask, allowed, cpu_online_mask);
	}
	if (reg->cpumask) {
		ret = -EINVAL;
		if (!reg->cpumask_len || reg->cpumask_len > cpumask_size())
			goto free_mask;
		ret = -EFAULT;
		if (copy_from_user(cpumask_bits(mask), u64_to_user_ptr(reg->cpumask),
				   reg->cpumask_len))
			goto free_mask;
		ret = -EINVAL;
		if (!cpumask_subset(mask, allowed) ||
		    !cpumask_subset(mask, cpu_online_mask) || cpumask_empty(mask))
			goto free_mask;
		cpu = cpumask_first(mask);
	}
	ret = -ENOMEM;
	grp = kzalloc(struct_size(grp, exec, reg->nr_exec), GFP_KERNEL);
	if (!grp)
		goto free_mask;
	if (!zalloc_cpumask_var(&grp->mask, GFP_KERNEL)) {
		kfree(grp);
		goto free_mask;
	}
	cpumask_copy(grp->mask, mask);
	refcount_set(&grp->refs, 1);
	spin_lock_init(&grp->lock);
	INIT_LIST_HEAD(&grp->ctx_list);
	init_waitqueue_head(&grp->wq);
	grp->creds = get_current_cred();
	grp->tgid = current->tgid;
	grp->nr_exec = reg->nr_exec;
	grp->linger_ns = (u64)(reg->linger_us ?: 50) * NSEC_PER_USEC;
#ifdef CONFIG_PREEMPT_NOTIFIERS
	preempt_notifier_inc();
#endif
	for (i = 0; i < reg->nr_exec; i++) {
		struct io_spare_exec *exec = &grp->exec[i];
		struct io_uring_task *tctx;
		struct task_struct *task;

		exec->grp = grp;
		exec->exec_id = i + 1;
		exec->cpu = cpu;
		exec->owner_pid = current->pid;
		/* The registration bounds the idle spin (linger_us <= 1000); bursts shrink it. */
		exec->linger_ns = grp->linger_ns;
		INIT_LIST_HEAD(&exec->open);
		INIT_LIST_HEAD(&exec->ports);
		init_completion(&exec->exited);
		if (io_alloc_cache_init(&exec->rw_cache, IO_ALLOC_CACHE_MAX,
					sizeof(struct io_async_rw),
					offsetof(struct io_async_rw, clear))) {
			ret = -ENOMEM;
			goto stop;
		}
		task = create_io_thread(io_spare_thread, exec, NUMA_NO_NODE);
		if (IS_ERR(task)) {
			io_alloc_cache_free(&exec->rw_cache, io_rw_cache_free);
			ret = PTR_ERR(task);
			goto stop;
		}
		refcount_inc(&grp->refs);
		atomic_inc(&grp->nr_live);
		get_task_struct(task);
		spin_lock(&grp->lock);
		WRITE_ONCE(exec->task, task);
		spin_unlock(&grp->lock);
		/* tctx.c:23 takes uring_lock; registration has dropped it here. */
		tctx = io_uring_alloc_task_context(task, ctx);
		if (!IS_ERR(tctx))
			task->io_uring = tctx;
		wake_up_new_task(task);
		if (IS_ERR(tctx)) {
			ret = PTR_ERR(tctx);
			goto stop;
		}
		if (cpu >= 0) {
			cpu = cpumask_next(cpu, mask);
			if (cpu >= nr_cpu_ids)
				cpu = cpumask_first(mask);
		}
	}
	free_cpumask_var(allowed);
	free_cpumask_var(mask);
	return grp;
stop:
	io_spare_stop(grp);
	io_spare_grp_put(grp);
free_mask:
	free_cpumask_var(allowed);
	free_cpumask_var(mask);
	return ERR_PTR(ret);
}

static struct io_spare_grp *io_spare_attach(int fd)
{
	struct io_spare_grp *grp;
	struct io_ring_ctx *ctx;
	struct file *file = fget(fd);

	if (!file)
		return ERR_PTR(-EINVAL);
	grp = ERR_PTR(-EINVAL);
	if (!io_is_uring_fops(file))
		goto out;
	ctx = file->private_data;
	if (!ctx->spare || !READ_ONCE(ctx->spare->attached))
		goto out;
	grp = ctx->spare->grp;
	if (grp->tgid != current->tgid) {
		grp = ERR_PTR(-EPERM);
		goto out;
	}
	refcount_inc(&grp->refs);
out:
	fput(file);
	return grp;
}

static void io_spare_port_free(struct io_spare_port *port)
{
	kmem_cache_free(req_cachep, port->token);
	kfree(port->journal);
	kfree(port);
}

/* Async requests still out, or (held) an executor still at a port. */
static bool io_spare_ports_busy(struct io_spare_q *q, bool held)
{
	unsigned int i;

	for (i = 0; i < READ_ONCE(q->nr_ports); i++) {
		struct io_spare_port *port = READ_ONCE(q->ports[i]);

		if (port && (atomic_read(&port->outstanding) ||
			     (held && smp_load_acquire(&port->held))))
			return true;
	}
	return false;
}

/*
 * Registration: one port per executor index, kept across registrations and
 * freed with the ring. The journal token is not a cached request: it counts
 * in neither nr_req_allocated (drain) nor ctx->refs, and is only queued while
 * its executor holds a ctx ref (io_exec_port_kick()).
 */
static int io_spare_ports_init(struct io_ring_ctx *ctx, struct io_spare_q *q,
			       struct io_spare_grp *grp)
{
	unsigned int i;

	for (i = 0; i < grp->nr_exec; i++) {
		struct io_spare_port *port = q->ports[i];
		struct io_kiocb *token;

		if (!port) {
			port = kzalloc_obj(*port);
			if (!port)
				return -ENOMEM;
			port->journal = kmalloc_array(IO_SPARE_JOURNAL,
						      sizeof(*port->journal),
						      GFP_KERNEL);
			token = kmem_cache_alloc(req_cachep, GFP_KERNEL | __GFP_ZERO);
			if (!port->journal || !token) {
				if (token)
					kmem_cache_free(req_cachep, token);
				kfree(port->journal);
				kfree(port);
				return -ENOMEM;
			}
			port->q = q;
			init_llist_head(&port->done);
			INIT_LIST_HEAD(&port->node);
			token->ctx = ctx;
			token->tctx = current->io_uring;
			token->opcode = IORING_OP_NOP;
			token->flags = REQ_F_CQE_SKIP;
			token->io_task_work.func = io_spare_port_tw;
			token->big_cqe.extra2 = (unsigned long)port;
			port->token = token;
			WRITE_ONCE(q->ports[i], port);
			WRITE_ONCE(q->nr_ports, max(q->nr_ports, i + 1));
		}
		port->exec = &grp->exec[i];
	}
	/* Ports past this group's executors keep no stale executor. */
	for (; i < q->nr_ports; i++)
		if (q->ports[i])
			q->ports[i]->exec = NULL;
	return 0;
}

int io_register_spare(struct io_ring_ctx *ctx, void __user *arg,
		      unsigned int nr_args)
{
	const unsigned int required = IORING_SETUP_SINGLE_ISSUER |
		IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SUBMIT_ALL;
	const unsigned int rejected = IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL |
		IORING_SETUP_SQE128 | IORING_SETUP_SQE_MIXED |
		IORING_SETUP_CQE32 | IORING_SETUP_CQE_MIXED |
		IORING_SETUP_SQ_REWIND;
	struct io_uring_spare_reg reg;
	struct io_uring_spare_reg __user *user = arg;
	struct io_spare_grp *grp, *old_grp = NULL;
	struct io_spare_q *q;
	size_t size;
	int ret = -EINVAL;

	lockdep_assert_held(&ctx->uring_lock);
	BUILD_BUG_ON(sizeof(struct io_uring_spare_reg) != 56);
	BUILD_BUG_ON(offsetof(struct io_uring_spare_reg, rescue_us) != 48);
	BUILD_BUG_ON(offsetof(struct io_uring_spare_reg, features) != 52);
	BUILD_BUG_ON(sizeof(struct io_uring_spare_debug) != 32);
	if (nr_args != 1)
		return -EINVAL;
	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;
	if ((reg.flags & ~(((1U << 10) - 1) | IORING_SPARE_F_PULL_HANDOFF)) ||
	    reg.attach_fd < -1 || reg.n_max > IO_SPARE_MAX_SQES ||
	    reg.n_min > IO_SPARE_MAX_SQES || reg.linger_us > 1000 ||
	    reg.mode > IORING_SPARE_MODE_NEVER ||
	    (ctx->flags & required) != required || (ctx->flags & rejected) ||
	    ctx->bpf_filters || ctx->submitter_task != current)
		return -EINVAL;
	reg.features = 0;
	if ((ctx->flags & (IORING_SETUP_NO_SQARRAY | IORING_SETUP_TASKRUN_FLAG)) ==
	    (IORING_SETUP_NO_SQARRAY | IORING_SETUP_TASKRUN_FLAG) &&
	    !(reg.flags & IORING_SPARE_F_NO_PULL))
		reg.features |= IORING_SPARE_FEAT_PULL;
	/* Output may fault: publish no attachment or reusable state before it succeeds. */
	if (put_user(reg.features, &user->features))
		return -EFAULT;
	q = ctx->spare;
	/* A port may get another executor only once the previous one left it. */
	if (q && (q->attached || q->nr_chunks || atomic_read(&q->nr_publishers) ||
		  io_spare_ports_busy(q, true)))
		return -EBUSY;
	if (q) {
		old_grp = q->grp;
		/* fdinfo reads grp under uring_lock; old selectors use q->lock. */
		spin_lock(&q->lock);
		q->grp = NULL;
		spin_unlock(&q->lock);
	} else {
		/* A power-of-two kmalloc keeps the per-line split above intact. */
		q = kzalloc(roundup_pow_of_two(sizeof(*q)), GFP_KERNEL);
		if (!q)
			return -ENOMEM;
		q->rtoken = kmem_cache_alloc(req_cachep, GFP_KERNEL | __GFP_ZERO);
		if (!q->rtoken) {
			kfree(q);
			return -ENOMEM;
		}
		q->ctx = ctx;
		spin_lock_init(&q->lock);
		INIT_LIST_HEAD(&q->pending);
		INIT_LIST_HEAD(&q->handoff);
		init_llist_head(&q->pull_pool);
		INIT_LIST_HEAD(&q->inflight);
		INIT_LIST_HEAD(&q->pull);
		INIT_LIST_HEAD(&q->rescue);
		INIT_LIST_HEAD(&q->grp_node);
		INIT_LIST_HEAD(&q->free_chunks);
		q->rtoken->ctx = ctx;
		q->rtoken->tctx = current->io_uring;
		q->rtoken->opcode = IORING_OP_NOP;
		q->rtoken->flags = REQ_F_CQE_SKIP;
		q->rtoken->io_task_work.func = io_spare_rtoken_tw;
		q->rtoken->big_cqe.extra1 = (unsigned long)q;
		init_irq_work(&q->notify_work, io_spare_notify_fn);
#ifdef CONFIG_IO_URING_SPARE_DEBUG
		spin_lock_init(&q->dbg_lock);
		init_waitqueue_head(&q->dbg_wait);
#endif
		WRITE_ONCE(ctx->spare, q);
	}
	q->dead = true;
	/* Recycled chunks have the previous registration's size. */
	io_spare_free_chunks(q);
	q->n_max = reg.n_max ?: 32;
	q->n_min = min(reg.n_min ?: IO_SPARE_MIN_RUN, q->n_max);
	q->u_pending = reg.u_pending ?: 4;
	q->u_chunks = reg.u_chunks ?: 16;
	q->mode = reg.mode;
	q->flags = reg.flags;
	/* EXEC_BLOCK/EXEC_FINISH/NO_TIER are stored for later S4/S6/S7 behavior. */
	q->rescue_ns = (reg.rescue_us ? clamp(reg.rescue_us, 10U, 100000U) :
			1000U) * NSEC_PER_USEC;
	if (!IS_ENABLED(CONFIG_PREEMPT_NOTIFIERS) ||
	    (q->flags & IORING_SPARE_F_NO_NOTIFIER))
		q->rescue_ns = min_t(u32, q->rescue_ns, 100 * NSEC_PER_USEC);
	q->ready_hits = 0;
	q->sampled = false;
	q->t_submit = 0;
	/* Measured on the development host; the EWMAs take over within a few submissions. */
	q->cost_inline = 650;
	q->cost_chunk = 800;
	q->cost_exec = 0;
	size = offsetof(struct io_chunk, data) + q->n_max *
		(sizeof(struct io_uring_sqe) + sizeof(struct io_cqe) + 2 * sizeof(u8));
	size = ALIGN(size, 8) + q->n_max * sizeof(struct io_spare_copy);
	/*
	 * kmalloc() aligns power-of-two sizes naturally, which keeps the
	 * owner/executor cache line split in io_chunk. No per-ring kmem_cache:
	 * creating and destroying one per registration collides in SLUB sysfs
	 * (merged caches share a size-based name) and costs a slab_mutex trip.
	 */
	q->chunk_size = roundup_pow_of_two(size);
	/* Rescue runs in the wait path; allocate its scratch once, under uring_lock. */
	kfree(q->rescue_buf);
	q->rescue_buf = kmalloc_array(q->n_max, sizeof(*q->rescue_buf), GFP_KERNEL);
	if (!q->run)
		q->run = kzalloc(sizeof(*q->run), GFP_KERNEL);
	/* Serialize list membership without ever nesting grp->lock under uring_lock. */
	mutex_unlock(&ctx->uring_lock);
	mutex_lock(&io_spare_mutex);
	if (old_grp)
		io_spare_grp_put(old_grp);
	if (!q->rescue_buf || !q->run) {
		ret = -ENOMEM;
		goto out;
	}
	grp = reg.attach_fd == -1 ? io_spare_create(ctx, &reg) :
				   io_spare_attach(reg.attach_fd);
	if (IS_ERR(grp)) {
		ret = PTR_ERR(grp);
		goto out;
	}
	/* Before executors can find the ring: claims use the ports. */
	ret = io_spare_ports_init(ctx, q, grp);
	if (ret) {
		/* A group made here has no other user: stop its executors too. */
		if (reg.attach_fd == -1)
			io_spare_stop(grp);
		io_spare_grp_put(grp);
		goto out;
	}
	spin_lock(&grp->lock);
	list_add_tail(&q->grp_node, &grp->ctx_list);
	spin_unlock(&grp->lock);
	mutex_lock(&ctx->uring_lock);
	spin_lock(&q->lock);
	q->grp = grp;
	q->dead = false;
	q->pull_ok = reg.features & IORING_SPARE_FEAT_PULL;
	q->gen = (q->gen + 1) & 0xffffff;
	atomic64_set(&q->lease, IO_W(0, q->gen, ctx->cached_sq_head));
	atomic_andnot(IORING_SQ_LEASED, &ctx->rings->sq_flags);
	atomic_set(&q->nr_rsv_chunks, 0);
	q->zp_snap.valid = false;
	io_spare_dbg_init_head(q);
	q->attached = true;
	spin_unlock(&q->lock);
	WRITE_ONCE(q->offer, q->pull_ok && q->mode != IORING_SPARE_MODE_NEVER);
	if (q->offer)
		atomic_inc(&grp->nr_offers);
	mutex_unlock(&ctx->uring_lock);
	trace_io_uring_spare_register(ctx, grp, reg.attach_fd != -1, grp->nr_exec,
				      q->n_max, q->u_pending, q->u_chunks, q->mode);
	ret = 0;
out:
	mutex_unlock(&io_spare_mutex);
	mutex_lock(&ctx->uring_lock);
	return ret;
}

/* Detached handoffs have issued nothing and have no queued chunk tokens. */
static void io_spare_handoff_drain(struct io_ring_ctx *ctx)
{
	struct io_spare_q *q = ctx->spare;
	struct io_chunk *chunk;
	unsigned int i, nr, ncancel, drain;
	u64 valid, cancelled;

	lockdep_assert_held(&ctx->uring_lock);
	for (;;) {
		valid = 0;
		cancelled = 0;
		nr = 0;
		ncancel = 0;
		spin_lock(&q->lock);
		chunk = io_spare_handoff_pop(q);
		if (chunk) {
			atomic_set(&chunk->handoff_to->offered, 0);
			chunk->handoff_to = NULL;
			for (i = 0; i < chunk->n; i++) {
				int old = io_spare_take(&chunk->slot[i], IO_SPARE_OWNER);

				if (old != IO_SPARE_FREE && old != IO_SPARE_CANCEL)
					continue;
				valid |= BIT_ULL(i);
				if (old == IO_SPARE_CANCEL) {
					cancelled |= BIT_ULL(i);
					ncancel++;
				}
				nr++;
				io_spare_slot_taken_locked(chunk);
			}
		}
		spin_unlock(&q->lock);
		if (!chunk)
			break;
		q->rescue_tail += nr;
		atomic64_add(nr, &q->rescued);
		trace_io_uring_spare_rescue(ctx, chunk->seq, nr, ncancel,
					    IO_SPARE_RESCUE_TAIL);
		drain = io_spare_copies_start(ctx, nr);
		while (valid) {
			i = __ffs64(valid);
			valid &= valid - 1;
			io_spare_submit_copy(ctx, &chunk->sqes[i],
					     io_chunk_slot_file(chunk, i),
					     cancelled & BIT_ULL(i));
		}
		io_spare_copies_end(ctx, drain);
		io_chunk_retire(chunk, IO_SPARE_RETIRE_RESCUE);
		io_submit_flush_completions(ctx);
	}
}

/* uring_lock held on entry/return; no group lock may nest with it. */
static void io_spare_detach(struct io_ring_ctx *ctx)
{
	struct io_spare_q *q = ctx->spare;
	struct io_spare_grp *grp = q->grp;
	bool last;

	if (q->offer) {
		WRITE_ONCE(q->offer, false);
		atomic_dec(&grp->nr_offers);
	}
	spin_lock(&q->lock);
	/* Detached FIFO work remains owner-rescuable, but is no longer group work. */
	atomic_sub(q->nr_pending, &grp->nr_pending);
	q->attached = false;
	q->dead = true;
	spin_unlock(&q->lock);
	io_spare_handoff_drain(ctx);
#ifdef CONFIG_IO_URING_SPARE_DEBUG
	wake_up_all(&q->dbg_wait);
#endif
	mutex_unlock(&ctx->uring_lock);
	mutex_lock(&io_spare_mutex);
	spin_lock(&grp->lock);
	list_del_init(&q->grp_node);
	if (grp->hint == q)
		grp->hint = NULL;
	last = list_empty(&grp->ctx_list);
	spin_unlock(&grp->lock);
	trace_io_uring_spare_detach(ctx, grp, last);
	if (last)
		io_spare_stop(grp);
	mutex_unlock(&io_spare_mutex);
	mutex_lock(&ctx->uring_lock);
}

bool io_spare_frozen(struct io_ring_ctx *ctx)
{
	struct io_spare_q *q = READ_ONCE(ctx->spare);

	return q && (READ_ONCE(q->attached) || READ_ONCE(q->nr_chunks) ||
		     atomic_read(&q->nr_publishers) ||
		     io_spare_ports_busy(q, false));
}

static bool io_spare_task_stalled(struct io_spare_exec *exec)
{
	struct task_struct *task;
	bool stalled;

	/* exec->task is cleared before the executor exits; task_structs are RCU-freed. */
	rcu_read_lock();
	task = READ_ONCE(exec->task);
	stalled = !task || !task_curr(task) || test_bit(IO_SPARE_STOP, &exec->state);
	rcu_read_unlock();
	return stalled;
}

/*
 * Some executor holds a claimed chunk (busy) but is off CPU: its unissued
 * tail and its stored but unkicked CQEs wait for it to run again. Owner, no lock.
 */
static bool io_spare_any_stalled(struct io_spare_q *q)
{
	struct io_spare_grp *grp = q->grp;
	unsigned int i;

	if (!grp)
		return false;
	for (i = 0; i < grp->nr_exec; i++) {
		struct io_spare_exec *exec = &grp->exec[i];

		if (READ_ONCE(exec->busy) && io_spare_task_stalled(exec))
			return true;
	}
	return false;
}

/*
 * Some executor serves q on a CPU: it claims q's unclaimed chunks next, as it
 * neither sleeps while group work is pending nor leaves q without
 * io_exec_serve(). Owner, no lock; serving is only compared, never followed.
 */
static bool io_spare_served(struct io_spare_q *q)
{
	struct io_spare_grp *grp = q->grp;
	unsigned int i;

	if (!grp || !READ_ONCE(q->attached))
		return false;
	for (i = 0; i < grp->nr_exec; i++) {
		struct io_spare_exec *exec = &grp->exec[i];

		if (READ_ONCE(exec->serving) == q && !io_spare_task_stalled(exec))
			return true;
	}
	return false;
}

static bool io_spare_pull_work(struct io_spare_q *q, u64 w)
{
	struct io_chunk *chunk;
	bool work = false;
	unsigned int i;

	if (IO_W_CURSOR(w) != smp_load_acquire(&q->ctx->rings->sq.tail) ||
	    atomic_read(&q->nr_rsv_chunks) || !list_empty(&q->rescue))
		return true;
	if (!atomic_read(&q->nr_publishers))
		return false;
	/*
	 * BEFORE_HEAD can stop after the last RESERVED decrement but before
	 * copy_done/rescue publication. Those FREEs still need owner service.
	 */
	spin_lock(&q->lock);
	/* Publication may have completed between the lockless hints and this lock. */
	if (!list_empty(&q->rescue)) {
		work = true;
		goto out;
	}
	list_for_each_entry(chunk, &q->pull, list) {
		if (chunk->copy_done || READ_ONCE(chunk->state) != IO_CHUNK_CLAIMED)
			continue;
		for (i = 0; i < chunk->n; i++) {
			u8 state = smp_load_acquire(&chunk->slot[i]);

			if (state == IO_SPARE_FREE || state == IO_SPARE_CANCEL) {
				work = true;
				goto out;
			}
		}
	}
out:
	spin_unlock(&q->lock);
	return work;
}

/* lease holder identity is stable in the whole-word W read, not task state. */
static bool io_spare_pull_wait(struct io_spare_q *q)
{
	struct io_spare_grp *grp = q->grp;
	u64 w = atomic64_read(&q->lease);
	unsigned int holder = IO_W_HOLDER(w);

	if (!io_spare_pull_work(q, w))
		return false;
	return test_bit(IO_RTOK_TAKEOVER, &q->rbits) || !holder || !grp ||
	       holder > grp->nr_exec || !io_spare_exec_running(&grp->exec[holder - 1]);
}

bool io_spare_wait_rescue_timer(struct io_ring_ctx *ctx)
{
	struct io_spare_q *q = ctx->spare;
	u64 w;
	unsigned int i;

	if (!q || !q->pull_ok)
		return false;
	w = atomic64_read(&q->lease);
	/*
	 * Any pending work, not only work under the holder seen here: between
	 * this check and the last one before schedule() one lessee may release
	 * (its token push still pending) and another acquire, and the last
	 * check then sees a running lessee. Only the timer bounds that sleep.
	 */
	if (io_spare_pull_work(q, w) || q->zp_snap.valid)
		return true;
	for (i = 0; i < READ_ONCE(q->nr_ports); i++) {
		struct io_spare_port *port = READ_ONCE(q->ports[i]);

		if (port && READ_ONCE(port->active) && !llist_empty(&port->done))
			return true;
	}
	return false;
}

u32 io_spare_rescue_ns(struct io_ring_ctx *ctx)
{
	return ctx->spare->rescue_ns;
}

void io_spare_timer_event(struct io_ring_ctx *ctx, bool fired)
{
	struct io_spare_q *q = ctx->spare;
	u32 cursor = IO_W_CURSOR(atomic64_read(&q->lease));

	if (fired) {
		atomic64_inc(&q->timer_fires);
		q->zp_snap.valid = false;
	}
	trace_io_uring_spare_rtimer(ctx, !fired, fired,
				    smp_load_acquire(&ctx->rings->sq.tail) - cursor,
				    atomic_read(&q->nr_rsv_chunks));
}

void io_spare_wait_last_check(struct io_ring_ctx *ctx)
{
	struct io_spare_q *q = ctx->spare;

	/* About to schedule(): until io_spare_wait_woke() the owner is idle. */
	q->t_sleep = ktime_get_ns();
	if (io_spare_pull(ctx))
		io_spare_dbg(q, IORING_SPARE_DBG_OWNER_AFTER_LAST_CHECK, 0);
}

/* Owner, right after the wait's schedule() returned (wait.c). */
void io_spare_wait_woke(struct io_ring_ctx *ctx)
{
	struct io_spare_q *q = ctx->spare;

	if (q->t_sleep) {
		q->blocked_acc += ktime_get_ns() - q->t_sleep;
		q->t_sleep = 0;
	}
}

/* No submission batch is active in this owner wait frame (wait.c:219,279). */
static bool io_spare_wait_takeover(struct io_ring_ctx *ctx)
{
	struct io_spare_q *q = ctx->spare;
	u32 head, rsv;
	int live;
	bool progress;

	mutex_lock(&ctx->uring_lock);
	head = READ_ONCE(ctx->rings->sq.head);
	live = atomic_read(&q->live);
	rsv = atomic_read(&q->nr_rsv_chunks);
	clear_bit(IO_RTOK_TAKEOVER, &q->rbits);
	/* sq_entries is not a backlog the application handed us: keep the offer. */
	q->owner_wait = true;
	io_submit_sqes(ctx, ctx->sq_entries);
	q->owner_wait = false;
	progress = head != READ_ONCE(ctx->rings->sq.head) ||
		   live != atomic_read(&q->live) || rsv != atomic_read(&q->nr_rsv_chunks);
	progress |= io_spare_rescue_locked(ctx, true,
					   !(q->flags & IORING_SPARE_F_NO_SPLIT));
	progress |= io_spare_harvest_locked(q);
	progress |= io_spare_ports_owner(q);
	io_submit_flush_completions(ctx);
	if (!progress && io_spare_pull_work(q, atomic64_read(&q->lease)))
		io_spare_zero_progress(q);
	else if (progress && !io_spare_zp_same(q))
		q->zp_snap.valid = false;
	mutex_unlock(&ctx->uring_lock);
	return progress;
}

/*
 * q->lock held: the unclaimed chunk to take back whole, or NULL to leave them.
 * An owner about to wait leaves them to an executor serving q: taking one
 * whole moments before that executor reached it left the executor idle and
 * the owner issuing alone (half of all delegated SQEs, issued serially).
 * Sharing (split) still takes the newest while another stays queued, so the
 * two work from opposite ends. Otherwise the oldest goes first.
 */
static struct io_chunk *io_spare_rescue_pick(struct io_spare_q *q, bool wait,
					      bool split)
{
	if (!wait || !io_spare_served(q))
		return list_first_entry(&q->pending, struct io_chunk, list);
	q->rescue_left++;
	if (split && q->nr_pending >= 2)
		return list_last_entry(&q->pending, struct io_chunk, list);
	return NULL;
}

/*
 * Owner in io_cqring_wait(), after storing cq_wait_nr and its sleeping task
 * state (full barrier): chunks left to a serving executor that has since
 * stopped serving q (moved on, off CPU, exiting) must be taken back before
 * sleeping. Dekker pair with io_exec_serve().
 */
bool io_spare_wait_unserved(struct io_ring_ctx *ctx)
{
	struct io_spare_q *q = ctx->spare;

	if (!q || current != ctx->submitter_task)
		return false;
	if (q->pull_ok && io_spare_pull_wait(q) && !io_spare_zp_same(q))
		return true;
	/* The rescue at the loop head finishes them (io_spare_ports_owner()). */
	if (q->flags & IORING_SPARE_F_EXEC_FINISH) {
		/*
		 * Served ports keep their completions. Journal entries stored but
		 * not flushed bring us back to harvest them: Dekker pair with
		 * io_exec_port_reap()'s produced store -> cq_wait_nr load.
		 */
		if (io_spare_ports_hint(q))
			return true;
	} else if (io_spare_ports_queued(q)) {
		return true;
	}
	return READ_ONCE(q->nr_pending) && !io_spare_served(q);
}

/*
 * Lockless hint only: never follow a node without q->lock. Unclaimed chunks
 * are always taken back; claimed ones from a stalled executor, or with split
 * (owner wait) from a running one. Stale q->rescue entries make it a false
 * positive once; the rescue scan prunes them.
 */
static bool io_spare_rescue_hint(struct io_spare_q *q, bool split)
{
	if (READ_ONCE(q->nr_pending))
		return true;
	if (!READ_ONCE(q->nr_chunks))
		return false;
	return split ? !list_empty(&q->rescue) : io_spare_any_stalled(q);
}

/*
 * A claimed chunk is only taken back from an executor that is not on a CPU
 * (preempted, blocked or exiting). A running executor is making progress on
 * it, and taking its tail would just turn every owner wait into stealing.
 */
static bool io_spare_exec_stalled(struct io_chunk *chunk)
{
	return io_spare_task_stalled(chunk->exec);
}

/*
 * Post the CQEs a stalled executor stored but has not kicked yet: with it off
 * CPU they would wait for it to run again. Only the owner writes ->posted, and
 * a chunk with buffered CQEs (produced > 0) is retired only by the owner's fin
 * (io_exec_retire() requires produced == 0), both under uring_lock (held), so
 * the collected chunks stay valid after q->lock is dropped; posting is done
 * outside q->lock.
 */
static bool io_spare_harvest_locked(struct io_spare_q *q)
{
	struct io_chunk *chunk, *found[8];
	unsigned int nr = 0, i;

	lockdep_assert_held(&q->ctx->uring_lock);
	spin_lock(&q->lock);
	list_for_each_entry(chunk, &q->inflight, list) {
		if (READ_ONCE(chunk->produced) == chunk->posted ||
		    !io_spare_exec_stalled(chunk))
			continue;
		found[nr++] = chunk;
		if (nr == ARRAY_SIZE(found))
			break;
	}
	if (nr < ARRAY_SIZE(found))
		list_for_each_entry(chunk, &q->pull, list) {
			if (READ_ONCE(chunk->state) != IO_CHUNK_CLAIMED ||
			    !chunk->copy_done ||
			    READ_ONCE(chunk->produced) == chunk->posted ||
			    !io_spare_exec_stalled(chunk))
				continue;
			found[nr++] = chunk;
			if (nr == ARRAY_SIZE(found))
				break;
		}
	spin_unlock(&q->lock);
	for (i = 0; i < nr; i++)
		io_chunk_post(found[i], IO_SPARE_POST_HARVEST, false);
	return nr;
}

/*
 * Owner about to sleep, U slots of a running executor's chunk unissued: how
 * many to take so both sides finish together. The executor needs e per slot,
 * the owner o per slot plus H to start (a chunk's worth of handoff); with
 * x taken, (U - x) * e = x * o + H gives x = (e * U - H) / (e + o). Half,
 * when nothing is known yet; none, when the executor would finish first.
 */
static unsigned int io_spare_split_quota(struct io_spare_q *q, unsigned int U)
{
	u64 e = READ_ONCE(q->cost_exec), o = q->cost_inline, h = q->cost_chunk;

	if (!U)
		return 0;
	if (!e || !o)
		return max(U / 2, 1U);
	if (e * U <= h)
		return 0;
	return clamp_t(u64, div64_u64(e * U - h, e + o), 1, U);
}

/*
 * Returns true if any work was taken back, so the caller may retry. wait: the
 * owner is about to sleep, so it leaves unclaimed chunks to a serving
 * executor. split: it may also share a running executor's work.
 */
static bool io_spare_rescue_locked(struct io_ring_ctx *ctx, bool wait,
				   bool split)
{
	struct io_spare_q *q = ctx->spare;
	struct io_spare_rescue_entry *entries = q->rescue_buf;
	struct io_chunk *chunk, *next, *pending = NULL;
	u64 valid = 0, cancelled = 0, seq = 0;
	unsigned int nr = 0, ncancel = 0, quota, i, drain;
	u8 kind = IO_SPARE_RESCUE_TAIL;

	lockdep_assert_held(&ctx->uring_lock);
	if (!io_spare_rescue_hint(q, split))
		return false;
	spin_lock(&q->lock);
	if (!list_empty(&q->pending))
		pending = io_spare_rescue_pick(q, wait, split);
	if (pending) {
		list_del_init(&pending->list);
		q->nr_pending--;
		if (q->attached)
			atomic_dec(&q->grp->nr_pending);
		for (i = 0; i < pending->n; i++) {
			int old = io_spare_take(&pending->slot[i], IO_SPARE_OWNER);

			if (old != IO_SPARE_FREE && old != IO_SPARE_CANCEL)
				continue;
			valid |= BIT_ULL(i);
			if (old == IO_SPARE_CANCEL)
				cancelled |= BIT_ULL(i);
			nr++;
		}
	} else {
		/*
		 * Bounded: claimed chunks are at most u_chunks per ring. Newest
		 * first: the executor works through its chunks in claim order, so
		 * the newest is the one it reaches last and has the most left.
		 */
		list_for_each_entry_safe_reverse(chunk, next, &q->rescue, rescue) {
			/* An executor may lag between its last decrement and list removal. */
			if (!atomic_read(&chunk->unvisited)) {
				list_del_init(&chunk->rescue);
				continue;
			}
			kind = IO_SPARE_RESCUE_TAIL;
			quota = q->n_max;
			if (!io_spare_exec_stalled(chunk)) {
				/*
				 * Rather than sleep on a running executor's progress, take
				 * the back half of its unissued tail (docs/12 5.3); the two
				 * meet in the middle. Not once its issues went async: the
				 * wait is then for the device, and a share would only move
				 * issue CPU back to the owner.
				 */
				if (!split || READ_ONCE(chunk->async))
					continue;
				kind = IO_SPARE_RESCUE_SPLIT;
				quota = io_spare_split_quota(q, atomic_read(&chunk->unvisited));
				if (!quota)
					continue;
			}
			for (i = chunk->n; i && nr < quota; ) {
				int old = io_spare_take(&chunk->slot[--i], IO_SPARE_OWNER);

				if (old == IO_SPARE_EXEC) {
					/* Its prefix is executor-owned, even if the count lags CAS. */
					list_del_init(&chunk->rescue);
					break;
				}
				if (old != IO_SPARE_FREE && old != IO_SPARE_CANCEL)
					continue;
				entries[nr].sqe = chunk->sqes[i];
				entries[nr].file = io_chunk_slot_file(chunk, i);
				entries[nr++].cancel = old == IO_SPARE_CANCEL;
				ncancel += old == IO_SPARE_CANCEL;
				io_spare_slot_taken_locked(chunk);
			}
			if (nr) {
				seq = chunk->seq;
				break;
			}
		}
	}
	spin_unlock(&q->lock);
	if (pending) {
		q->rescue_chunks++;
		trace_io_uring_spare_rescue(ctx, pending->seq, nr,
					    hweight64(cancelled),
					    IO_SPARE_RESCUE_PENDING);
	} else if (nr) {
		q->rescue_tail += nr;
		if (kind == IO_SPARE_RESCUE_SPLIT)
			q->rescue_split += nr;
		trace_io_uring_spare_rescue(ctx, seq, nr, ncancel, kind);
	}
	if (!pending && !nr)
		return false;
	drain = io_spare_copies_start(ctx, nr);
	if (pending) {
		/* The unlinked chunk is exclusively ours; no scratch allocation needed. */
		while (valid) {
			i = __ffs64(valid);
			valid &= valid - 1;
			io_spare_submit_copy(ctx, &pending->sqes[i],
					     io_chunk_slot_file(pending, i),
					     cancelled & BIT_ULL(i));
		}
	} else {
		for (i = 0; i < nr; i++)
			io_spare_submit_copy(ctx, &entries[i].sqe, entries[i].file,
					     entries[i].cancel);
	}
	io_spare_copies_end(ctx, drain);
	atomic64_add(nr, &q->rescued);
	if (pending)
		io_chunk_retire(pending, IO_SPARE_RETIRE_RESCUE);
	io_submit_flush_completions(ctx);
	return true;
}

/* Completions queued to a port its executor does not poll now. */
static bool io_spare_port_stranded(struct io_spare_port *port)
{
	/*
	 * Only the owner's wait path asks. An owner about to wait finishes what
	 * it waits for (io_spare_rw_done()'s rule), even from a running
	 * executor's port: leaving it there would need the completion to have
	 * seen our cq_wait_nr, which the Dekker pair guarantees only if we look.
	 */
	if (llist_empty(&port->done))
		return false;
	/*
	 * EXEC_FINISH: the running executor reaps them after its current slot
	 * (io_exec_chunk()) or between chunks (io_exec_ports_reap()), and its
	 * flush wakes us; only a port it stopped polling is stranded.
	 */
	if ((port->q->flags & IORING_SPARE_F_EXEC_FINISH) &&
	    READ_ONCE(port->active) && io_spare_exec_running(port->exec))
		return false;
	return true;
}

/* Owner, after cq_wait_nr and its sleeping state are stored (full barrier). */
static bool io_spare_ports_queued(struct io_spare_q *q)
{
	unsigned int i;

	for (i = 0; i < READ_ONCE(q->nr_ports); i++) {
		struct io_spare_port *port = READ_ONCE(q->ports[i]);

		if (port && !llist_empty(&port->done))
			return true;
	}
	return false;
}

/* Lockless hint: journal entries to post, or completions stranded at a port. */
static bool io_spare_ports_hint(struct io_spare_q *q)
{
	unsigned int i;

	for (i = 0; i < READ_ONCE(q->nr_ports); i++) {
		struct io_spare_port *port = READ_ONCE(q->ports[i]);

		if (port && (READ_ONCE(port->produced) != port->posted ||
			     io_spare_port_stranded(port)))
			return true;
	}
	return false;
}

/*
 * Owner wait, uring_lock held: post what executors stored, without waiting
 * for their kicks, and finish completions stranded at a port. Returns true
 * on progress.
 */
static bool io_spare_ports_owner(struct io_spare_q *q)
{
	bool progress = false;
	unsigned int i;

	for (i = 0; i < READ_ONCE(q->nr_ports); i++) {
		struct io_spare_port *port = READ_ONCE(q->ports[i]);
		struct llist_node *node;
		unsigned int nr = 0;

		if (!port)
			continue;
		if (io_spare_port_post(port, IO_SPARE_POST_HARVEST, UINT_MAX))
			progress = true;
		if (!io_spare_port_stranded(port))
			continue;
		node = llist_reverse_order(llist_del_all(&port->done));
		while (node) {
			struct io_kiocb *req = container_of(node, struct io_kiocb,
							    io_task_work.node);

			node = node->next;
			io_spare_owner_finish(req, false);
			nr++;
		}
		if (nr) {
			atomic64_add(nr, &q->async_steal);
			progress = true;
		}
	}
	return progress;
}

bool io_spare_rescue(struct io_ring_ctx *ctx)
{
	struct io_spare_q *q = ctx->spare;
	bool progress, split;

	if (!q || current != ctx->submitter_task)
		return false;
	if (q->pull_ok && io_spare_pull_wait(q) && !io_spare_zp_same(q))
		return io_spare_wait_takeover(ctx);
	split = !(q->flags & IORING_SPARE_F_NO_SPLIT);
	if (!io_spare_rescue_hint(q, split) && !io_spare_ports_hint(q))
		return false;
	mutex_lock(&ctx->uring_lock);
	progress = io_spare_rescue_locked(ctx, true, split);
	/* Only the wait path harvests: the owner is about to sleep on these CQEs. */
	if (io_spare_any_stalled(q))
		progress |= io_spare_harvest_locked(q);
	progress |= io_spare_ports_owner(q);
	/* Commit harvested and port CQEs now; io_should_wake() reads the CQ tail. */
	io_submit_flush_completions(ctx);
	if (progress)
		q->zp_snap.valid = false;
	mutex_unlock(&ctx->uring_lock);
	return progress;
}

static bool io_spare_cancel_match(struct io_spare_q *q,
				   const struct io_uring_sqe *sqe, struct file *file,
				   struct io_cancel_data *cd)
{
	bool user_data = cd->flags & IORING_ASYNC_CANCEL_USERDATA;
	struct io_rsrc_node *node;
	bool match;

	if (cd->flags & IORING_ASYNC_CANCEL_ANY)
		return true;
	if (!(cd->flags & (IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_OP)))
		user_data = true;
	if (user_data && sqe->user_data != cd->data)
		return false;
	if ((cd->flags & IORING_ASYNC_CANCEL_OP) && sqe->opcode != cd->opcode)
		return false;
	if (!(cd->flags & IORING_ASYNC_CANCEL_FD))
		return true;
	if (IS_ERR(file))
		return false;
	if (sqe->flags & IOSQE_FIXED_FILE) {
		node = io_rsrc_node_lookup(&q->ctx->file_table.data, sqe->fd);
		return node && io_slot_file(node) == cd->file;
	}
	/* The file the request would use: resolved at delegation, not by fd now. */
	if (file)
		return file == cd->file;
	file = fget(sqe->fd);
	match = file && file == cd->file;
	if (file)
		fput(file);
	return match;
}

int io_spare_try_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd)
{
	struct io_spare_q *q = ctx->spare;
	struct io_chunk *chunk;
	struct list_head *head;
	unsigned int i, pass;
	int ret = -ENOENT;

	if (!q || cd->ctx != ctx)
		return -ENOENT;
	/*
	 * Pull chunks too (spec 11.3): a FREE pull slot was copied before its
	 * RESERVED -> FREE CAS (io_exec_pull()), so the acquire below sees its
	 * SQE. RESERVED slots have no copy here yet; sync cancel of those
	 * (uring_lock, SQ copy, spec 11.3) is S5.
	 */
	spin_lock(&q->lock);
	for (pass = 0; pass < 3; pass++) {
		head = pass == 2 ? &q->pull : pass ? &q->inflight : &q->pending;
		list_for_each_entry(chunk, head, list) {
			for (i = 0; i < chunk->n; i++) {
				if (smp_load_acquire(&chunk->slot[i]) != IO_SPARE_FREE ||
				    !io_spare_cancel_match(q, &chunk->sqes[i],
							   io_chunk_slot_file(chunk, i), cd))
					continue;
				if (cmpxchg(&chunk->slot[i], IO_SPARE_FREE,
					    IO_SPARE_CANCEL) != IO_SPARE_FREE)
					continue;
				/* Irreversible marking also makes ALL/ANY sequence-safe. */
				trace_io_uring_spare_cancel(ctx, chunk->seq, i,
							    chunk->sqes[i].user_data);
				ret = 0;
				goto unlock;
			}
		}
	}
unlock:
	spin_unlock(&q->lock);
	return ret;
}

bool io_spare_cancel_pending(struct io_ring_ctx *ctx, bool cancel_all)
{
	struct io_spare_q *q = ctx->spare;
	struct io_chunk *chunk, *next;
	unsigned int i;
	LIST_HEAD(cancel);
	bool progress;

	lockdep_assert_held(&ctx->uring_lock);
	if (!q || (!cancel_all && !percpu_ref_is_dying(&ctx->refs)))
		return false;
	progress = q->pull_ok &&
		    io_spare_takeover_locked(ctx, q, IO_SPARE_TAKE_CLOSE);
	spin_lock(&q->lock);
	progress |= !list_empty(&q->pending);
	list_splice_init(&q->pending, &cancel);
	if (q->attached)
		atomic_sub(q->nr_pending, &q->grp->nr_pending);
	q->nr_pending = 0;
	spin_unlock(&q->lock);
	list_for_each_entry_safe(chunk, next, &cancel, list) {
		for (i = 0; i < chunk->n; i++) {
			int old = io_spare_take(&chunk->slot[i], IO_SPARE_OWNER);

			if (old == IO_SPARE_FREE || old == IO_SPARE_CANCEL) {
				io_add_aux_cqe(ctx, chunk->sqes[i].user_data, -ECANCELED, 0);
				atomic64_inc(&q->cancelled);
				io_spare_inflight_done(q, 1);
			}
		}
		io_chunk_retire(chunk, IO_SPARE_RETIRE_CANCEL);
	}
	/* H2's caller does not otherwise flush the tokens we just completed. */
	if (progress)
		io_submit_flush_completions(ctx);
	return progress;
}

int io_unregister_spare(struct io_ring_ctx *ctx)
{
	struct io_spare_q *q = ctx->spare;

	lockdep_assert_held(&ctx->uring_lock);
	if (!q || !q->attached)
		return -EINVAL;
	io_spare_detach(ctx);
	if (q->pull_ok) {
		io_spare_takeover_locked(ctx, q, IO_SPARE_TAKE_UNREGISTER);
		/* The ring remains alive: pending SQEs use the ordinary submit path. */
		io_submit_sqes(ctx, ctx->sq_entries);
	}
	/*
	 * No executor claims a detached ring's chunks, so issue the unclaimed
	 * ones now, as the inline path would have: an owner that only polls
	 * (GETEVENTS with min_complete 0) reaches neither the submit nor the
	 * wait-path rescue. Claimed chunks come back by handback and fin.
	 */
	while (READ_ONCE(q->nr_pending) && io_spare_rescue_locked(ctx, false, false))
		;
	return 0;
}

void io_spare_ctx_exit(struct io_ring_ctx *ctx)
{
	lockdep_assert_held(&ctx->uring_lock);
	if (!ctx->spare)
		return;
	if (ctx->spare->attached)
		io_spare_detach(ctx);
	io_spare_cancel_pending(ctx, true);
	io_submit_flush_completions(ctx);
}

void io_spare_ctx_quiesce(struct io_ring_ctx *ctx)
{
	struct io_spare_q *q = ctx->spare;
	struct io_chunk *chunk;

	if (!q)
		return;
	/* All producer refs have drained (io_ring_exit_work(): ref_comp wait). */
	irq_work_sync(&q->notify_work);
	/* A late fin may be queued without a rescue token (tw.c:261-288). */
	io_cancel_local_task_work(ctx);
	mutex_lock(&ctx->uring_lock);
	if (q->pull_ok) {
		spin_lock(&q->lock);
		list_for_each_entry(chunk, &q->pull, list)
			WARN_ON_ONCE(!chunk->fin_seen);
		spin_unlock(&q->lock);
		io_spare_takeover_locked(ctx, q, IO_SPARE_TAKE_CLOSE);
	}
	io_submit_flush_completions(ctx);
	mutex_unlock(&ctx->uring_lock);
}

void io_spare_ctx_free(struct io_ring_ctx *ctx)
{
	struct io_spare_q *q = ctx->spare;
	unsigned int i;

	if (!q)
		return;
	trace_io_uring_spare_free(ctx);
	/* Tokens, requests, held ports and selection snapshots hold ctx refs until done. */
	if (WARN_ON_ONCE(q->attached || q->nr_chunks || atomic_read(&q->nr_publishers) ||
			 q->nr_handoff || !list_empty(&q->handoff) ||
			 !list_empty(&q->pull) ||
			 io_spare_ports_busy(q, true)))
		return;
	if (q->grp)
		io_spare_grp_put(q->grp);
	io_spare_free_chunks(q);
	if (q->rtoken)
		kmem_cache_free(req_cachep, q->rtoken);
	kfree(q->rescue_buf);
	kfree(q->run);
	/* A journal token left queued at exit is not run again (io_ring_exit_work()). */
	for (i = 0; i < q->nr_ports; i++)
		if (q->ports[i])
			io_spare_port_free(q->ports[i]);
	WRITE_ONCE(ctx->spare, NULL);
	kfree(q);
}

void io_spare_show_fdinfo(struct io_ring_ctx *ctx, struct seq_file *m)
{
	struct io_spare_q *q = ctx->spare;
	struct io_spare_grp *grp;
	unsigned int i;
	u64 w;
	const char *pull;
	int out = 0;

	if (!q)
		return;
	grp = q->grp;
	if (q->pull_ok)
		pull = "on";
	else if (q->flags & IORING_SPARE_F_NO_PULL)
		pull = "off(NO_PULL)";
	else if (!(ctx->flags & IORING_SETUP_NO_SQARRAY))
		pull = "off(NO_SQARRAY required)";
	else
		pull = "off(TASKRUN_FLAG required)";
	w = atomic64_read(&q->lease);
	seq_printf(m, "Spare:\tmode=%u attached=%u nr_exec=%u nr_awake=%d n_max=%u n_min=%u flags=%#x\n",
		   q->mode, q->attached, grp ? grp->nr_exec : 0,
		   grp ? atomic_read(&grp->nr_awake) : 0, q->n_max, q->n_min,
		   q->flags);
	seq_printf(m, "SparePull:\tpull=%s offer=%u rescue_ns=%u publishers=%d rsv_chunks=%d lease: holder=%u gen=%u cursor=%u\n",
		   pull, READ_ONCE(q->offer), q->rescue_ns,
		   atomic_read(&q->nr_publishers), atomic_read(&q->nr_rsv_chunks),
		   IO_W_HOLDER(w), IO_W_GEN(w), IO_W_CURSOR(w));
	seq_printf(m, "SpareLease:\tlease_acquires=%lld releases=%lld handbacks=%lld takeovers=%lld withdraw_owner=%lld withdraw_exec=%lld abort_publish=%lld token_push=%lld timer_fires=%lld zero_progress=%lld reserved_taken=%lld\n",
		   atomic64_read(&q->lease_acquires), atomic64_read(&q->releases),
		   atomic64_read(&q->handbacks), atomic64_read(&q->takeovers),
		   atomic64_read(&q->withdraw_owner), atomic64_read(&q->withdraw_exec),
		   atomic64_read(&q->abort_publish), atomic64_read(&q->token_push),
		   atomic64_read(&q->timer_fires), atomic64_read(&q->zero_progress),
		   atomic64_read(&q->reserved_taken));
	seq_printf(m, "SpareChunks:\tpending=%u outstanding=%u delegated=%lld chunks=%lld\n",
		   READ_ONCE(q->nr_pending), READ_ONCE(q->nr_chunks),
		   atomic64_read(&q->delegated) + (s64)io_spare_ports_sum(q, delegated),
		   atomic64_read(&q->chunks) + (s64)io_spare_ports_sum(q, chunks));
	seq_printf(m, "SpareEvents:\trescued=%lld bounced=%lld cancelled=%lld kicks=%lld wakes=%lld direct=%llu blocked=%lld appended=%llu files=%llu\n",
		   atomic64_read(&q->rescued), atomic64_read(&q->bounced),
		   atomic64_read(&q->cancelled),
		   atomic64_read(&q->kicks) + (s64)io_spare_ports_sum(q, kicks),
		   atomic64_read(&q->wakes), io_spare_ports_sum(q, direct),
		   atomic64_read(&q->blocked), q->appended, q->files);
	seq_printf(m, "SpareLive:\tdelegated_live=%d\n", atomic_read(&q->live));
	seq_printf(m, "SpareCost:\tinline=%u chunk=%u exec=%u threshold=%u owner_busy=%u\n",
		   q->cost_inline, q->cost_chunk, READ_ONCE(q->cost_exec),
		   io_spare_threshold(q), READ_ONCE(q->owner_busy) * 100 / 1024);
	/* Inline reasons count delegate calls; the inline fallback makes one per SQE. */
	seq_printf(m, "SpareSkip:\tstate=%llu budget=%llu ineligible=%llu asleep=%llu pending=%llu nomem=%llu short=%llu\n",
		   q->skip[IO_SPARE_SKIP_STATE], q->skip[IO_SPARE_SKIP_BUDGET],
		   q->skip[IO_SPARE_SKIP_INELIGIBLE], q->skip[IO_SPARE_SKIP_ASLEEP],
		   q->skip[IO_SPARE_SKIP_PENDING], q->skip[IO_SPARE_SKIP_NOMEM],
		   q->skip[IO_SPARE_SKIP_SHORT]);
	seq_printf(m, "SpareExec:\tclaims=%llu rescue_chunks=%llu rescue_tail=%llu rescue_split=%llu handback=%lld deferred=%llu sleeps=%lld empty_wakes=%lld left=%llu handoffs=%llu early=%llu early_kept=%llu\n",
		   io_spare_ports_sum(q, claims), q->rescue_chunks, q->rescue_tail,
		   q->rescue_split, atomic64_read(&q->handback), q->deferred,
		   grp ? atomic64_read(&grp->sleeps) : 0,
		   grp ? atomic64_read(&grp->empty_wakes) : 0, q->rescue_left,
		   io_spare_ports_sum(q, handoffs), io_spare_ports_sum(q, early),
		   io_spare_ports_sum(q, early_kept));
	for (i = 0; i < READ_ONCE(q->nr_ports); i++) {
		struct io_spare_port *port = READ_ONCE(q->ports[i]);

		if (port)
			out += atomic_read(&port->outstanding);
	}
	seq_printf(m, "SpareAsync:\texec=%llu owner=%llu steal=%lld outstanding=%d\n",
		   io_spare_ports_sum(q, async_exec), q->async_owner,
		   atomic64_read(&q->async_steal), out);
	if (grp)
		for (i = 0; i < grp->nr_exec; i++)
			seq_printf(m, "SpareCPU:\texec=%u cpu=%d tier=S6 cost_exec=S6\n",
				   grp->exec[i].exec_id, grp->exec[i].cpu);
#ifdef CONFIG_IO_URING_SPARE_DEBUG
	{
		u32 armed = 0;

		for (i = 1; i <= IORING_SPARE_DBG_EXEC_BEFORE_REAP; i++)
			if (READ_ONCE(q->dbg[i].action))
				armed |= 1U << i;
		seq_printf(m, "SpareDbg:\tarmed=%#x parked=%d hits=", armed,
			   atomic_read(&q->dbg_parked));
		for (i = 1; i <= IORING_SPARE_DBG_EXEC_BEFORE_REAP; i++)
			seq_printf(m, "%s%u:%u", i == 1 ? "" : ",", i,
				   READ_ONCE(q->dbg[i].hits));
		seq_putc(m, '\n');
	}
#endif
}
