// SPDX-License-Identifier: GPL-2.0
/*
 * Contains the core associated with submission side polling of the SQ
 * ring, offloading submissions from the application to a kernel thread.
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/audit.h>
#include <linux/security.h>
#include <linux/cpuset.h>
#include <linux/sched/cputime.h>
#include <linux/sched/stat.h>
#include <linux/io_uring.h>
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/kcov.h>
#include <linux/irq_work.h>
#include <linux/preempt.h>
#include <linux/seq_file.h>
#include <linux/seqlock.h>
#include <uapi/linux/sched/types.h>
#ifdef CONFIG_X86
#include <asm/mwait.h>
#endif

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "tctx.h"
#include "napi.h"
#include "cancel.h"
#include "rw.h"
#include "sqpoll.h"

#define IORING_SQPOLL_CAP_ENTRIES_VALUE 8
#define IORING_TW_CAP_ENTRIES_VALUE	32

static bool ringback_enable;
module_param_named(sqpoll_safe, ringback_enable, bool, 0644);
MODULE_PARM_DESC(sqpoll_safe, "RingBack POLL/OWNER switching for new unshared SQPOLL rings (default: 0)");

static unsigned int ringback_rt = 3;
module_param_named(sqpoll_safe_rt, ringback_rt, uint, 0644);
MODULE_PARM_DESC(sqpoll_safe_rt, "The owner's wait for uring_lock held by the poller: 3 trylock with RETRY and release wakeups (default), 2 mutex wait (priority inheritance only with proxy execution); 0 (NORMAL nice 19) and 1 (FIFO 1) are the remote debt boosts of earlier versions, kept for diagnostics only. v6.5: the idle-class poller is never raised or boosted in the default configuration");

static bool ringback_redirect = true;
module_param_named(sqpoll_safe_redirect, ringback_redirect, bool, 0644);
MODULE_PARM_DESC(sqpoll_safe_redirect, "Redirect poller-homed read/write completions to OWNER (default: 1)");

static unsigned int ringback_hold_us = 200;
module_param_named(sqpoll_safe_hold_us, ringback_hold_us, uint, 0644);
MODULE_PARM_DESC(sqpoll_safe_hold_us, "Uncontended CPU hold time in us before returning to SQPOLL (default: 200)");

static unsigned int ringback_checks = 2;
module_param_named(sqpoll_safe_checks, ringback_checks, uint, 0644);
MODULE_PARM_DESC(sqpoll_safe_checks, "Consecutive uncontended CPU checks (minimum: 2, default: 2)");

static unsigned int ringback_kick_us;
module_param_named(sqpoll_safe_kick_us, ringback_kick_us, uint, 0644);
MODULE_PARM_DESC(sqpoll_safe_kick_us, "OWNER completion kick delay in us (0: immediate, default: 0)");

static unsigned int ringback_owner_max_us = 500;
module_param_named(sqpoll_safe_owner_max_us, ringback_owner_max_us, uint, 0644);
MODULE_PARM_DESC(sqpoll_safe_owner_max_us, "OWNER-mode recheck period doubles while the CPU stays contended, up to this many us (0: fixed period; with sqpoll_safe_idlewake the parked poller sleeps for the sqpoll_safe_owner_safety_us period instead; default: 500)");

static unsigned int ringback_defer = 1;
module_param_named(sqpoll_safe_defer, ringback_defer, uint, 0644);
MODULE_PARM_DESC(sqpoll_safe_defer, "Ring-local deferral of read/write completions through ->work_list as with DEFER_TASKRUN: 1 only the creator's own completions in OWNER mode, rings without eventfd or poll waiters; POLL-mode completions take the upstream SQPOLL task_work path and those a preempted poller leaves are run by the owner's rescue (sqpoll_safe_steal) (default); 2 every eligible read/write completion (not linked, not multishot) in both modes, POLL run by the poller, for rings created while set (v6.4; about 4-6% slower than 1 at very high per-ring rates, see RINGBACK_V6_5_DESIGN.md); 3 as 2 with a lockless CQ; 0 none");

static bool sqpoll_cap_all;
module_param(sqpoll_cap_all, bool, 0644);
MODULE_PARM_DESC(sqpoll_cap_all, "Cap every SQPOLL batch at 8 SQEs for baseline comparison (default: 0)");

static bool ringback_idle = true;
module_param_named(sqpoll_safe_idle, ringback_idle, bool, 0644);
MODULE_PARM_DESC(sqpoll_safe_idle, "Start RingBack SQPOLL threads with SCHED_IDLE (default: 1)");

static bool ringback_idlepoll;
module_param_named(sqpoll_safe_k12, ringback_idlepoll, bool, 0644);
MODULE_PARM_DESC(sqpoll_safe_k12, "Poll an empty ring as SCHED_IDLE only while the poller owes nothing (needs sqpoll_safe_idle=0; default: 0)");

static unsigned int ringback_idlepoll_us = 100;
module_param_named(sqpoll_safe_k12_us, ringback_idlepoll_us, uint, 0644);
MODULE_PARM_DESC(sqpoll_safe_k12_us, "Continuous empty polling in us before entering SCHED_IDLE (default: 100)");

static unsigned int ringback_lease_us;
module_param_named(sqpoll_safe_lease_us, ringback_lease_us, uint, 0644);
MODULE_PARM_DESC(sqpoll_safe_lease_us, "Resume polling when OWNER mode makes no SQ or redirect progress for this long (0: never, default: 0)");

static bool ringback_ghostfree = true;
module_param_named(sqpoll_safe_ghostfree, ringback_ghostfree, bool, 0644);
MODULE_PARM_DESC(sqpoll_safe_ghostfree, "The contention check ignores fair tasks queued only for delayed dequeue (default: 1)");

static bool ringback_idlepoll_inflight;
module_param_named(sqpoll_safe_k12_inflight, ringback_idlepoll_inflight, bool,
		   0644);
MODULE_PARM_DESC(sqpoll_safe_k12_inflight, "Idle-class empty polling also while the poller has requests in flight, relying on OWNER redirect after a preemption (experimental; default: 0)");

static unsigned int ringback_slice_us;
module_param_named(sqpoll_safe_slice_us, ringback_slice_us, uint, 0644);
MODULE_PARM_DESC(sqpoll_safe_slice_us, "EEVDF custom slice in us for a NORMAL/BATCH RingBack poller, set at start with its nice kept, so that wakeups with a shorter slice preempt it (0: default slice, default: 0)");

static bool ringback_dual;
module_param_named(sqpoll_safe_dual, ringback_dual, bool, 0644);
MODULE_PARM_DESC(sqpoll_safe_dual, "Mode-free handoff (dual mode): OWNER mode lasts exactly while the poller is preempted (it ends on the poller's next loop, without hold time, backoff or voluntary switches); a sleeping poller keeps the upstream wake-up path; pair with sqpoll_safe_idle=1 (default: 0)");

static bool ringback_mwait = true;
module_param_named(sqpoll_safe_mwait, ringback_mwait, bool, 0644);
MODULE_PARM_DESC(sqpoll_safe_mwait, "Wait for SQ tail stores with MONITOR/MWAIT in C1 instead of spinning on an empty single ring; x86 only, otherwise spins (default: 1)");

static unsigned int ringback_a2l_us;
module_param_named(sqpoll_safe_a2l_us, ringback_a2l_us, uint, 0644);
MODULE_PARM_DESC(sqpoll_safe_a2l_us, "A2L-style load policy baseline (threshold imitation, not a reproduction): sampling period in us; the poller stops (OWNER, the app submits inline) after a period in which the deepest SQ it saw was below sqpoll_safe_a2l_off, and resumes once an owner enter submits a batch of at least sqpoll_safe_a2l_on SQEs; preemption and CPU contention never switch, and a preempted poller is not bypassed (0: off, default: 0)");

static unsigned int ringback_a2l_off = 1;
module_param_named(sqpoll_safe_a2l_off, ringback_a2l_off, uint, 0644);
MODULE_PARM_DESC(sqpoll_safe_a2l_off, "A2L-style: deepest SQ seen in a period below which the poller stops (default: 1)");

static unsigned int ringback_a2l_on = 8;
module_param_named(sqpoll_safe_a2l_on, ringback_a2l_on, uint, 0644);
MODULE_PARM_DESC(sqpoll_safe_a2l_on, "A2L-style: owner enter batch size at or above which the poller resumes (default: 8)");

static bool ringback_lazy_rescue;
module_param_named(sqpoll_safe_lazy_rescue, ringback_lazy_rescue, bool, 0644);
/*
 * Ring-local completions in POLL mode are left to the running poller
 * (io_ringback_poller_runs()); 0 restores the two-runner behaviour of v6.4.
 */
static bool ringback_prefer = true;
module_param_named(sqpoll_safe_prefer, ringback_prefer, bool, 0644);
/*
 * Parked OWNER mode: a CPU idle only because a task sleeps there in I/O wait
 * (an owner waiting for its completions) is not free; that task comes back
 * within microseconds and would preempt a poller resumed there.
 */
static bool ringback_hint_iowait = true;
module_param_named(sqpoll_safe_hint_iowait, ringback_hint_iowait, bool, 0644);
/*
 * Ring-local completions: a push onto a non-empty ->work_list does no wake or
 * kick work; the push that made the list non-empty did it for the whole list.
 */
static bool ringback_lean = true;
module_param_named(sqpoll_safe_lean, ringback_lean, bool, 0644);
MODULE_PARM_DESC(sqpoll_safe_lean, "Ring-local completions: only the push that makes ->work_list non-empty evaluates the wake, the preference and the MWAIT kick (default: 1)");
/* Diagnosis only: POLL-mode completions of a running poller go to its task_work. */
static bool ringback_route;
module_param_named(sqpoll_safe_route, ringback_route, bool, 0644);
/*
 * ringback_defer=1 (and route): at a POLL->OWNER switch the poller-homed
 * read/write completions already on the preempted poller's task_work list
 * are run by the owner's rescue instead of waiting for the poller's CPU.
 */
static bool ringback_steal = true;
module_param_named(sqpoll_safe_steal, ringback_steal, bool, 0644);
MODULE_PARM_DESC(sqpoll_safe_steal, "OWNER mode: the owner's rescue runs the read/write completions left on the preempted poller's task_work list (default: 1)");
MODULE_PARM_DESC(sqpoll_safe_route, "Diagnosis: while the poller runs, its read/write completions use its normal task_work instead of ->work_list (default: 0)");
MODULE_PARM_DESC(sqpoll_safe_hint_iowait, "Parked OWNER mode: idle-CPU hints and hint resumes ignore a CPU on which a task sleeps in I/O wait (default: 1)");
MODULE_PARM_DESC(sqpoll_safe_lazy_rescue, "Lazy rescue: a switch to OWNER queues no rescue task_work (no IPI) unless redirected completions wait; ring-local completions wake the owner on their own and NEED_WAKEUP makes a conforming application enter. A 2 ms safety timer rescues SQEs that make no progress for an application that never enters (default: 0)");

static bool ringback_idlewake = true;
module_param_named(sqpoll_safe_idlewake, ringback_idlewake, bool, 0644);
MODULE_PARM_DESC(sqpoll_safe_idlewake, "Parked OWNER mode: the poller drops its periodic rechecks (only the sqpoll_safe_owner_safety_us safety wake stays) and the owner's enter wakes it when one of the poller's allowed CPUs is idle; it then resumes polling at once if its own CPU is uncontended (default: 1)");

static unsigned int ringback_idlewake_us = 100;
module_param_named(sqpoll_safe_idlewake_us, ringback_idlewake_us, uint, 0644);
MODULE_PARM_DESC(sqpoll_safe_idlewake_us, "Parked OWNER mode: minimum interval in us between two idle-CPU scans of a ring by its owner's enters (default: 100)");

static unsigned int ringback_owner_safety_us = 10000;
module_param_named(sqpoll_safe_owner_safety_us, ringback_owner_safety_us, uint,
		   0644);
MODULE_PARM_DESC(sqpoll_safe_owner_safety_us, "Parked OWNER mode: period in us of the poller's safety wake, which rescues applications that do not enter (default: 10000)");

static unsigned int ringback_flap_us = 1000;
module_param_named(sqpoll_safe_flap_us, ringback_flap_us, uint, 0644);
MODULE_PARM_DESC(sqpoll_safe_flap_us, "Parked OWNER mode: a POLL epoch started by an idle-CPU hint that ends within this many us is a flap; flaps double the time during which hints are ignored (0: no backoff, default: 1000)");

static unsigned int ringback_flap_max_us = 20000;
module_param_named(sqpoll_safe_flap_max_us, ringback_flap_max_us, uint, 0644);
MODULE_PARM_DESC(sqpoll_safe_flap_max_us, "Parked OWNER mode: upper bound in us of the hint backoff after flaps (default: 20000)");

static bool ringback_polled;
module_param_named(sqpoll_safe_polled, ringback_polled, bool, 0644);
MODULE_PARM_DESC(sqpoll_safe_polled, "Polled completions for rings created while set: O_DIRECT reads and writes that the poller issues in POLL mode go to the device's poll queues and complete by polling (the poller polls them, the owner after a switch to OWNER mode); requests the owner issues complete by interrupt. The ring is not an IOPOLL ring (default: 0)");

/*
 * The A2L-style policy leaves switching to the load alone: no contention
 * checks. The dual mode keeps the contention checks (they close the lock-holder
 * window before a batch starts) but never waits in OWNER mode.
 */
static bool io_rbk_policy_fixed(void)
{
	return READ_ONCE(ringback_a2l_us);
}

/* Contention check: another task wants this CPU. */
static bool io_sq_contended(void)
{
	if (READ_ONCE(ringback_ghostfree))
		return !single_task_runnable();
	return !single_task_running();
}

static unsigned int io_rbk_checks(void)
{
	return max(2U, READ_ONCE(ringback_checks));
}

enum {
	IO_SQ_THREAD_SHOULD_STOP = 0,
	IO_SQ_THREAD_SHOULD_PARK,
};

enum {
	IO_RBK_STOPPING,
	IO_RBK_PENDING,
	IO_RBK_REQUEST,
	IO_RBK_RETRY,
	IO_RBK_DEMOTE,
	IO_RBK_OWNER,
	IO_RBK_DEBT,
	IO_RBK_KICK,
	/* Held by whoever consumes the poller's task_work list (poller or rescue). */
	IO_RBK_TWRUN,
};

/* Why an idle-class empty poll ended. */
enum {
	IO_RBK_IDLEPOLL_EXIT_SQ,
	IO_RBK_IDLEPOLL_EXIT_TW,
	IO_RBK_IDLEPOLL_EXIT_EVENT,
	IO_RBK_IDLEPOLL_EXIT_OWNER,
	IO_RBK_IDLEPOLL_EXIT_TIMEOUT,
	IO_RBK_IDLEPOLL_EXIT_NR,
};

struct io_ringback {
	struct io_ring_ctx *ctx;
#ifdef CONFIG_PREEMPT_NOTIFIERS
	struct preempt_notifier notifier;
#endif
	struct irq_work irq;
	/* Wake-only handoff of ring-local completions to the owner. */
	struct irq_work wake_irq;
	/* Deferred kick of a running owner for NO_IPI completions. */
	struct hrtimer kick;
	atomic64_t lazy_kicks;
	/* Wake-only handoffs of ring-local completions from the notifier. */
	atomic64_t handoffs;
	/* Read/write completions run from the preempted poller's task_work list. */
	atomic64_t stolen;
	/*
	 * POLL->OWNER switches at a debt-free point (no batch, no task_work).
	 */
	atomic64_t vol_to_owner;
	struct callback_head work;
	wait_queue_head_t wait;
	atomic_t wake_seq;
	unsigned long state;
	/* Notifier registered: the handoffs are armed (release/acquire). */
	bool ready;
	bool in_batch;
	bool in_tw;
	unsigned int idle_checks;
	int idle_cpu;
	u64 idle_start;
	u64 owner_start;
	seqcount_t mode_seq;
	bool boosted;
	int boost_policy;
	/* Never held while acquiring uring_lock; rescue only uses trylock. */
	struct mutex policy_lock;
	struct sched_attr saved;
	u64 boost_start;
	/* The poller's CPU time while boosted, not the boosted wall time. */
	u64 boost_runtime0;
	/*
	 * Per-boost poller CPU time (policy_lock): max; <10/30/100/300 us,
	 * <1/3/10 ms, more.
	 */
	u64 boost_rt_max;
	u64 boost_rt_hist[8];
	atomic64_t boosted_runtime_ns;
	atomic64_t preempts;
	atomic64_t rescues;
	/*
	 * SQEs by who submitted them: the owner's rescue (submitted), the
	 * owner's own enter in OWNER mode (owner_submitted), the poller.
	 */
	atomic64_t submitted;
	atomic64_t poll_submitted;
	atomic64_t trylock_fail;
	atomic64_t boosts;
	atomic64_t boosted_ns;
	atomic64_t poll_to_owner;
	atomic64_t owner_to_poll;
	atomic64_t owner_ns;
	atomic64_t owner_submitted;
	atomic64_t preempt_locked;
	atomic64_t redirected;
	/*
	 * OWNER-mode completions of poller-homed requests, run by the owner's
	 * rescue. Producers push in RCU read sections; the single consumer is
	 * serialized by uring_lock.
	 */
	struct mpscq redirect;
	struct llist_node *redirect_head;
	/* Poller-only: SQ head seen by the previous OWNER-mode check. */
	unsigned int last_head;
	/*
	 * Idle-class empty polling, poller-only: the policy the poller works
	 * with, the start of the current empty poll and the next entry check.
	 */
	bool idlepoll_on;
	struct sched_attr idlepoll_saved;
	u64 idlepoll_empty_start;
	u64 idlepoll_next_check;
	atomic64_t idlepoll_entries;
	atomic64_t idlepoll_idle_ns;
	/*
	 * Entry checks refused because the poller still had requests in flight.
	 */
	atomic64_t idlepoll_inflight_block;
	atomic64_t idlepoll_setattr_fail;
	atomic64_t idlepoll_exit[IO_RBK_IDLEPOLL_EXIT_NR];
	/*
	 * Lease, poller-only: SQ head and start of the current OWNER stall, and
	 * one batch without the contention check after an expiry so the poller
	 * makes progress.
	 */
	unsigned int stall_head;
	u64 stall_start;
	bool lease_grace;
	atomic64_t lease_expired;
	/* Poller-only: current OWNER-mode recheck period (0: base period). */
	u64 owner_backoff_ns;
	atomic64_t owner_wakes;
	/*
	 * Ring-local completions, poller-only stall check:
	 * ->ringback_local_runs seen by the previous OWNER-mode check and
	 * consecutive checks without a run while completions waited. After
	 * three, the owner is taken to reap without entering (CQ spinning) and
	 * its completions go back to task_work.
	 */
	unsigned long defer_last_runs;
	unsigned int defer_stuck;
	bool defer_spin;
	atomic64_t defer_rescues;
	/*
	 * Owner-written: ->work_list runs done by the rescue, not by an enter.
	 */
	unsigned long defer_rescue_runs;
	/*
	 * Lazy rescue: switches without an IPI, and the safety timer. The
	 * lock orders the callback's stop decision with the poller's arming
	 * (also from sched_out) and with the cancel in io_ringback_stop().
	 * The SQ head and the owner's ->work_list runs seen by the previous
	 * check, and consecutive checks that left completions unrun.
	 */
	atomic64_t lazy_skips;
	atomic64_t safety_rescues;
	struct hrtimer safety;
	raw_spinlock_t safety_lock;
	bool safety_armed;
	unsigned int safety_head;
	unsigned long safety_runs;
	unsigned int safety_stuck;
	/*
	 * Dual mode: SQEs the creator's enter submitted in POLL mode, poller
	 * off CPU.
	 */
	atomic64_t dual_submitted;
	/*
	 * Dual mode: the poller is giving the CPU up in OWNER mode (not a
	 * preemption).
	 */
	bool yielding;
	atomic64_t yields;
	/* MWAIT: entries, the flag producers test, and the IPIs they sent. */
	atomic64_t mwaits;
	bool in_mwait;
	atomic64_t mwait_kicks;
	/*
	 * A2L-style policy, poller-only: period start and the deepest SQ seen
	 * in it; owner-set resume request.
	 */
	u64 a2l_period_start;
	unsigned int a2l_depth_max;
	bool a2l_resume;
	atomic64_t a2l_offs;
	atomic64_t a2l_ons;
	/*
	 * Parked OWNER mode: the idle CPU an owner enter found (-1: none),
	 * written by the owner and consumed by the poller, the owner's last
	 * scan, and wakes sent, resumes taken and hints found contended.
	 */
	int idle_hint;
	u64 idle_scan_ns;
	atomic64_t idle_wakes;
	atomic64_t idle_hits;
	atomic64_t idle_misses;
	/*
	 * Hint backoff, poller-only except the owner's read of hint_quiet:
	 * start of the POLL epoch a hint began (0: not a hint epoch), the
	 * current backoff, the end of the quiet time, and flaps seen.
	 */
	u64 hint_resume_ns;
	u64 hint_backoff_ns;
	u64 hint_quiet;
	atomic64_t idle_flaps;
	/*
	 * Polled completions, fixed at ring creation: requests the poller
	 * issued polled, and polled requests the owner reaped.
	 */
	bool polled;
	atomic64_t polled_issued;
	atomic64_t polled_reaped_by_owner;
};

static unsigned int io_sqpoll_sq_entries(struct io_ring_ctx *ctx);
static bool io_sq_tw_pending(void);

/*
 * Ring-local eligibility of a completion, see io_req_ringback_local_work_add().
 */
bool io_ringback_defer_ok(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_ringback *rbk = ctx->ringback;

	if (!rbk || READ_ONCE(rbk->defer_spin) ||
	    req->io_task_work.func != io_req_rw_complete ||
	    (req->flags & IO_REQ_LINK_FLAGS) ||
	    test_bit(IO_RBK_STOPPING, &rbk->state) ||
	    percpu_ref_is_dying(&ctx->refs))
		return false;
	/*
	 * ringback_defer=2: every read/write completion of the ring, in either
	 * mode. RINGBACK_LOCAL is set once, before the ring is used.
	 */
	if (data_race(ctx->int_flags) & IO_RING_F_RINGBACK_LOCAL)
		return true;
	/*
	 * ringback_defer=1: the creator's own in OWNER mode, without notify
	 * users.
	 */
	return READ_ONCE(ringback_defer) == 1 &&
	       req->tctx && req->tctx->task == ctx->ringback_owner &&
	       test_bit(IO_RBK_OWNER, &rbk->state) &&
	       /* Unlocked, like the other int_flags tests in io_uring. */
	       !(data_race(ctx->int_flags) & IO_RING_F_HAS_EVFD) &&
	       /* Unlocked: a poll waiter added concurrently may be missed. */
	       !waitqueue_active(&ctx->poll_wq);
}

/* Ring-local completions: the POLL-mode runner of ->work_list is the poller. */
bool io_ringback_is_poller(struct io_ring_ctx *ctx)
{
	return ctx->sq_data &&
	       current == rcu_access_pointer(ctx->sq_data->thread);
}

static void io_rbk_queue(struct io_ringback *rbk);

/*
 * Parked OWNER mode, from the owner's enter: wake the parked poller when one
 * of its allowed CPUs is idle, so that it resumes polling without periodic
 * rechecks. Rate-limited per ring, and skipped while the poller is runnable or
 * an earlier hint is pending. At most 16 CPUs of the enter's node are tested.
 */
static bool io_rbk_cpu_napping(int cpu)
{
	return READ_ONCE(ringback_hint_iowait) && nr_iowait_cpu(cpu);
}

void io_ringback_idle_scan(struct io_ring_ctx *ctx)
{
	struct io_ringback *rbk = ctx->ringback;
	struct task_struct *tsk;
	unsigned int tested = 0;
	int cpu, hint = -1;
	u64 now;

	/* A2L-style: the load policy alone decides when polling resumes. */
	if (!rbk || !READ_ONCE(ringback_idlewake) || io_rbk_policy_fixed() ||
	    READ_ONCE(rbk->idle_hint) >= 0)
		return;
	now = ktime_get_ns();
	if (now - READ_ONCE(rbk->idle_scan_ns) <
	    (u64)READ_ONCE(ringback_idlewake_us) * NSEC_PER_USEC ||
	    now < READ_ONCE(rbk->hint_quiet))
		return;
	WRITE_ONCE(rbk->idle_scan_ns, now);
	rcu_read_lock();
	tsk = rcu_dereference(ctx->sq_data->thread);
	if (tsk && !task_is_running(tsk)) {
		for_each_cpu_and(cpu, tsk->cpus_ptr,
				 cpumask_of_node(numa_node_id())) {
			if (idle_cpu(cpu) && !io_rbk_cpu_napping(cpu)) {
				hint = cpu;
				break;
			}
			if (++tested >= 16)
				break;
		}
	}
	rcu_read_unlock();
	if (hint < 0)
		return;
	WRITE_ONCE(rbk->idle_hint, hint);
	atomic64_inc(&rbk->idle_wakes);
	/*
	 * The wakeup orders the hint before the poller's read of it in
	 * io_rbk_try_poll().
	 */
	wake_up(&ctx->sq_data->wait);
}

/*
 * RingBack promotion targets only queues that poll: a raw block device file
 * has ->iopoll even when its queue cannot, and blk-mq then fails the bio.
 */
static bool io_rbk_queue_polls(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct block_device *bdev;
	struct request_queue *q;

	bdev = S_ISBLK(inode->i_mode) ? I_BDEV(file->f_mapping->host) :
					inode->i_sb->s_bdev;
	if (!bdev)
		return false;
	q = bdev_get_queue(bdev);
	if (!(q->limits.features & BLK_FEAT_POLL))
		return false;
	return !queue_is_mq(q) || q->tag_set->map[HCTX_TYPE_POLL].nr_queues;
}

/*
 * Polled completions, at issue (rw.c, direct I/O to a file with ->iopoll): a
 * request the poller issues on a polled ring completes by polling. The choice
 * sticks to the request across reissues from io-wq.
 */
bool io_ringback_polled_issue(struct io_kiocb *req, struct file *file)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_ringback *rbk = ctx->ringback;

	if (req->flags & REQ_F_IOPOLL)
		return true;
	if (!rbk || !rbk->polled || !io_ringback_is_poller(ctx) ||
	    !io_rbk_queue_polls(file))
		return false;
	atomic64_inc(&rbk->polled_issued);
	return true;
}

/*
 * Polled completions, uring_lock held: polled requests complete only when
 * someone polls. In OWNER mode the poller does not, so the owner reaps those
 * the poller left; also from the dual-mode bypass. Returns the number reaped.
 */
int io_ringback_owner_reap(struct io_ring_ctx *ctx)
{
	struct io_ringback *rbk = ctx->ringback;
	int ret;

	lockdep_assert_held(&ctx->uring_lock);
	if (!rbk || list_empty(&ctx->iopoll_list))
		return 0;
	ret = io_do_iopoll(ctx, true);
	if (ret > 0)
		atomic64_add(ret, &rbk->polled_reaped_by_owner);
	return ret;
}

/*
 * Polled completions: io-wq added a polled request (its issue punted); a
 * poller waiting in MWAIT gets no store to the SQ tail for it.
 */
void io_ringback_polled_added(struct io_ring_ctx *ctx)
{
	struct task_struct *tsk;

	rcu_read_lock();
	tsk = rcu_dereference(ctx->sq_data->thread);
	if (tsk)
		io_ringback_mwait_kick(ctx, tsk);
	rcu_read_unlock();
}

/*
 * Ring-local completions in POLL mode: a scheduling preference, separate from
 * the drain authorization in io_ringback_local_runner(). True while the LOCAL
 * ring's poller is current on its CPU (MWAIT included): then the poller runs
 * ->work_list and its CQEs wake an armed owner by count, so a producer need
 * not wake the owner and the owner need not drain. It is a snapshot. A poller
 * committed to its empty-SQ sleep (state set, then the list checked) is not
 * "running": the push before this load is seen by that check, or this load
 * sees the state, as in io_ringback_defer_kick(). Every other path on which the
 * poller stops running with the list non-empty hands off to the owner
 * (io_rbk_handoff() from the preempt notifier, the rescue of an OWNER switch,
 * the terminal drain at exit), so a stale "runs" only delays the owner. False
 * before the notifier is registered, in OWNER mode, while stopping and under
 * the A2L-style policy (a preempted A2L poller never switches); the same
 * tests io_ringback_owner_submit() makes before bypassing a poller.
 */
bool io_ringback_poller_runs(struct io_ring_ctx *ctx)
{
	struct io_ringback *rbk = ctx->ringback;
	struct task_struct *tsk;
	bool runs = false;

	if (!rbk || !(data_race(ctx->int_flags) & IO_RING_F_RINGBACK_LOCAL) ||
	    !READ_ONCE(ringback_prefer))
		return false;
	if (!smp_load_acquire(&rbk->ready) || io_ringback_owner_mode(ctx) ||
	    test_bit(IO_RBK_STOPPING, &rbk->state) || io_rbk_policy_fixed())
		return false;
	rcu_read_lock();
	tsk = rcu_dereference(ctx->sq_data->thread);
	if (tsk)
		runs = task_curr(tsk) && task_is_running(tsk);
	rcu_read_unlock();
	return runs;
}

bool io_ringback_lean(void)
{
	return READ_ONCE(ringback_lean);
}

/* Diagnosis (sqpoll_safe_route): leave a running poller's completion to its task_work. */
bool io_ringback_route_poller(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;

	return READ_ONCE(ringback_route) && req->tctx &&
	       req->tctx->task != ctx->ringback_owner &&
	       io_ringback_poller_runs(ctx);
}

/* The owner should leave ->work_list to the poller right now. */
bool io_ringback_prefer_poller(struct io_ring_ctx *ctx, struct task_struct *tsk)
{
	return ctx->ringback && tsk == ctx->ringback_owner &&
	       io_ringback_poller_runs(ctx);
}

static void io_rbk_wake_irq(struct irq_work *work)
{
	struct io_ringback *rbk = container_of(work, struct io_ringback,
					       wake_irq);

	wake_up_state(rbk->ctx->ringback_owner, TASK_INTERRUPTIBLE);
}

/*
 * From the preempt notifier: the poller leaves the CPU with ring-local
 * completions a producer may have left to it in POLL mode: a sleep that does
 * not check the list first (a mutex, an event wait, a park) or a preemption
 * under the A2L policy; the empty-SQ sleep is covered by
 * io_ringback_poller_runs() itself.
 * Wake the owner (no rescue: nothing to submit, and the A2L policy forbids
 * one). An owner waiting in
 * io_cqring_wait() then drains them itself while the preference stays false
 * (the poller is not current); if the poller resumes first, it runs them or
 * hands off again. An owner that does not wait keeps its usual consumers (the
 * kicked poller, its next enter). Ordering: the
 * scheduler publishes rq->curr = next before this notifier (__schedule() ->
 * context_switch() -> prepare_task_switch()); the barrier orders that store
 * before the list load, against a producer's push (full barrier) before its
 * task_curr() load. The wake is deferred: wake_up_state() takes the owner's
 * pi_lock and rq lock, which the notifier may hold.
 */
static void io_rbk_handoff(struct io_ringback *rbk)
{
	smp_mb();
	/*
	 * OWNER mode: the preference is false, so the owner is woken for its
	 * ring-local completions already, and the switch to OWNER queued a
	 * rescue for what was left to the poller before it.
	 */
	if (test_bit(IO_RBK_OWNER, &rbk->state))
		return;
	if (io_local_work_pending(rbk->ctx)) {
		atomic64_inc(&rbk->handoffs);
		irq_work_queue(&rbk->wake_irq);
	}
}

/*
 * After a ring-local enqueue, under the producer's RCU read section. The
 * push's full barrier pairs with the poller clearing OWNER, so either this
 * sees POLL or the poller sees the entry. @waiter: an owner waiting in
 * io_cqring_wait() for this cycle runs the list itself.
 */
void io_ringback_defer_kick(struct io_ring_ctx *ctx, bool waiter)
{
	struct io_ringback *rbk = ctx->ringback;
	/* RINGBACK_LOCAL is set once, before the ring is used. */
	bool local = data_race(ctx->int_flags) & IO_RING_F_RINGBACK_LOCAL;
	struct task_struct *tsk;

	if (test_bit(IO_RBK_OWNER, &rbk->state)) {
		/*
		 * ringback_defer=2: eventfd and poll users reap without
		 * entering, so run it now. Both tests are unlocked, like the
		 * other int_flags and poll waiter tests in io_uring.
		 */
		if (local && ((data_race(ctx->int_flags) & IO_RING_F_HAS_EVFD) ||
			      /* A new poll waiter may be missed. */
			      waitqueue_active(&ctx->poll_wq)))
			io_rbk_queue(rbk);
		return;
	}
	/*
	 * A ringback_defer=1 entry that raced with OWNER -> POLL: owner's
	 * rescue.
	 */
	if (!local) {
		io_rbk_queue(rbk);
		return;
	}
	/*
	 * ringback_defer=2 in POLL mode: the poller runs ->work_list; wake it.
	 */
	tsk = rcu_dereference(ctx->sq_data->thread);
	if (!tsk)
		return;
	if (!task_is_running(tsk)) {
		wake_up_state(tsk, TASK_INTERRUPTIBLE);
		return;
	}
	/*
	 * MWAIT: a poller in MWAIT is running and only an IPI ends its wait.
	 * An owner that reaps without waiting (CQ spinning) depends on the
	 * poller's run; a waiter runs the list itself once woken.
	 */
	if (!waiter && READ_ONCE(rbk->in_mwait)) {
		atomic64_inc(&rbk->mwait_kicks);
		kick_process(tsk);
	}
}

/*
 * MWAIT: poller-homed task_work added while the poller waits in MWAIT. The
 * caller's atomic flag set orders the work before this load; the poller's
 * full barrier after setting in_mwait orders the flag before its checks.
 */
void io_ringback_mwait_kick(struct io_ring_ctx *ctx, struct task_struct *tsk)
{
	struct io_ringback *rbk = ctx->ringback;

	if (READ_ONCE(rbk->in_mwait)) {
		atomic64_inc(&rbk->mwait_kicks);
		kick_process(tsk);
	}
}

/*
 * Ring-local completions, from the owner's rescue: run its ring-local
 * completions with uring_lock held. These runs are not progress of the owner's
 * own enters, so the poller's stall check discounts them. Left to the poller
 * while it runs the list (io_ringback_poller_runs()).
 */
static void io_rbk_run_local(struct io_ring_ctx *ctx)
{
	struct io_ringback *rbk = ctx->ringback;

	if (!io_local_work_pending(ctx) || ctx->ringback_owner != current ||
	    io_ringback_poller_runs(ctx))
		return;
	(void)io_run_local_work_locked(ctx, 0);
	WRITE_ONCE(rbk->defer_rescue_runs, rbk->defer_rescue_runs + 1);
}

void io_ringback_submitted(struct io_ring_ctx *ctx, unsigned int submitted)
{
	struct io_ringback *rbk = ctx->ringback;

	atomic64_add(submitted, &rbk->owner_submitted);
	/*
	 * A2L-style: a large inline batch is the load signal that turns polling
	 * back on.
	 */
	if (READ_ONCE(ringback_a2l_us) &&
	    submitted >= READ_ONCE(ringback_a2l_on))
		WRITE_ONCE(rbk->a2l_resume, true);
}

/*
 * Dual mode: does the creator's enter bypass a poller that is merely off CPU?
 */
bool io_ringback_dual(struct io_ring_ctx *ctx)
{
	return ctx->ringback && READ_ONCE(ringback_dual);
}

/*
 * A2L-style baseline: the load policy alone decides; a preempted poller is
 * never bypassed.
 */
bool io_ringback_a2l(struct io_ring_ctx *ctx)
{
	return ctx->ringback && READ_ONCE(ringback_a2l_us);
}

void io_ringback_dual_submitted(struct io_ring_ctx *ctx, unsigned int submitted)
{
	atomic64_add(submitted, &ctx->ringback->dual_submitted);
}

static void io_rbk_queue(struct io_ringback *rbk)
{
	if (!test_bit(IO_RBK_STOPPING, &rbk->state)) {
		set_bit(IO_RBK_REQUEST, &rbk->state);
		irq_work_queue(&rbk->irq);
	}
}

/*
 * Lazy-rescue safety net while OWNER mode lasts after a lazy switch (no rescue
 * queued): every 2 ms, what makes no progress without the poller gets the
 * owner's rescue. Three kinds, with the rules of io_rbk_owner_wait(): SQEs
 * pending with no SQ progress since the previous check (an application that
 * publishes without entering); ->work_list completions with no run by the owner
 * since the previous check (an owner that reaps without entering; after three
 * such checks of an owner on CPU, its completions go back to task_work); and
 * redirected work left by a failed rescue. The callback stops the timer once it
 * sees POLL; safety_lock orders that decision with the next arming in
 * io_rbk_to_owner(), so no OWNER epoch is left without a timer.
 */
static enum hrtimer_restart io_rbk_safety_fn(struct hrtimer *timer)
{
	struct io_ringback *rbk = container_of(timer, struct io_ringback,
					       safety);
	struct io_ring_ctx *ctx = rbk->ctx;
	bool rescue = false;
	unsigned long runs;
	unsigned int head;

	raw_spin_lock(&rbk->safety_lock);
	if (test_bit(IO_RBK_STOPPING, &rbk->state) ||
	    !test_bit(IO_RBK_OWNER, &rbk->state)) {
		rbk->safety_armed = false;
		raw_spin_unlock(&rbk->safety_lock);
		return HRTIMER_NORESTART;
	}
	head = READ_ONCE(ctx->rings->sq.head);
	if (io_sqpoll_sq_entries(ctx) && head == rbk->safety_head) {
		atomic64_inc(&rbk->safety_rescues);
		rescue = true;
	}
	rbk->safety_head = head;
	runs = READ_ONCE(ctx->ringback_local_runs) -
	       READ_ONCE(rbk->defer_rescue_runs);
	if (io_local_work_pending(ctx) && runs == rbk->safety_runs) {
		atomic64_inc(&rbk->defer_rescues);
		if (task_curr(ctx->ringback_owner) && ++rbk->safety_stuck >= 3)
			WRITE_ONCE(rbk->defer_spin, true);
		rescue = true;
	} else {
		rbk->safety_stuck = 0;
	}
	rbk->safety_runs = runs;
	if (!mpscq_empty(&rbk->redirect) ||
	    !list_empty_careful(&ctx->iopoll_list))
		rescue = true;
	if (rescue)
		io_rbk_queue(rbk);
	hrtimer_forward_now(timer, ms_to_ktime(2));
	raw_spin_unlock(&rbk->safety_lock);
	return HRTIMER_RESTART;
}

/* Arm the safety timer for this OWNER epoch unless it is running already. */
static void io_rbk_safety_arm(struct io_ringback *rbk)
{
	struct io_ring_ctx *ctx = rbk->ctx;
	unsigned long flags;

	raw_spin_lock_irqsave(&rbk->safety_lock, flags);
	if (!rbk->safety_armed && !test_bit(IO_RBK_STOPPING, &rbk->state)) {
		rbk->safety_armed = true;
		rbk->safety_head = READ_ONCE(ctx->rings->sq.head);
		rbk->safety_runs = READ_ONCE(ctx->ringback_local_runs) -
				   READ_ONCE(rbk->defer_rescue_runs);
		rbk->safety_stuck = 0;
		hrtimer_start(&rbk->safety, ms_to_ktime(2), HRTIMER_MODE_REL);
	}
	raw_spin_unlock_irqrestore(&rbk->safety_lock, flags);
}

/*
 * Parked OWNER mode, at a POLL->OWNER switch: a POLL epoch that an idle-CPU
 * hint started and that ends within sqpoll_safe_flap_us is a flap (the CPU was
 * free only for a moment, as in an overloaded pool). Flaps double the time in
 * which the owner's enters send no hints; a long hint epoch clears it.
 */
static void io_rbk_hint_backoff(struct io_ringback *rbk)
{
	u64 now, flap = (u64)READ_ONCE(ringback_flap_us) * NSEC_PER_USEC;

	if (!rbk->hint_resume_ns)
		return;
	now = ktime_get_ns();
	if (now - rbk->hint_resume_ns < flap) {
		u64 max = (u64)READ_ONCE(ringback_flap_max_us) * NSEC_PER_USEC;

		atomic64_inc(&rbk->idle_flaps);
		rbk->hint_backoff_ns = min(max_t(u64, rbk->hint_backoff_ns * 2,
						 100 * NSEC_PER_USEC), max);
		WRITE_ONCE(rbk->hint_quiet, now + rbk->hint_backoff_ns);
	} else {
		rbk->hint_backoff_ns = 0;
	}
	rbk->hint_resume_ns = 0;
}

/* Called only by the poller, with preemption disabled (also in sched_out). */
static void io_rbk_to_owner(struct io_ringback *rbk, bool voluntary)
{
	struct io_ring_ctx *ctx = rbk->ctx;
	bool lazy = READ_ONCE(ringback_lazy_rescue);

	rbk->idle_checks = 0;
	if (test_bit(IO_RBK_OWNER, &rbk->state)) {
		/* A previous rescue may have seen us still on CPU. */
		if (test_bit(IO_RBK_DEBT, &rbk->state) && !lazy)
			io_rbk_queue(rbk);
		return;
	}
	io_rbk_hint_backoff(rbk);
	write_seqcount_begin(&rbk->mode_seq);
	WRITE_ONCE(rbk->owner_start, ktime_get_ns());
	set_bit(IO_RBK_DEBT, &rbk->state);
	set_bit(IO_RBK_OWNER, &rbk->state);
	WRITE_ONCE(ctx->ringback_owner_mode, true);
	atomic64_inc(&rbk->poll_to_owner);
	if (voluntary)
		atomic64_inc(&rbk->vol_to_owner);
	/*
	 * Unlike upstream, preemption/OWNER sets NEED_WAKEUP before
	 * sq_thread_idle expires; liburing sqpoll-sleep.t assumes otherwise.
	 * Publish OWNER first so every enter prompted by this flag can submit.
	 */
	smp_mb__before_atomic();
	atomic_or(IORING_SQ_NEED_WAKEUP, &ctx->rings->sq_flags);
	/* Pair with userspace's tail-store/flag-load barrier. */
	smp_mb__after_atomic();
	write_seqcount_end(&rbk->mode_seq);
	/*
	 * Lazy rescue: no IPI for the common switch. Redirected completions
	 * need the owner's rescue; everything else reaches the owner on its
	 * own.
	 */
	/*
	 * The dual mode yields instead of the OWNER-mode wait and its periodic
	 * checks, so with it every OWNER epoch needs the safety timer, also one
	 * that starts with an immediate rescue for redirected work.
	 */
	/* Polled rings: polled requests left in flight need a rescuer too. */
	if (lazy || READ_ONCE(ringback_dual) || rbk->polled)
		io_rbk_safety_arm(rbk);
	if (lazy) {
		/* Order rq->curr = next before the list loads (io_rbk_handoff()). */
		smp_mb();
		if (mpscq_empty(&rbk->redirect) &&
		    !io_local_work_pending(ctx)) {
			atomic64_inc(&rbk->lazy_skips);
			return;
		}
	}
	io_rbk_queue(rbk);
}

void io_ringback_wake(struct io_ring_ctx *ctx)
{
	struct io_ringback *rbk = ctx->ringback;

	/*
	 * A late poller-homed completion still belongs to the switch debt; a
	 * non-creator enter in OWNER mode is handed to the creator likewise.
	 */
	if (rbk && test_bit(IO_RBK_OWNER, &rbk->state))
		io_rbk_queue(rbk);
}

static bool io_rbk_runnable(struct task_struct *tsk)
{
	/* __state may be INTERRUPTIBLE before the sleep handshake completes. */
	return READ_ONCE(tsk->on_rq) && !READ_ONCE(tsk->se.sched_delayed);
}

static bool io_rbk_off_cpu(struct task_struct *tsk)
{
	return io_rbk_runnable(tsk) && !task_curr(tsk);
}

static void io_rbk_wake(struct io_ringback *rbk)
{
	atomic_inc(&rbk->wake_seq);
	wake_up_all(&rbk->wait);
}

static void io_rbk_policy_unlock(struct io_ringback *rbk)
{
	mutex_unlock(&rbk->policy_lock);
	if (test_and_clear_bit(IO_RBK_DEMOTE, &rbk->state))
		io_rbk_queue(rbk);
}

/* policy_lock serializes remote boosting with debt-drain restoration. */
static void io_rbk_restore(struct io_ringback *rbk, struct task_struct *tsk)
{
	static const u64 bounds[] = {
		10 * NSEC_PER_USEC, 30 * NSEC_PER_USEC, 100 * NSEC_PER_USEC,
		300 * NSEC_PER_USEC, NSEC_PER_MSEC, 3 * NSEC_PER_MSEC,
		10 * NSEC_PER_MSEC,
	};
	unsigned int i;
	bool ours;
	u64 rt;

	if (!rbk->boosted)
		return;
	/*
	 * Preserve already observed external changes; concurrent setters can
	 * race.
	 */
	if (rbk->boost_policy == SCHED_FIFO)
		ours = READ_ONCE(tsk->policy) == SCHED_FIFO &&
		       READ_ONCE(tsk->rt_priority) == 1;
	else
		ours = READ_ONCE(tsk->policy) == SCHED_NORMAL &&
		       task_nice(tsk) == MAX_NICE;
	if (ours && sched_setattr_nocheck(tsk, &rbk->saved))
		return;
	rt = task_sched_runtime(tsk) - rbk->boost_runtime0;
	atomic64_add(ktime_get_ns() - rbk->boost_start, &rbk->boosted_ns);
	atomic64_add(rt, &rbk->boosted_runtime_ns);
	rbk->boost_rt_max = max(rbk->boost_rt_max, rt);
	for (i = 0; i < ARRAY_SIZE(bounds) && rt >= bounds[i]; i++)
		;
	rbk->boost_rt_hist[i]++;
	WRITE_ONCE(rbk->boosted, false);
}

/* No new poller requests can be added in OWNER; cached refs are not I/O. */
static bool io_rbk_debt(struct io_ringback *rbk, struct task_struct *tsk)
{
	struct io_uring_task *tctx = READ_ONCE(tsk->io_uring);

	if (!test_bit(IO_RBK_DEBT, &rbk->state))
		return false;
	if (READ_ONCE(rbk->in_batch) || READ_ONCE(rbk->in_tw))
		return true;
	if (!tctx)
		return false;
	if (!mpscq_empty(&tctx->task_list))
		return true;
	/* Redirected completions of in-flight requests need only the owner. */
	return !READ_ONCE(ringback_redirect) &&
	       percpu_counter_sum(&tctx->inflight) >
	       READ_ONCE(tctx->cached_refs);
}

/*
 * Repay a SCHED_IDLE poller's switch debt while the owner waits for it. With
 * @stopping, STOPPING is set and the poller no longer switches to OWNER: boost
 * only a holder preempted inside a batch or task_work run. The caller then
 * restores the policy in io_ringback_stop().
 */
static void io_rbk_boost(struct io_ringback *rbk, struct task_struct *tsk,
			 bool stopping)
{
	struct sched_attr attr = {
		.size = sizeof(attr),
		.sched_policy = SCHED_NORMAL,
		.sched_nice = MAX_NICE,
	};
	unsigned long flags;

	if (!mutex_trylock(&rbk->policy_lock))
		return;
	if ((!stopping && test_bit(IO_RBK_STOPPING, &rbk->state)) ||
	    READ_ONCE(ringback_rt) == 2 ||
	    READ_ONCE(ringback_rt) == 3) {
		io_rbk_restore(rbk, tsk);
		goto out;
	}
	if (rbk->boosted) {
		if (!io_rbk_runnable(tsk))
			io_rbk_restore(rbk, tsk);
		goto out;
	}
	if (stopping) {
		if (!io_rbk_off_cpu(tsk) ||
		    (!READ_ONCE(rbk->in_batch) && !READ_ONCE(rbk->in_tw)))
			goto out;
	} else if (!test_bit(IO_RBK_OWNER, &rbk->state) ||
		   !io_rbk_off_cpu(tsk) || !io_rbk_debt(rbk, tsk)) {
		goto out;
	}

	/* NORMAL/RT/DL already outrank NORMAL nice 19; never demote them. */
	raw_spin_lock_irqsave(&tsk->pi_lock, flags);
	rbk->saved = (struct sched_attr) {
		.size = sizeof(rbk->saved),
		.sched_policy = tsk->policy,
		.sched_nice = task_nice(tsk),
		.sched_flags = tsk->sched_reset_on_fork ?
			       SCHED_FLAG_RESET_ON_FORK : 0,
		.sched_runtime = tsk->se.custom_slice ? tsk->se.slice : 0,
	};
	raw_spin_unlock_irqrestore(&tsk->pi_lock, flags);
	if (rbk->saved.sched_policy != SCHED_IDLE)
		goto out;
	if (READ_ONCE(ringback_rt) == 1) {
		/*
		 * Bounded priority inheritance: the owner waits on this holder,
		 * and a SCHED_IDLE holder rarely runs next to NORMAL work.
		 */
		attr.sched_policy = SCHED_FIFO;
		attr.sched_priority = 1;
		attr.sched_nice = 0;
	}
	attr.sched_flags = rbk->saved.sched_flags;
	rbk->boost_policy = attr.sched_policy;
	rbk->boost_start = ktime_get_ns();
	rbk->boost_runtime0 = task_sched_runtime(tsk);
	if (!sched_setattr_nocheck(tsk, &attr)) {
		WRITE_ONCE(rbk->boosted, true);
		atomic64_inc(&rbk->boosts);
		/*
		 * Pair publication with sched_out's boosted check before
		 * sleeping.
		 */
		smp_mb();
		if (!io_rbk_runnable(tsk))
			io_rbk_restore(rbk, tsk);
	}
out:
	io_rbk_policy_unlock(rbk);
}

/*
 * Fail only after publishing RETRY and retrying once: io_rbk_released()
 * tests RETRY after its unlock and a full barrier, so either this trylock
 * sees the unlock or the releaser sees RETRY and wakes or requeues us.
 */
static bool io_rbk_trylock_retry(struct io_ringback *rbk)
{
	struct mutex *lock = &rbk->ctx->uring_lock;

	if (mutex_trylock(lock))
		return true;
	set_bit(IO_RBK_RETRY, &rbk->state);
	/* Order RETRY before the recheck, against the releaser's smp_mb(). */
	smp_mb__after_atomic();
	return mutex_trylock(lock);
}

bool io_ringback_tw_lock(struct io_ring_ctx *ctx)
{
	struct io_ringback *rbk = ctx->ringback;
	struct task_struct *tsk;

	if (ctx->ringback_owner != current)
		return false;
	if (mutex_trylock(&ctx->uring_lock))
		return true;
	/* Baseline: a real mutex wait lets proxy execution run the holder. */
	if (READ_ONCE(ringback_rt) == 2) {
		mutex_lock(&ctx->uring_lock);
		return true;
	}
	/*
	 * task_work is LIFO: a completion can precede the rescue callback. Wait
	 * here with a preemption/release wakeup instead of hiding the rescue
	 * behind a mutex wait. The popped FIFO head stays on this task's stack.
	 */
	rcu_read_lock();
	tsk = rcu_dereference(ctx->sq_data->thread);
	if (tsk)
		get_task_struct(tsk);
	rcu_read_unlock();
	for (;;) {
		int seq = atomic_read(&rbk->wake_seq);

		if (io_rbk_trylock_retry(rbk))
			break;
		if (tsk && READ_ONCE(ringback_rt) != 3)
			io_rbk_boost(rbk, tsk, false);
		/*
		 * The poller wakes us after a batch or its task_work run. Other
		 * holders have no release hook: poll at a fixed short interval,
		 * not once per jiffy (3.3 ms at HZ=300).
		 */
		wait_event_hrtimeout(rbk->wait,
				     atomic_read(&rbk->wake_seq) != seq,
				     ns_to_ktime(50 * NSEC_PER_USEC));
	}
	if (tsk)
		put_task_struct(tsk);
	return true;
}

bool io_ringback_redirect(struct io_kiocb *req)
{
	struct io_ringback *rbk = req->ctx->ringback;
	bool empty;

	/*
	 * Only read/write completions: they do not depend on the running task.
	 * uring_cmd (ublk checks current), linked issue (current->files), poll
	 * and multishot re-arm and link timeouts stay with the poller.
	 */
	if (req->io_task_work.func != io_req_rw_complete)
		return false;
	/* Caller holds rcu_read_lock(): io_rbk_return() waits for us. */
	if (!READ_ONCE(ringback_redirect) ||
	    !test_bit(IO_RBK_OWNER, &rbk->state) ||
	    test_bit(IO_RBK_STOPPING, &rbk->state))
		return false;
	/* Never strand the consumer between tail xchg and linking. */
	preempt_disable();
	empty = mpscq_push(&rbk->redirect, &req->io_task_work.node);
	preempt_enable();
	atomic64_inc(&rbk->redirected);
	if (empty)
		io_rbk_queue(rbk);
	return true;
}

/* Run redirected completions in the owner. Caller holds uring_lock. */
static void io_rbk_run_redirect(struct io_ringback *rbk)
{
	struct io_ring_ctx *ctx = rbk->ctx;
	struct io_tw_state ts = { .cancel = io_should_terminate_tw(ctx) };
	const struct cred *creds = NULL;
	struct llist_node *node;

	if (mpscq_empty(&rbk->redirect))
		return;
	/* The poller would have run these with the ring's SQPOLL creds. */
	if (ctx->sq_creds != current_cred())
		creds = override_creds(ctx->sq_creds);
	while ((node = mpscq_pop(&rbk->redirect, &rbk->redirect_head))) {
		struct io_kiocb *req = container_of(node, struct io_kiocb,
						    io_task_work.node);

		req->io_task_work.func((struct io_tw_req){req}, ts);
	}
	if (creds)
		revert_creds(creds);
	/* A producer is between tail xchg and linking: come back later. */
	if (!mpscq_empty(&rbk->redirect))
		set_bit(IO_RBK_REQUEST, &rbk->state);
}

/*
 * Stopping: a preempted SCHED_IDLE poller may hold uring_lock in its last
 * batch, and STOPPING ends switch-debt boosts. Repay that lock debt here as
 * io_ringback_tw_lock() does; rt=2/3 keep their plain mutex wait.
 */
static void io_rbk_stop_lock(struct io_ringback *rbk)
{
	struct io_ring_ctx *ctx = rbk->ctx;
	unsigned int rt = READ_ONCE(ringback_rt);
	struct task_struct *tsk = NULL;

	if (mutex_trylock(&ctx->uring_lock))
		return;
	if (rt == 2 || rt == 3 || !ctx->sq_data) {
		mutex_lock(&ctx->uring_lock);
		return;
	}
	rcu_read_lock();
	tsk = rcu_dereference(ctx->sq_data->thread);
	if (tsk)
		get_task_struct(tsk);
	rcu_read_unlock();
	while (!mutex_trylock(&ctx->uring_lock)) {
		int seq = atomic_read(&rbk->wake_seq);

		if (tsk)
			io_rbk_boost(rbk, tsk, true);
		wait_event_hrtimeout(rbk->wait,
				     atomic_read(&rbk->wake_seq) != seq,
				     ns_to_ktime(50 * NSEC_PER_USEC));
	}
	if (tsk)
		put_task_struct(tsk);
}

/*
 * Stopping: hand redirected completions back to their poller tctx, which
 * also runs task_work while it cancels and exits. Caller set STOPPING.
 */
static void io_rbk_return(struct io_ringback *rbk)
{
	struct io_ring_ctx *ctx = rbk->ctx;
	struct llist_node *node;

	/* No producer can still be inside io_ringback_redirect(). */
	synchronize_rcu();
	if (mpscq_empty(&rbk->redirect))
		return;
	io_rbk_stop_lock(rbk);
	while ((node = mpscq_pop(&rbk->redirect, &rbk->redirect_head))) {
		struct io_kiocb *req = container_of(node, struct io_kiocb,
						    io_task_work.node);
		struct io_uring_task *tctx = req->tctx;
		bool empty;

		preempt_disable();
		empty = mpscq_push(&tctx->task_list, node);
		preempt_enable();
		if (empty)
			__set_notify_signal(tctx->task);
	}
	WARN_ON_ONCE(!mpscq_empty(&rbk->redirect));
	mutex_unlock(&ctx->uring_lock);
}

/*
 * Polled completions, from the owner's rescue (uring_lock held): drain the
 * polled requests left from POLL mode, also for owners that never enter.
 * Bounded to 200 us per rescue.
 */
static void io_rbk_reap_polled(struct io_ringback *rbk)
{
	struct io_ring_ctx *ctx = rbk->ctx;
	u64 end = ktime_get_ns() + 200 * NSEC_PER_USEC;

	while (!list_empty(&ctx->iopoll_list)) {
		io_ringback_owner_reap(ctx);
		/*
		 * Not requeued at once: that would keep the owner in
		 * task_work_run(). The poller and the safety timer retry.
		 */
		if (list_empty(&ctx->iopoll_list) || ktime_get_ns() > end)
			break;
		cpu_relax();
	}
}

static unsigned int io_sq_tw(int max_entries);

/*
 * OWNER mode, from the owner's rescue with uring_lock held and the poller off
 * CPU: run the read/write completions the poller left on its own task_work
 * list when it was preempted (later ones are redirected, io_ringback_redirect()).
 * IO_RBK_TWRUN makes this and the poller's io_sq_tw() the list's only
 * consumers in turn. Other task_work stays with the poller, as for redirect.
 */
static void io_rbk_steal_tw(struct io_ringback *rbk, struct task_struct *tsk)
{
	struct io_ring_ctx *ctx = rbk->ctx;
	struct io_uring_task *tctx = tsk->io_uring;
	struct io_tw_state ts = { .cancel = io_should_terminate_tw(ctx) };
	const struct cred *creds = NULL;
	struct llist_node *node;
	bool foreign = false;
	unsigned int n = 0;

	if (!READ_ONCE(ringback_steal) || !tctx ||
	    mpscq_empty(&tctx->task_list) ||
	    test_and_set_bit_lock(IO_RBK_TWRUN, &rbk->state))
		return;
	if (ctx->sq_creds != current_cred())
		creds = override_creds(ctx->sq_creds);
	while ((node = mpscq_pop(&tctx->task_list, &tctx->task_head))) {
		struct io_kiocb *req = container_of(node, struct io_kiocb,
						    io_task_work.node);

		if (req->ctx != ctx ||
		    req->io_task_work.func != io_req_rw_complete) {
			/* The poller's to run: requeue it for the poller. */
			preempt_disable();
			mpscq_push(&tctx->task_list, node);
			preempt_enable();
			foreign = true;
			break;
		}
		req->io_task_work.func((struct io_tw_req){req}, ts);
		n++;
	}
	if (creds)
		revert_creds(creds);
	clear_bit_unlock(IO_RBK_TWRUN, &rbk->state);
	if (n)
		atomic64_add(n, &rbk->stolen);
	if (foreign) {
		__set_notify_signal(tsk);
	} else if (!mpscq_empty(&tctx->task_list)) {
		/* A producer is between tail xchg and linking: come back later. */
		set_bit(IO_RBK_REQUEST, &rbk->state);
	}
}

/* The poller's task_work, unless the owner's rescue is running it. */
static unsigned int io_rbk_sq_tw(struct io_ringback *rbk, int max_entries,
				 bool wait)
{
	unsigned int count;

	if (!rbk)
		return io_sq_tw(max_entries);
	while (test_and_set_bit_lock(IO_RBK_TWRUN, &rbk->state)) {
		if (!wait)
			return 0;
		/* Exit: the owner's rescue holds it for one bounded run. */
		cond_resched();
	}
	count = io_sq_tw(max_entries);
	clear_bit_unlock(IO_RBK_TWRUN, &rbk->state);
	return count;
}

static void io_rbk_rescue(struct callback_head *cb)
{
	struct io_ringback *rbk = container_of(cb, struct io_ringback, work);
	struct io_ring_ctx *ctx = rbk->ctx;
	const struct cred *creds = NULL;
	struct task_struct *tsk;
	int ret = 0;

	clear_bit(IO_RBK_REQUEST, &rbk->state);
	/*
	 * Observe the poller only after consuming this notification generation.
	 */
	smp_mb__after_atomic();
	atomic64_inc(&rbk->rescues);
	rcu_read_lock();
	tsk = rcu_dereference(ctx->sq_data->thread);
	if (tsk)
		get_task_struct(tsk);
	rcu_read_unlock();
	if (!tsk)
		goto done;

	/* A boosted issuer can block inside an SQE, not just be preempted. */
	if (!io_rbk_runnable(tsk) && READ_ONCE(rbk->boosted)) {
		/*
		 * Publish before trylock so its holder cannot miss the deferred
		 * kick.
		 */
		set_bit(IO_RBK_DEMOTE, &rbk->state);
		/*
		 * Order the request against the holder's unlock/request
		 * recheck.
		 */
		smp_mb__after_atomic();
		if (mutex_trylock(&rbk->policy_lock)) {
			clear_bit(IO_RBK_DEMOTE, &rbk->state);
			io_rbk_restore(rbk, tsk);
			io_rbk_policy_unlock(rbk);
		}
	}
	if (test_bit(IO_RBK_STOPPING, &rbk->state) ||
	    (current->flags & PF_EXITING))
		goto put_task;
	if (!io_ringback_owner_mode(ctx) && !io_rbk_off_cpu(tsk)) {
		/*
		 * POLL again with the poller on CPU: finish redirected work and
		 * ring-local completions left from OWNER mode only.
		 */
		if (mpscq_empty(&rbk->redirect) &&
		    (!io_local_work_pending(ctx) || io_ringback_poller_runs(ctx)))
			goto put_task;
		if (!io_rbk_trylock_retry(rbk))
			goto put_task;
		io_rbk_run_redirect(rbk);
		io_rbk_run_local(ctx);
		io_submit_flush_completions(ctx);
		mutex_unlock(&ctx->uring_lock);
		goto put_task;
	}
	if (READ_ONCE(ringback_rt) != 3)
		io_rbk_boost(rbk, tsk, false);
	if (READ_ONCE(ringback_rt) == 2) {
		/*
		 * Baseline: block so that proxy execution can donate this CPU.
		 */
		mutex_lock(&ctx->uring_lock);
	} else if (!io_rbk_trylock_retry(rbk)) {
		/*
		 * RETRY is set: do not requeue into task_work_run()'s drain
		 * loop.
		 */
		atomic64_inc(&rbk->trylock_fail);
		goto put_task;
	}
	io_rbk_run_redirect(rbk);
	io_rbk_run_local(ctx);
	io_rbk_steal_tw(rbk, tsk);
	io_rbk_reap_polled(rbk);
	if (ctx->ringback_owner_tctx && ctx->ringback_owner == current &&
	    ctx->ringback_owner_tctx == current->io_uring &&
	    !percpu_ref_is_dying(&ctx->refs) &&
	    !(ctx->flags & IORING_SETUP_R_DISABLED)) {
		if (ctx->sq_creds != current_cred())
			creds = override_creds(ctx->sq_creds);
		ret = io_submit_sqes(ctx, ctx->sq_entries);
		if (creds)
			revert_creds(creds);
	}
	io_submit_flush_completions(ctx);
	mutex_unlock(&ctx->uring_lock);
	if (ret > 0) {
		atomic64_add(ret, &rbk->submitted);
		if (wq_has_sleeper(&ctx->sqo_sq_wait))
			wake_up(&ctx->sqo_sq_wait);
	}
put_task:
	put_task_struct(tsk);
done:
	clear_bit(IO_RBK_PENDING, &rbk->state);
	/* Do not lose a sched_out that raced with an already running rescue. */
	smp_mb__after_atomic();
	if (test_bit(IO_RBK_REQUEST, &rbk->state))
		io_rbk_queue(rbk);
	percpu_ref_put(&ctx->refs);
}

/*
 * OWNER mode, owner running: queue its completion task_work without an IPI
 * (TWA_SIGNAL_NO_IPI; TWA_RESUME would kick_process() too). Standard SQPOLL
 * apps enter on every submit while NEED_WAKEUP is set and run it on that
 * return; otherwise the timer sends the one IPI, kick_us later at most.
 */
bool io_ringback_lazy_kick(struct io_ring_ctx *ctx)
{
	struct io_ringback *rbk = ctx->ringback;

	/* A kick from the owner's own CPU sends no IPI: nothing to coalesce. */
	return READ_ONCE(ringback_kick_us) &&
	       test_bit(IO_RBK_OWNER, &rbk->state) &&
	       !test_bit(IO_RBK_STOPPING, &rbk->state) &&
	       task_curr(ctx->ringback_owner) &&
	       task_cpu(ctx->ringback_owner) != raw_smp_processor_id();
}

/*
 * Called after the NO_IPI task_work_add() set TIF_NOTIFY_SIGNAL. A producer
 * that finds KICK set relies on the pending timer, which clears KICK before
 * testing the flag: either it sees this flag or this producer re-arms.
 */
void io_ringback_arm_kick(struct io_ring_ctx *ctx)
{
	struct io_ringback *rbk = ctx->ringback;
	unsigned int us = max(1U, READ_ONCE(ringback_kick_us));

	if (!test_and_set_bit(IO_RBK_KICK, &rbk->state))
		hrtimer_start(&rbk->kick, us_to_ktime(us), HRTIMER_MODE_REL);
}

static enum hrtimer_restart io_rbk_kick_fn(struct hrtimer *timer)
{
	struct io_ringback *rbk = container_of(timer, struct io_ringback, kick);
	struct task_struct *owner = rbk->ctx->ringback_owner;

	clear_bit(IO_RBK_KICK, &rbk->state);
	/* Pairs with test_and_set_bit() in io_ringback_arm_kick(). */
	smp_mb__after_atomic();
	/*
	 * NO_IPI left TIF_NOTIFY_SIGNAL set if unhandled: only the IPI is
	 * missing.
	 */
	if (test_tsk_thread_flag(owner, TIF_NOTIFY_SIGNAL)) {
		atomic64_inc(&rbk->lazy_kicks);
		kick_process(owner);
	}
	return HRTIMER_NORESTART;
}

static void io_rbk_irq(struct irq_work *work)
{
	struct io_ringback *rbk = container_of(work, struct io_ringback, irq);
	struct io_ring_ctx *ctx = rbk->ctx;

	/* Wake an earlier completion even if the rescue callback is pending. */
	io_rbk_wake(rbk);
	if (test_bit(IO_RBK_STOPPING, &rbk->state) ||
	    test_and_set_bit(IO_RBK_PENDING, &rbk->state))
		return;
	if (!percpu_ref_tryget_live(&ctx->refs)) {
		clear_bit(IO_RBK_PENDING, &rbk->state);
		return;
	}
	if (task_work_add(ctx->ringback_owner, &rbk->work, TWA_SIGNAL)) {
		set_bit(IO_RBK_STOPPING, &rbk->state);
		clear_bit(IO_RBK_PENDING, &rbk->state);
		percpu_ref_put(&ctx->refs);
	}
}

#ifdef CONFIG_PREEMPT_NOTIFIERS
static void io_rbk_sched_out(struct preempt_notifier *pn,
			     struct task_struct *next)
{
	struct io_ringback *rbk = container_of(pn, struct io_ringback,
					       notifier);

	if (test_bit(IO_RBK_STOPPING, &rbk->state))
		return;
	if (!task_is_runnable(current)) {
		/*
		 * Voluntary sleep (empty SQ, park, a mutex): hand pending
		 * ring-local completions to the owner. Its barrier also orders
		 * a remote boost before the demotion decision below.
		 */
		io_rbk_handoff(rbk);
		if (READ_ONCE(rbk->boosted))
			io_rbk_queue(rbk);
		return;
	}
	/*
	 * Dual mode: the poller's own yield in OWNER mode; the mode is set
	 * already.
	 */
	if (READ_ONCE(rbk->yielding))
		return;
	atomic64_inc(&rbk->preempts);
	/* Approximate: in_tw also covers task_work run outside uring_lock. */
	if (READ_ONCE(rbk->in_batch) || READ_ONCE(rbk->in_tw))
		atomic64_inc(&rbk->preempt_locked);
	/*
	 * A2L-style: only the load policy switches; lock-debt repayment stays.
	 * An entry left to this poller while the policy was off is handed to
	 * the owner (wake only: no rescue submits under A2L).
	 */
	if (READ_ONCE(ringback_a2l_us)) {
		io_rbk_handoff(rbk);
		return;
	}
	io_rbk_to_owner(rbk, false);
}

/* Required: sched_in is called unconditionally. OWNER exits via hold time. */
static void io_rbk_sched_in(struct preempt_notifier *pn, int cpu)
{
}

static struct preempt_ops io_rbk_preempt_ops = {
	.sched_in = io_rbk_sched_in,
	.sched_out = io_rbk_sched_out,
};
#endif

int io_ringback_init(struct io_ring_ctx *ctx)
{
	struct io_ringback *rbk;
	unsigned int defer;

	if (!READ_ONCE(ringback_enable))
		return 0;
	if (ctx->flags & IORING_SETUP_ATTACH_WQ)
		return -EINVAL;
	if (!IS_ENABLED(CONFIG_PREEMPT_NOTIFIERS) ||
	    (ctx->flags & IORING_SETUP_IOPOLL))
		return -EOPNOTSUPP;
	rbk = kzalloc_obj(*rbk);
	if (!rbk)
		return -ENOMEM;
	rbk->ctx = ctx;
	rbk->idle_hint = -1;
	rbk->polled = READ_ONCE(ringback_polled);
	seqcount_init(&rbk->mode_seq);
	mutex_init(&rbk->policy_lock);
	init_waitqueue_head(&rbk->wait);
	init_irq_work(&rbk->irq, io_rbk_irq);
	init_irq_work(&rbk->wake_irq, io_rbk_wake_irq);
	init_task_work(&rbk->work, io_rbk_rescue);
	mpscq_init(&rbk->redirect, &rbk->redirect_head);
	hrtimer_setup(&rbk->kick, io_rbk_kick_fn, CLOCK_MONOTONIC,
		      HRTIMER_MODE_REL);
	hrtimer_setup(&rbk->safety, io_rbk_safety_fn, CLOCK_MONOTONIC,
		      HRTIMER_MODE_REL);
	raw_spin_lock_init(&rbk->safety_lock);
#ifdef CONFIG_PREEMPT_NOTIFIERS
	preempt_notifier_inc();
	preempt_notifier_init(&rbk->notifier, &io_rbk_preempt_ops);
#endif
	/*
	 * ringback_defer=2 is fixed at creation, before the poller starts:
	 * every CQE of the ring is then posted under uring_lock by one of its
	 * two runners, so mode 3 may also drop completion_lock.
	 */
	defer = READ_ONCE(ringback_defer);
	if (defer >= 2) {
		ctx->int_flags |= IO_RING_F_RINGBACK_LOCAL;
		if (defer >= 3)
			ctx->int_flags |= IO_RING_F_LOCKLESS_CQ;
	}
	ctx->ringback = rbk;
	return 0;
}

void io_ringback_stop(struct io_ring_ctx *ctx)
{
	struct io_ringback *rbk = ctx->ringback;
	struct task_struct *tsk = NULL;

	if (!rbk)
		return;
	set_bit(IO_RBK_STOPPING, &rbk->state);
	/*
	 * An arming that saw !STOPPING completes under safety_lock before this;
	 * a later one sees STOPPING. Then nothing re-arms the timer.
	 */
	raw_spin_lock_irq(&rbk->safety_lock);
	raw_spin_unlock_irq(&rbk->safety_lock);
	hrtimer_cancel(&rbk->safety);
	irq_work_sync(&rbk->irq);
	irq_work_sync(&rbk->wake_irq);
	io_rbk_return(rbk);
	/* After the RCU grace period in io_rbk_return(): nobody re-arms it. */
	hrtimer_cancel(&rbk->kick);
	/*
	 * A creator that went to sleep leaving the list to the poller just
	 * before STOPPING: wake it; the preference is false now.
	 */
	if (io_local_work_pending(ctx))
		wake_up_state(ctx->ringback_owner, TASK_INTERRUPTIBLE);
	if (ctx->sq_data) {
		rcu_read_lock();
		tsk = rcu_dereference(ctx->sq_data->thread);
		if (tsk)
			get_task_struct(tsk);
		rcu_read_unlock();
	}
	if (tsk) {
		mutex_lock(&rbk->policy_lock);
		io_rbk_restore(rbk, tsk);
		io_rbk_policy_unlock(rbk);
		put_task_struct(tsk);
	}
	if (ctx->sq_data)
		wake_up_all(&ctx->sq_data->wait);
	if (task_work_cancel(ctx->ringback_owner, &rbk->work)) {
		clear_bit(IO_RBK_PENDING, &rbk->state);
		percpu_ref_put(&ctx->refs);
	}
}

void io_ringback_free(struct io_ring_ctx *ctx)
{
	if (!ctx->ringback)
		return;
	/* SQ thread has exited/unregistered; no notifier can queue irq_work. */
	io_ringback_stop(ctx);
#ifdef CONFIG_PREEMPT_NOTIFIERS
	preempt_notifier_dec();
#endif
	kfree(ctx->ringback);
}

void io_ringback_fdinfo(struct io_ring_ctx *ctx, struct seq_file *m)
{
	struct io_ringback *rbk = ctx->ringback;
	u64 boosted_ns, owner_ns, rt_max, hist[8];
	unsigned int seq;

	if (!rbk)
		return;
	mutex_lock(&rbk->policy_lock);
	boosted_ns = atomic64_read(&rbk->boosted_ns);
	if (rbk->boosted)
		boosted_ns += ktime_get_ns() - rbk->boost_start;
	rt_max = rbk->boost_rt_max;
	memcpy(hist, rbk->boost_rt_hist, sizeof(hist));
	io_rbk_policy_unlock(rbk);
	do {
		seq = read_seqcount_begin(&rbk->mode_seq);
		owner_ns = atomic64_read(&rbk->owner_ns);
		if (test_bit(IO_RBK_OWNER, &rbk->state))
			owner_ns += ktime_get_ns() -
				    READ_ONCE(rbk->owner_start);
	} while (read_seqcount_retry(&rbk->mode_seq, seq));
	seq_printf(m, "SqSafe:\tpreempts=%lld rescues=%lld submitted=%lld trylock_fail=%lld boosts=%lld boosted_ns=%llu poll_to_owner=%lld owner_to_poll=%lld owner_ns=%llu owner_submitted=%lld preempt_locked=%lld redirected=%lld boosted_runtime_ns=%lld lazy_kicks=%lld vol_to_owner=%lld boost_rt_max_ns=%llu boost_rt_hist=%llu/%llu/%llu/%llu/%llu/%llu/%llu/%llu poll_submitted=%lld owner_wakes=%lld defer_rescues=%lld defer_spin=%d dual_submitted=%lld mwaits=%lld a2l_offs=%lld a2l_ons=%lld lazy_skips=%lld safety_rescues=%lld mwait_kicks=%lld yields=%lld idle_wakes=%lld idle_hits=%lld idle_misses=%lld polled_issued=%lld polled_reaped_by_owner=%lld idle_flaps=%lld handoffs=%lld stolen=%lld\n",
		   atomic64_read(&rbk->preempts), atomic64_read(&rbk->rescues),
		   atomic64_read(&rbk->submitted),
		   atomic64_read(&rbk->trylock_fail),
		   atomic64_read(&rbk->boosts), boosted_ns,
		   atomic64_read(&rbk->poll_to_owner),
		   atomic64_read(&rbk->owner_to_poll), owner_ns,
		   atomic64_read(&rbk->owner_submitted),
		   atomic64_read(&rbk->preempt_locked),
		   atomic64_read(&rbk->redirected),
		   atomic64_read(&rbk->boosted_runtime_ns),
		   atomic64_read(&rbk->lazy_kicks),
		   atomic64_read(&rbk->vol_to_owner), rt_max, hist[0], hist[1],
		   hist[2], hist[3], hist[4], hist[5], hist[6], hist[7],
		   atomic64_read(&rbk->poll_submitted),
		   atomic64_read(&rbk->owner_wakes),
		   atomic64_read(&rbk->defer_rescues),
		   READ_ONCE(rbk->defer_spin),
		   atomic64_read(&rbk->dual_submitted),
		   atomic64_read(&rbk->mwaits), atomic64_read(&rbk->a2l_offs),
		   atomic64_read(&rbk->a2l_ons),
		   atomic64_read(&rbk->lazy_skips),
		   atomic64_read(&rbk->safety_rescues),
		   atomic64_read(&rbk->mwait_kicks),
		   atomic64_read(&rbk->yields),
		   atomic64_read(&rbk->idle_wakes),
		   atomic64_read(&rbk->idle_hits),
		   atomic64_read(&rbk->idle_misses),
		   atomic64_read(&rbk->polled_issued),
		   atomic64_read(&rbk->polled_reaped_by_owner),
		   atomic64_read(&rbk->idle_flaps),
		   atomic64_read(&rbk->handoffs),
		   atomic64_read(&rbk->stolen));
	seq_printf(m, "SqK12:\ton=%d entries=%lld idle_ns=%lld inflight_block=%lld setattr_fail=%lld exit_sq=%lld exit_tw=%lld exit_event=%lld exit_owner=%lld exit_timeout=%lld lease_expired=%lld\n",
		   READ_ONCE(rbk->idlepoll_on),
		   atomic64_read(&rbk->idlepoll_entries),
		   atomic64_read(&rbk->idlepoll_idle_ns),
		   atomic64_read(&rbk->idlepoll_inflight_block),
		   atomic64_read(&rbk->idlepoll_setattr_fail),
		   atomic64_read(&rbk->idlepoll_exit[IO_RBK_IDLEPOLL_EXIT_SQ]),
		   atomic64_read(&rbk->idlepoll_exit[IO_RBK_IDLEPOLL_EXIT_TW]),
		   atomic64_read(&rbk->idlepoll_exit[IO_RBK_IDLEPOLL_EXIT_EVENT]),
		   atomic64_read(&rbk->idlepoll_exit[IO_RBK_IDLEPOLL_EXIT_OWNER]),
		   atomic64_read(&rbk->idlepoll_exit[IO_RBK_IDLEPOLL_EXIT_TIMEOUT]),
		   atomic64_read(&rbk->lease_expired));
}

/*
 * End of a uring_lock section of the idle-class poller. Under full preemption
 * a fair wakeup preempts an idle entity at once; lazy preemption only flags
 * the poller (resched_curr_lazy) until the next tick. Give the CPU up here when
 * another task is runnable, as the idle class promises and as the removed soft
 * ceiling's lowering used to do.
 */
static void io_rbk_yield_if_contended(void)
{
	if (io_sq_contended())
		schedule();
}

static bool io_rbk_lock(struct io_ringback *rbk)
{
	/* Only the completion drain may end a switch-debt boost. */
	if (unlikely(READ_ONCE(rbk->boosted)))
		return false;
	/* Close the acquired-lock/visible-holder preemption window. */
	preempt_disable();
	if (!test_bit(IO_RBK_STOPPING, &rbk->state) &&
	    !rbk->lease_grace && !io_rbk_policy_fixed() && io_sq_contended())
		io_rbk_to_owner(rbk, true);
	if (test_bit(IO_RBK_OWNER, &rbk->state)) {
		preempt_enable();
		return false;
	}
	if (!mutex_trylock(&rbk->ctx->uring_lock)) {
		preempt_enable();
		return false;
	}
	WRITE_ONCE(rbk->in_batch, true);
	preempt_enable();
	return true;
}

/*
 * The poller released uring_lock: retry a waiting owner or failed rescue.
 * Nothing waits unless RETRY is set; skip the wakeup on the common path.
 */
static void io_rbk_released(struct io_ringback *rbk)
{
	/*
	 * Pair with io_rbk_trylock_retry(): it publishes RETRY and then
	 * retries the lock; this orders the unlock before the RETRY test, so
	 * either its retry sees the lock free or this sees RETRY. (Missing a
	 * wakeup would only cost latency: the waiter retries every 50 us.)
	 */
	smp_mb();
	if (likely(!test_bit(IO_RBK_RETRY, &rbk->state)))
		return;
	io_rbk_wake(rbk);
	if (test_and_clear_bit(IO_RBK_RETRY, &rbk->state))
		io_rbk_queue(rbk);
}

static void io_rbk_unlock(struct io_ringback *rbk)
{
	mutex_unlock(&rbk->ctx->uring_lock);
	/*
	 * Preempted in between: at most one needless debt check, never a lost
	 * one.
	 */
	WRITE_ONCE(rbk->in_batch, false);
	/* Keep a debt boost through io_sq_tw(), not merely the batch unlock. */
	io_rbk_released(rbk);
	io_rbk_yield_if_contended();
}

void io_sq_thread_unpark(struct io_sq_data *sqd)
	__releases(&sqd->lock)
{
	WARN_ON_ONCE(sqpoll_task_locked(sqd) == current);

	/*
	 * Do the dance but not conditional clear_bit() because it'd race with
	 * other threads incrementing park_pending and setting the bit.
	 */
	clear_bit(IO_SQ_THREAD_SHOULD_PARK, &sqd->state);
	if (atomic_dec_return(&sqd->park_pending))
		set_bit(IO_SQ_THREAD_SHOULD_PARK, &sqd->state);
	mutex_unlock(&sqd->lock);
	wake_up(&sqd->wait);
}

/*
 * MWAIT: a poller in MWAIT holds sqd->lock and is running; only an IPI ends its
 * wait, so kick it before the lock, not after. The event bit is set already.
 * Not conditional on the parameter: a wait entered before it was cleared
 * still has to end.
 */
static void io_sq_mwait_kick(struct io_sq_data *sqd)
{
	struct task_struct *tsk;

	if (!sqd->ringback)
		return;
	rcu_read_lock();
	tsk = rcu_dereference(sqd->thread);
	if (tsk)
		kick_process(tsk);
	rcu_read_unlock();
}

void io_sq_thread_park(struct io_sq_data *sqd)
	__acquires(&sqd->lock)
{
	struct task_struct *tsk;

	atomic_inc(&sqd->park_pending);
	set_bit(IO_SQ_THREAD_SHOULD_PARK, &sqd->state);
	io_sq_mwait_kick(sqd);
	mutex_lock(&sqd->lock);

	tsk = sqpoll_task_locked(sqd);
	if (tsk) {
		WARN_ON_ONCE(tsk == current);
		wake_up_process(tsk);
	}
}

void io_sq_thread_stop(struct io_sq_data *sqd)
{
	struct task_struct *tsk;

	WARN_ON_ONCE(test_bit(IO_SQ_THREAD_SHOULD_STOP, &sqd->state));

	set_bit(IO_SQ_THREAD_SHOULD_STOP, &sqd->state);
	io_sq_mwait_kick(sqd);
	mutex_lock(&sqd->lock);
	tsk = sqpoll_task_locked(sqd);
	if (tsk) {
		WARN_ON_ONCE(tsk == current);
		wake_up_process(tsk);
	}
	mutex_unlock(&sqd->lock);
	wait_for_completion(&sqd->exited);
}

void io_put_sq_data(struct io_sq_data *sqd)
{
	if (refcount_dec_and_test(&sqd->refs)) {
		WARN_ON_ONCE(atomic_read(&sqd->park_pending));

		io_sq_thread_stop(sqd);
		kfree(sqd);
	}
}

static __cold void io_sqd_update_thread_idle(struct io_sq_data *sqd)
{
	struct io_ring_ctx *ctx;
	unsigned sq_thread_idle = 0;

	list_for_each_entry(ctx, &sqd->ctx_list, sqd_list)
		sq_thread_idle = max(sq_thread_idle, ctx->sq_thread_idle);
	sqd->sq_thread_idle = sq_thread_idle;
}

void io_sq_thread_finish(struct io_ring_ctx *ctx)
{
	struct io_sq_data *sqd = ctx->sq_data;

	if (sqd) {
		io_sq_thread_park(sqd);
		list_del_init(&ctx->sqd_list);
		io_sqd_update_thread_idle(sqd);
		io_sq_thread_unpark(sqd);

		io_put_sq_data(sqd);
		ctx->sq_data = NULL;
	}
}

static struct io_sq_data *io_attach_sq_data(struct io_uring_params *p)
{
	struct io_ring_ctx *ctx_attach;
	struct io_sq_data *sqd;
	CLASS(fd, f)(p->wq_fd);

	if (fd_empty(f))
		return ERR_PTR(-ENXIO);
	if (!io_is_uring_fops(fd_file(f)))
		return ERR_PTR(-EINVAL);

	ctx_attach = fd_file(f)->private_data;
	sqd = ctx_attach->sq_data;
	if (!sqd)
		return ERR_PTR(-EINVAL);
	/*
	 * A RingBack poller must stay exclusive even if the parameter changes.
	 */
	if (sqd->ringback)
		return ERR_PTR(-EINVAL);
	if (sqd->task_tgid != current->tgid)
		return ERR_PTR(-EPERM);

	refcount_inc(&sqd->refs);
	return sqd;
}

static struct io_sq_data *io_get_sq_data(struct io_uring_params *p,
					 bool *attached)
{
	struct io_sq_data *sqd;

	*attached = false;
	if (p->flags & IORING_SETUP_ATTACH_WQ) {
		sqd = io_attach_sq_data(p);
		if (!IS_ERR(sqd)) {
			*attached = true;
			return sqd;
		}
		/* fall through for EPERM case, setup new sqd/task */
		if (PTR_ERR(sqd) != -EPERM)
			return sqd;
	}

	sqd = kzalloc_obj(*sqd);
	if (!sqd)
		return ERR_PTR(-ENOMEM);

	atomic_set(&sqd->park_pending, 0);
	refcount_set(&sqd->refs, 1);
	INIT_LIST_HEAD(&sqd->ctx_list);
	mutex_init(&sqd->lock);
	init_waitqueue_head(&sqd->wait);
	init_completion(&sqd->exited);
	return sqd;
}

static inline bool io_sqd_events_pending(struct io_sq_data *sqd)
{
	return READ_ONCE(sqd->state);
}

struct io_sq_time {
	bool started;
	u64 usec;
};

u64 io_sq_cpu_usec(struct task_struct *tsk)
{
	u64 utime, stime;

	task_cputime_adjusted(tsk, &utime, &stime);
	do_div(stime, 1000);
	return stime;
}

static void io_sq_update_worktime(struct io_sq_data *sqd, struct io_sq_time *ist)
{
	if (!ist->started)
		return;
	ist->started = false;
	sqd->work_time += io_sq_cpu_usec(current) - ist->usec;
}

static void io_sq_start_worktime(struct io_sq_time *ist)
{
	if (ist->started)
		return;
	ist->started = true;
	ist->usec = io_sq_cpu_usec(current);
}

static unsigned int io_sqpoll_sq_entries(struct io_ring_ctx *ctx)
{
	if (!ctx->ringback_owner)
		return io_sqring_entries(ctx);
	/*
	 * The owner may consume too, so this unlocked count is only advisory;
	 * io_submit_sqes() rechecks cached_sq_head under uring_lock. Read the
	 * private cached head as upstream does, not the shared ring head line.
	 */
	return min(smp_load_acquire(&ctx->rings->sq.tail) -
		   READ_ONCE(ctx->cached_sq_head), ctx->sq_entries);
}

static int __io_sq_thread(struct io_ring_ctx *ctx, struct io_sq_data *sqd,
			  bool cap_entries, struct io_sq_time *ist)
{
	unsigned int to_submit;
	int ret = 0;

	if (io_ringback_owner_mode(ctx))
		return 0;
	to_submit = io_sqpoll_sq_entries(ctx);
	/*
	 * A switch can owe at most this one new batch, plus older completions.
	 */
	if ((cap_entries || ctx->ringback || READ_ONCE(sqpoll_cap_all)) &&
	    to_submit > IORING_SQPOLL_CAP_ENTRIES_VALUE)
		to_submit = IORING_SQPOLL_CAP_ENTRIES_VALUE;

	if (to_submit || !list_empty(&ctx->iopoll_list)) {
		const struct cred *creds = NULL;

		io_sq_start_worktime(ist);

		if (ctx->sq_creds != current_cred())
			creds = override_creds(ctx->sq_creds);

		if (ctx->ringback) {
			if (!io_rbk_lock(ctx->ringback)) {
				if (creds)
					revert_creds(creds);
				return 0;
			}
		} else {
			mutex_lock(&ctx->uring_lock);
		}
		if (!list_empty(&ctx->iopoll_list))
			io_do_iopoll(ctx, true);

		/*
		 * Don't submit if refs are dying, good for io_uring_register(),
		 * but also it is relied upon by io_ring_exit_work()
		 */
		if (to_submit && likely(!percpu_ref_is_dying(&ctx->refs)) &&
		    !(ctx->flags & IORING_SETUP_R_DISABLED))
			ret = io_submit_sqes(ctx, to_submit);
		if (ctx->ringback) {
			io_rbk_unlock(ctx->ringback);
			if (ret > 0)
				atomic64_add(ret,
					     &ctx->ringback->poll_submitted);
		} else {
			mutex_unlock(&ctx->uring_lock);
		}

		if (to_submit && wq_has_sleeper(&ctx->sqo_sq_wait))
			wake_up(&ctx->sqo_sq_wait);
		if (creds)
			revert_creds(creds);
	}

	return ret;
}

static bool io_sqd_handle_event(struct io_sq_data *sqd)
{
	bool did_sig = false;
	struct ksignal ksig;

	if (test_bit(IO_SQ_THREAD_SHOULD_PARK, &sqd->state) ||
	    signal_pending(current)) {
		mutex_unlock(&sqd->lock);
		if (signal_pending(current))
			did_sig = get_signal(&ksig);
		wait_event(sqd->wait, !atomic_read(&sqd->park_pending));
		mutex_lock(&sqd->lock);
		sqd->sq_cpu = raw_smp_processor_id();
	}
	return did_sig || test_bit(IO_SQ_THREAD_SHOULD_STOP, &sqd->state);
}

/*
 * Run task_work, processing no more than max_entries at a time. If more
 * than that is pending, it simply stays on the queue for the next run.
 */
static unsigned int io_sq_tw(int max_entries)
{
	struct io_uring_task *tctx = current->io_uring;
	unsigned int count = 0;

	tctx_task_work_run(tctx, max_entries, &count);
	if (task_work_pending(current))
		task_work_run();
	return count;
}

static bool io_sq_tw_pending(void)
{
	struct io_uring_task *tctx = current->io_uring;

	return !mpscq_empty(&tctx->task_list);
}

/*
 * Only POLL -> OWNER creates debt: at most one capped issuing batch and
 * the poller-homed requests already in flight, including their task_work.
 * OWNER never starts a batch. Once its old completion work is drained, the
 * poller holds no uring_lock or completion work needed by the owner. Device
 * I/O can finish later; it retains its original tctx and wakes debt rescue.
 */
static void io_rbk_repay(struct io_ringback *rbk)
{
	struct io_uring_task *tctx = current->io_uring;

	if (!io_ringback_owner_mode(rbk->ctx))
		return;
	mutex_lock(&rbk->policy_lock);
	if (!io_sq_tw_pending() && !task_work_pending(current)) {
		/*
		 * Only the poller reads its own cached_refs for the final test.
		 */
		if (percpu_counter_sum(&tctx->inflight) == tctx->cached_refs)
			clear_bit(IO_RBK_DEBT, &rbk->state);
		/*
		 * Do not retain a CPU boost while waiting for device
		 * completion.
		 */
		io_rbk_restore(rbk, current);
	}
	io_rbk_policy_unlock(rbk);
}

/*
 * OWNER mode is a lease: when pending SQEs or redirected completions make no
 * progress for ringback_lease_us, the poller takes them back. Progress then
 * never waits on the owner longer than the lease beyond upstream.
 */
static bool io_rbk_owner_stalled(struct io_ringback *rbk, u64 now)
{
	unsigned int lease = READ_ONCE(ringback_lease_us);
	unsigned int head = READ_ONCE(rbk->ctx->rings->sq.head);
	bool pending = io_sqpoll_sq_entries(rbk->ctx) ||
		       !mpscq_empty(&rbk->redirect);

	if (!lease || !pending || head != rbk->stall_head) {
		rbk->stall_head = head;
		rbk->stall_start = 0;
		return false;
	}
	if (!rbk->stall_start) {
		rbk->stall_start = now;
		return false;
	}
	return now - rbk->stall_start >= (u64)lease * NSEC_PER_USEC;
}

static u64 io_rbk_check_ns(void);

static bool io_rbk_try_poll(struct io_ringback *rbk)
{
	bool resume = false, stalled, contended;
	u64 now;

	mutex_lock(&rbk->policy_lock);
	if (rbk->boosted)
		goto out;
	preempt_disable();
	now = ktime_get_ns();
	contended = io_sq_contended();
	if (contended) {
		u64 base = io_rbk_check_ns();
		u64 cap = max_t(u64, base,
				(u64)READ_ONCE(ringback_owner_max_us) *
				NSEC_PER_USEC);

		rbk->idle_checks = 0;
		/*
		 * Back off while the CPU stays contended: the wake itself
		 * costs.
		 */
		rbk->owner_backoff_ns =
			min(max(rbk->owner_backoff_ns, base) * 2, cap);
	} else if (rbk->owner_backoff_ns) {
		/*
		 * First uncontended check after a backoff: recheck at the base
		 * period.
		 */
		rbk->owner_backoff_ns = 0;
		rbk->idle_checks = 1;
		rbk->idle_start = now;
		rbk->idle_cpu = raw_smp_processor_id();
	} else if (!rbk->idle_checks ||
		   rbk->idle_cpu != raw_smp_processor_id()) {
		rbk->idle_checks = 1;
		rbk->idle_start = now;
		rbk->idle_cpu = raw_smp_processor_id();
	} else if (rbk->idle_checks < UINT_MAX) {
		rbk->idle_checks++;
	}
	stalled = io_rbk_owner_stalled(rbk, now);
	/*
	 * Dual mode: one uncontended check is the whole condition, no hold
	 * time; a contended check keeps OWNER (the caller yields the CPU),
	 * otherwise the mode would flip on every loop iteration spent on a
	 * contended CPU. A2L-style: resume only once the owner submitted a
	 * period's worth of SQEs; contention is irrelevant.
	 */
	if (READ_ONCE(ringback_a2l_us)) {
		stalled = false;
		if (READ_ONCE(rbk->a2l_resume)) {
			WRITE_ONCE(rbk->a2l_resume, false);
			atomic64_inc(&rbk->a2l_ons);
			/*
			 * A fresh sampling period starts with the resumed
			 * polling.
			 */
			rbk->a2l_period_start = 0;
			rbk->a2l_depth_max = 0;
			resume = true;
		}
	} else if (READ_ONCE(ringback_dual)) {
		resume = rbk->idle_checks > 0;
	}
	/*
	 * Parked OWNER mode: an owner enter found an idle CPU and woke the
	 * poller. Resume at once, without hold time, if the CPU it runs on is
	 * uncontended; otherwise a later scan or the safety wake retries.
	 */
	if (io_rbk_policy_fixed()) {
		/* A2L-style: a hint from before the policy was set is stale. */
		if (READ_ONCE(rbk->idle_hint) >= 0)
			WRITE_ONCE(rbk->idle_hint, -1);
	} else if (READ_ONCE(rbk->idle_hint) >= 0 &&
		   xchg(&rbk->idle_hint, -1) >= 0) {
		if (contended || io_rbk_cpu_napping(raw_smp_processor_id())) {
			atomic64_inc(&rbk->idle_misses);
		} else {
			atomic64_inc(&rbk->idle_hits);
			rbk->hint_resume_ns = now;
			resume = true;
		}
	}
	if (test_bit(IO_RBK_STOPPING, &rbk->state) || stalled || resume ||
	    (!io_rbk_policy_fixed() &&
	     rbk->idle_checks >= io_rbk_checks() &&
	     now - rbk->idle_start >=
	     (u64)READ_ONCE(ringback_hold_us) * NSEC_PER_USEC)) {
		if (stalled) {
			atomic64_inc(&rbk->lease_expired);
			rbk->stall_start = 0;
			rbk->lease_grace = true;
		}
		write_seqcount_begin(&rbk->mode_seq);
		atomic64_add(now - rbk->owner_start, &rbk->owner_ns);
		atomic64_inc(&rbk->owner_to_poll);
		clear_bit(IO_RBK_DEBT, &rbk->state);
		clear_bit(IO_RBK_OWNER, &rbk->state);
		WRITE_ONCE(rbk->ctx->ringback_owner_mode, false);
		atomic_andnot(IORING_SQ_NEED_WAKEUP,
			      &rbk->ctx->rings->sq_flags);
		/*
		 * Same tail-publication handshake as the upstream sleep path.
		 */
		smp_mb__after_atomic();
		write_seqcount_end(&rbk->mode_seq);
		resume = true;
	}
	preempt_enable();
out:
	io_rbk_policy_unlock(rbk);
	return resume;
}

/* OWNER-mode recheck period: spread the checks over the hold time. */
static u64 io_rbk_check_ns(void)
{
	unsigned int us = READ_ONCE(ringback_hold_us) /
			  io_rbk_checks();

	return (u64)clamp(us, 200U, 1000U) * NSEC_PER_USEC;
}

/*
 * Polled completions in OWNER mode: polled requests complete only when polled,
 * and an owner blocked outside io_uring (for instance in a freeze waiting for
 * such a write) never reaps them. The poller reaps them whenever it runs but
 * submits nothing; the lock section is held like a task_work batch.
 */
static void io_rbk_poller_reap(struct io_ringback *rbk)
{
	struct io_ring_ctx *ctx = rbk->ctx;

	if (list_empty_careful(&ctx->iopoll_list))
		return;
	WRITE_ONCE(rbk->in_tw, true);
	if (mutex_trylock(&ctx->uring_lock)) {
		if (!list_empty(&ctx->iopoll_list))
			io_do_iopoll(ctx, true);
		mutex_unlock(&ctx->uring_lock);
		io_rbk_released(rbk);
	}
	WRITE_ONCE(rbk->in_tw, false);
	io_rbk_yield_if_contended();
}

static void io_rbk_owner_wait(struct io_sq_data *sqd, struct io_ringback *rbk)
{
	unsigned int head = READ_ONCE(rbk->ctx->rings->sq.head);
	u64 period = max(io_rbk_check_ns(), rbk->owner_backoff_ns);
	ktime_t to;
	DEFINE_WAIT(wait);

	/*
	 * A2L-style: the stopped poller samples the owner's load every period.
	 */
	if (READ_ONCE(ringback_a2l_us))
		period = (u64)READ_ONCE(ringback_a2l_us) * NSEC_PER_USEC;
	/* Parked OWNER mode: only the safety wake is timed. */
	else if (READ_ONCE(ringback_idlewake))
		period = max_t(u64, period,
			       (u64)READ_ONCE(ringback_owner_safety_us) *
			       NSEC_PER_USEC);
	/* Polled requests in flight: come back soon to reap them. */
	if (!list_empty_careful(&rbk->ctx->iopoll_list))
		period = min_t(u64, period, 50 * NSEC_PER_USEC);

	/*
	 * Ring-local completions: completions waiting on ->work_list with no
	 * run by the owner since the previous check. Have the owner's rescue
	 * run them; an owner that keeps leaving them is reaping without
	 * entering.
	 */
	if (io_local_work_pending(rbk->ctx)) {
		unsigned long runs = READ_ONCE(rbk->ctx->ringback_local_runs) -
				     READ_ONCE(rbk->defer_rescue_runs);

		if (runs == rbk->defer_last_runs) {
			atomic64_inc(&rbk->defer_rescues);
			/*
			 * Only an owner on CPU that leaves them is reaping by
			 * spinning; a descheduled one is just not running.
			 */
			if (task_curr(rbk->ctx->ringback_owner) &&
			    ++rbk->defer_stuck >= 3)
				WRITE_ONCE(rbk->defer_spin, true);
			io_rbk_queue(rbk);
		} else {
			rbk->defer_stuck = 0;
		}
		rbk->defer_last_runs = runs;
	} else {
		rbk->defer_stuck = 0;
	}

	/*
	 * Also rescue applications which publish SQEs without entering: SQEs
	 * pending and no SQ progress since the previous check. An entering
	 * owner submits by itself; do not race it with rescue IPIs.
	 */
	if (io_sqpoll_sq_entries(rbk->ctx) && head == rbk->last_head)
		io_rbk_queue(rbk);
	rbk->last_head = head;
	/* Retry redirected work whose owner rescue lost a trylock. */
	if (!mpscq_empty(&rbk->redirect))
		io_rbk_queue(rbk);

	prepare_to_wait(&sqd->wait, &wait, TASK_INTERRUPTIBLE);
	if (!io_sqd_events_pending(sqd) && !io_sq_tw_pending() &&
	    !task_work_pending(current) &&
	    !test_bit(IO_RBK_STOPPING, &rbk->state)) {
		mutex_unlock(&sqd->lock);
		/*
		 * Recheck contention/hold time without spinning on a shared
		 * CPU.
		 */
		to = ns_to_ktime(period);
		schedule_hrtimeout_range(&to, max_t(u64, 50 * NSEC_PER_USEC,
						    period / 8),
					 HRTIMER_MODE_REL);
		atomic64_inc(&rbk->owner_wakes);
		mutex_lock(&sqd->lock);
		sqd->sq_cpu = raw_smp_processor_id();
	}
	finish_wait(&sqd->wait, &wait);
}

/*
 * MWAIT: wait for the next SQ tail store in C1 with MONITOR/MWAIT instead of
 * spinning (x86 only), as the kernel's own mwait_idle() does. The wait ends
 * with a store to the tail's line or with an interrupt: the tick, a reschedule,
 * or the IPI that producers send when they find in_mwait set (completions to
 * ->work_list or to the poller's task_work, park/stop). Interrupts are off
 * from the flag store to the sti;mwait pair, so an IPI sent after the flag is
 * delivered into the MWAIT and not before it, and the full barrier orders the
 * flag before the checks, against the producers' push before their flag load.
 * Returns at once if anything is pending; the caller rechecks everything.
 */
static void io_rbk_wait_tail(struct io_sq_data *sqd, struct io_ringback *rbk)
{
#ifdef CONFIG_X86
	struct io_ring_ctx *ctx = rbk->ctx;
	const void *addr = &ctx->rings->sq.tail;

	if (!boot_cpu_has(X86_FEATURE_MWAIT) ||
	    boot_cpu_has_bug(X86_BUG_MONITOR) ||
	    !list_is_singular(&sqd->ctx_list)) {
		cpu_relax();
		return;
	}
	local_irq_disable();
	WRITE_ONCE(rbk->in_mwait, true);
	/* Flag before the checks; pairs with the producers' push, then load. */
	smp_mb();
	alternative_input("", "clflush (%[addr])", X86_BUG_CLFLUSH_MONITOR,
			  [addr] "a" (addr));
	__monitor(addr, 0, 0);
	if (io_sqpoll_sq_entries(ctx) || io_sq_tw_pending() ||
	    task_work_pending(current) || io_sqd_events_pending(sqd) ||
	    io_local_work_pending(ctx) || !mpscq_empty(&rbk->redirect) ||
	    !list_empty(&ctx->iopoll_list) ||
	    need_resched() || tif_test_bit(TIF_NEED_RESCHED_LAZY) ||
	    signal_pending(current)) {
		local_irq_enable();
	} else {
		x86_idle_clear_cpu_buffers();
		/* C1 without extension bits: no CPUID.05H:ECX dependency. */
		__sti_mwait(0, 0);
		atomic64_inc(&rbk->mwaits);
		/* sti left interrupts on untraced; restore the traced state. */
		raw_local_irq_disable();
		local_irq_enable();
	}
	WRITE_ONCE(rbk->in_mwait, false);
#else
	cpu_relax();
#endif
}

/*
 * A2L-style policy, POLL mode: track the deepest SQ seen in the sampling
 * period and stop polling (OWNER, NEED_WAKEUP, the app submits inline) after a
 * period below the off threshold. The signal is the application's queue, as in
 * A2L: a starved poller meets a deep SQ and therefore keeps polling.
 * Resumption is decided in io_rbk_try_poll() from the owner's batch size.
 */
static void io_sq_a2l_account(struct io_ringback *rbk, unsigned int depth)
{
	u64 period = (u64)READ_ONCE(ringback_a2l_us) * NSEC_PER_USEC;
	u64 now = ktime_get_ns();

	rbk->a2l_depth_max = max(rbk->a2l_depth_max, depth);
	if (!rbk->a2l_period_start) {
		rbk->a2l_period_start = now;
		return;
	}
	if (now - rbk->a2l_period_start < period)
		return;
	if (rbk->a2l_depth_max < READ_ONCE(ringback_a2l_off) &&
	    !test_bit(IO_RBK_STOPPING, &rbk->state)) {
		WRITE_ONCE(rbk->a2l_resume, false);
		atomic64_inc(&rbk->a2l_offs);
		preempt_disable();
		io_rbk_to_owner(rbk, true);
		preempt_enable();
	}
	rbk->a2l_depth_max = 0;
	rbk->a2l_period_start = now;
}

/*
 * Idle-class empty polling: the poller may poll as SCHED_IDLE only while it
 * owes nothing, i.e. no SQEs, task_work, events, redirected work or OWNER mode,
 * and none of its own requests in flight (their completions would run as its
 * task_work; with ringback_idlepoll_inflight, completions after a preemption
 * are left to the OWNER redirect instead). Only a single-ring sqd without NAPI
 * or IOPOLL qualifies.
 */
static bool io_rbk_idlepoll_can_enter(struct io_sq_data *sqd,
				      struct io_ringback *rbk)
{
	struct io_uring_task *tctx = current->io_uring;
	struct io_ring_ctx *ctx = rbk->ctx;

	if (!list_is_singular(&sqd->ctx_list) ||
	    (ctx->flags & IORING_SETUP_IOPOLL) || io_napi(ctx) ||
	    !list_empty_careful(&ctx->iopoll_list))
		return false;
	if (test_bit(IO_RBK_STOPPING, &rbk->state) ||
	    test_bit(IO_RBK_OWNER, &rbk->state) ||
	    !mpscq_empty(&rbk->redirect))
		return false;
	if (io_sqd_events_pending(sqd) || signal_pending(current) ||
	    io_sq_tw_pending() || task_work_pending(current) ||
	    io_sqpoll_sq_entries(ctx) || io_local_work_pending(ctx))
		return false;
	if (!READ_ONCE(ringback_idlepoll_inflight) &&
	    percpu_counter_sum(&tctx->inflight) >
	    READ_ONCE(tctx->cached_refs)) {
		atomic64_inc(&rbk->idlepoll_inflight_block);
		return false;
	}
	return true;
}

static int io_rbk_idlepoll_exit_reason(struct io_sq_data *sqd,
				       struct io_ringback *rbk,
				       unsigned long timeout)
{
	if (io_sqpoll_sq_entries(rbk->ctx))
		return IO_RBK_IDLEPOLL_EXIT_SQ;
	if (io_sq_tw_pending() || task_work_pending(current) ||
	    io_local_work_pending(rbk->ctx) ||
	    !list_empty_careful(&rbk->ctx->iopoll_list))
		return IO_RBK_IDLEPOLL_EXIT_TW;
	if (io_sqd_events_pending(sqd) || signal_pending(current))
		return IO_RBK_IDLEPOLL_EXIT_EVENT;
	if (test_bit(IO_RBK_OWNER, &rbk->state) ||
	    test_bit(IO_RBK_STOPPING, &rbk->state) ||
	    !mpscq_empty(&rbk->redirect))
		return IO_RBK_IDLEPOLL_EXIT_OWNER;
	if (time_after(jiffies, timeout))
		return IO_RBK_IDLEPOLL_EXIT_TIMEOUT;
	return -1;
}

/*
 * Poll the empty ring as SCHED_IDLE. sqd->lock is dropped so that a parker or
 * registrant never waits behind a starved poller, and a ctx reference keeps
 * the rings mapped meanwhile. The working policy is restored before the ring
 * is touched again or the poller sleeps. Being preempted here switches to
 * OWNER through sched_out, without debt: nothing is held.
 */
static void io_rbk_idlepoll_idle(struct io_sq_data *sqd,
				 struct io_ringback *rbk,
				 unsigned long timeout)
{
	struct sched_attr idle = rbk->idlepoll_saved;
	struct io_ring_ctx *ctx = rbk->ctx;
	int reason;
	u64 start;

	idle.sched_policy = SCHED_IDLE;
	idle.sched_runtime = 0;
	percpu_ref_get(&ctx->refs);
	mutex_unlock(&sqd->lock);
	if (sched_setattr_nocheck(current, &idle)) {
		atomic64_inc(&rbk->idlepoll_setattr_fail);
		goto relock;
	}
	atomic64_inc(&rbk->idlepoll_entries);
	start = ktime_get_ns();
	while ((reason = io_rbk_idlepoll_exit_reason(sqd, rbk, timeout)) < 0) {
		/* Yield to a wakee at once, also when it only asked lazily. */
		if (tif_need_resched() || tif_test_bit(TIF_NEED_RESCHED_LAZY))
			schedule();
		else if (READ_ONCE(ringback_mwait))
			io_rbk_wait_tail(sqd, rbk);
		else
			cpu_relax();
	}
	if (WARN_ON_ONCE(sched_setattr_nocheck(current,
					       &rbk->idlepoll_saved))) {
		atomic64_inc(&rbk->idlepoll_setattr_fail);
		rbk->idlepoll_on = false;
	}
	atomic64_add(ktime_get_ns() - start, &rbk->idlepoll_idle_ns);
	atomic64_inc(&rbk->idlepoll_exit[reason]);
relock:
	mutex_lock(&sqd->lock);
	sqd->sq_cpu = raw_smp_processor_id();
	percpu_ref_put(&ctx->refs);
}

/* Returns true after an idle-class poll, so the caller restarts its loop. */
static bool io_rbk_idlepoll_try(struct io_sq_data *sqd, struct io_ringback *rbk,
				bool busy, unsigned long timeout)
{
	u64 now;

	if (busy) {
		rbk->idlepoll_empty_start = 0;
		return false;
	}
	now = ktime_get_ns();
	if (!rbk->idlepoll_empty_start) {
		rbk->idlepoll_empty_start = now;
		rbk->idlepoll_next_check = now +
			(u64)READ_ONCE(ringback_idlepoll_us) * NSEC_PER_USEC;
		return false;
	}
	if (now < rbk->idlepoll_next_check)
		return false;
	if (!io_rbk_idlepoll_can_enter(sqd, rbk)) {
		/* percpu_counter_sum() is not cheap: recheck every 10 us. */
		rbk->idlepoll_next_check = now + 10 * NSEC_PER_USEC;
		return false;
	}
	io_rbk_idlepoll_idle(sqd, rbk, timeout);
	rbk->idlepoll_empty_start = 0;
	return true;
}

static int io_sq_thread(void *data)
{
	struct io_sq_data *sqd = data;
	struct io_ringback *rbk = sqd->ringback;
	struct io_ring_ctx *ctx;
	unsigned long timeout = 0;
	char buf[TASK_COMM_LEN] = {};
	DEFINE_WAIT(wait);

	/* offload context creation failed, just exit */
	if (!current->io_uring) {
		mutex_lock(&sqd->lock);
		rcu_assign_pointer(sqd->thread, NULL);
		put_task_struct(current);
		mutex_unlock(&sqd->lock);
		goto err_out;
	}

	snprintf(buf, sizeof(buf), "iou-sqp-%d", sqd->task_pid);
	set_task_comm(current, buf);

	/* reset to our pid after we've set task_comm, for fdinfo */
	sqd->task_pid = current->pid;

	if (sqd->sq_cpu != -1) {
		set_cpus_allowed_ptr(current, cpumask_of(sqd->sq_cpu));
	} else {
		set_cpus_allowed_ptr(current, cpu_online_mask);
		sqd->sq_cpu = raw_smp_processor_id();
	}

	/*
	 * Force audit context to get setup, in case we do prep side async
	 * operations that would trigger an audit call before any issue side
	 * audit has been done.
	 */
	audit_uring_entry(IORING_OP_NOP);
	audit_uring_exit(true, 0);

	mutex_lock(&sqd->lock);
#ifdef CONFIG_PREEMPT_NOTIFIERS
	if (rbk) {
		preempt_notifier_register(&rbk->notifier);
		/* The handoffs are armed: the preference may now be true. */
		smp_store_release(&rbk->ready, true);
	}
#endif
	/*
	 * Custom slice: a slice longer than the neighbours' lets their wakeups
	 * preempt the poller (PREEMPT_SHORT) while its weight stays the same.
	 * Set before the idle-poll snapshot and the boost save, which restore
	 * it.
	 */
	if (rbk && READ_ONCE(ringback_slice_us) &&
	    (current->policy == SCHED_NORMAL ||
	     current->policy == SCHED_BATCH)) {
		struct sched_attr attr = {
			.size = sizeof(attr),
			.sched_policy = current->policy,
			.sched_nice = task_nice(current),
			.sched_flags = current->sched_reset_on_fork ?
				       SCHED_FLAG_RESET_ON_FORK : 0,
			.sched_runtime = (u64)READ_ONCE(ringback_slice_us) *
					 NSEC_PER_USEC,
		};

		sched_setattr_nocheck(current, &attr);
	}
	/*
	 * Idle-class empty polling only for a NORMAL/BATCH poller (an IDLE one
	 * could never return) and without lock-debt boosting, whose restore
	 * would fight the idle-poll one.
	 */
	if (rbk && READ_ONCE(ringback_idlepoll) && !READ_ONCE(ringback_idle) &&
	    READ_ONCE(ringback_rt) >= 2 &&
	    (current->policy == SCHED_NORMAL ||
	     current->policy == SCHED_BATCH)) {
		rbk->idlepoll_saved = (struct sched_attr) {
			.size = sizeof(rbk->idlepoll_saved),
			.sched_policy = current->policy,
			.sched_nice = task_nice(current),
			.sched_flags = current->sched_reset_on_fork ?
				       SCHED_FLAG_RESET_ON_FORK : 0,
			.sched_runtime = current->se.custom_slice ?
					 current->se.slice : 0,
		};
		rbk->idlepoll_on = true;
	}
	if (rbk && READ_ONCE(ringback_idle)) {
		struct sched_attr attr = {
			.size = sizeof(attr),
			.sched_policy = SCHED_IDLE,
			.sched_nice = task_nice(current),
			.sched_flags = current->sched_reset_on_fork ?
				       SCHED_FLAG_RESET_ON_FORK : 0,
		};

		sched_setattr_nocheck(current, &attr);
	}
	while (1) {
		bool cap_entries, sqt_spin = false;
		unsigned int tw;
		struct io_sq_time ist = { };

		if (io_sqd_events_pending(sqd) || signal_pending(current)) {
			if (io_sqd_handle_event(sqd))
				break;
			timeout = jiffies + sqd->sq_thread_idle;
		}

		if (rbk && !test_bit(IO_RBK_STOPPING, &rbk->state) &&
		    !rbk->lease_grace && !io_rbk_policy_fixed()) {
			preempt_disable();
			if (io_sq_contended())
				io_rbk_to_owner(rbk, true);
			preempt_enable();
		}
		cap_entries = !list_is_singular(&sqd->ctx_list);
		/*
		 * A2L-style: sample the application's queue before consuming
		 * it.
		 */
		if (rbk && READ_ONCE(ringback_a2l_us) &&
		    !io_ringback_owner_mode(rbk->ctx))
			io_sq_a2l_account(rbk, io_sqpoll_sq_entries(rbk->ctx));
		list_for_each_entry(ctx, &sqd->ctx_list, sqd_list) {
			int ret;

			kcov_remote_start_common(ctx->kcov_handle);
			ret = __io_sq_thread(ctx, sqd, cap_entries, &ist);

			if (!sqt_spin && (ret > 0 || !list_empty(&ctx->iopoll_list)))
				sqt_spin = true;
			kcov_remote_stop();
		}
		if (rbk)
			rbk->lease_grace = false;
		if (rbk)
			WRITE_ONCE(rbk->in_tw, true);
		tw = io_rbk_sq_tw(rbk, IORING_TW_CAP_ENTRIES_VALUE, false);
		if (tw)
			sqt_spin = true;
		if (rbk) {
			WRITE_ONCE(rbk->in_tw, false);
			/*
			 * That task_work ran under uring_lock: retry a waiting
			 * owner.
			 */
			if (tw) {
				io_rbk_released(rbk);
				io_rbk_yield_if_contended();
			}
			io_rbk_repay(rbk);
			/*
			 * Back in POLL: any uring_lock holder may consume
			 * leftover redirected work, including after a failed
			 * owner rescue.
			 */
			if (!mpscq_empty(&rbk->redirect) &&
			    !io_ringback_owner_mode(rbk->ctx)) {
				if (mutex_trylock(&rbk->ctx->uring_lock)) {
					io_rbk_run_redirect(rbk);
					io_submit_flush_completions(rbk->ctx);
					mutex_unlock(&rbk->ctx->uring_lock);
					io_rbk_released(rbk);
					io_rbk_yield_if_contended();
					sqt_spin = true;
				}
			}
			/*
			 * ->work_list in POLL mode: with ringback_defer=2 the
			 * poller runs it, as task_work held under uring_lock
			 * (debt if preempted); a ringback_defer=1 leftover from
			 * OWNER goes to the owner's rescue.
			 */
			if (unlikely(io_local_work_pending(rbk->ctx)) &&
			    !io_ringback_owner_mode(rbk->ctx)) {
				/*
				 * RINGBACK_LOCAL is set once, before the ring
				 * is used.
				 */
				if (data_race(rbk->ctx->int_flags) &
				    IO_RING_F_RINGBACK_LOCAL) {
					/*
					 * An owner holding uring_lock (enter or
					 * wait) runs the list itself; retry on
					 * the next loop.
					 */
					WRITE_ONCE(rbk->in_tw, true);
					if (mutex_trylock(&rbk->ctx->uring_lock)) {
						(void)io_run_local_work_locked(rbk->ctx, 0);
						mutex_unlock(&rbk->ctx->uring_lock);
						io_rbk_released(rbk);
						io_rbk_yield_if_contended();
					}
					WRITE_ONCE(rbk->in_tw, false);
					sqt_spin = true;
				} else {
					io_rbk_queue(rbk);
				}
			}
		}

		list_for_each_entry(ctx, &sqd->ctx_list, sqd_list) {
			if (io_ringback_owner_mode(ctx))
				continue;
			if (io_napi(ctx)) {
				io_sq_start_worktime(&ist);
				io_napi_sqpoll_busy_poll(ctx);
			}
		}

		io_sq_update_worktime(sqd, &ist);

		if (rbk && io_ringback_owner_mode(rbk->ctx)) {
			/*
			 * Idle-class polling counts only continuous empty
			 * polling in POLL.
			 */
			rbk->idlepoll_empty_start = 0;
			if (!io_rbk_try_poll(rbk)) {
				io_rbk_poller_reap(rbk);
				if (READ_ONCE(ringback_dual)) {
					/*
					 * Dual mode: no timed wait and no
					 * periodic check in OWNER mode. Give
					 * the contended CPU up but stay
					 * runnable: the scheduler picks an
					 * idle-class poller again as soon as
					 * the CPU is free, and the safety timer
					 * rescues meanwhile.
					 */
					atomic64_inc(&rbk->yields);
					WRITE_ONCE(rbk->yielding, true);
					mutex_unlock(&sqd->lock);
					yield();
					mutex_lock(&sqd->lock);
					WRITE_ONCE(rbk->yielding, false);
					sqd->sq_cpu = raw_smp_processor_id();
				} else {
					io_rbk_owner_wait(sqd, rbk);
				}
				timeout = jiffies + sqd->sq_thread_idle;
				continue;
			}
			/*
			 * Recheck the tail after clearing NEED_WAKEUP and the
			 * barrier.
			 */
			sqt_spin |= io_sqpoll_sq_entries(rbk->ctx) != 0;
			timeout = jiffies + sqd->sq_thread_idle;
		}
		if (sqt_spin || !time_after(jiffies, timeout)) {
			if (sqt_spin)
				timeout = jiffies + sqd->sq_thread_idle;
			if (rbk && rbk->idlepoll_on &&
			    io_rbk_idlepoll_try(sqd, rbk, sqt_spin, timeout))
				continue;
			if (unlikely(need_resched())) {
				mutex_unlock(&sqd->lock);
				cond_resched();
				mutex_lock(&sqd->lock);
				sqd->sq_cpu = raw_smp_processor_id();
			}
			/*
			 * MWAIT: an empty iteration waits for the tail store in
			 * C1.
			 */
			if (rbk && !sqt_spin && READ_ONCE(ringback_mwait) &&
			    !io_ringback_owner_mode(rbk->ctx))
				io_rbk_wait_tail(sqd, rbk);
			continue;
		}

		prepare_to_wait(&sqd->wait, &wait, TASK_INTERRUPTIBLE);
		if (!io_sqd_events_pending(sqd) && !io_sq_tw_pending() &&
		    !(rbk && !mpscq_empty(&rbk->redirect)) &&
		    !(rbk && io_local_work_pending(rbk->ctx))) {
			bool needs_sched = true;

			list_for_each_entry(ctx, &sqd->ctx_list, sqd_list) {
				atomic_or(IORING_SQ_NEED_WAKEUP,
						&ctx->rings->sq_flags);
				if ((ctx->flags & IORING_SETUP_IOPOLL ||
				     ctx->ringback) &&
				    !list_empty(&ctx->iopoll_list)) {
					needs_sched = false;
					break;
				}

				/*
				 * Ensure the store of the wakeup flag is not
				 * reordered with the load of the SQ tail
				 */
				smp_mb__after_atomic();

				if (io_sqpoll_sq_entries(ctx)) {
					needs_sched = false;
					break;
				}
			}

			if (needs_sched) {
				mutex_unlock(&sqd->lock);
				schedule();
				mutex_lock(&sqd->lock);
				sqd->sq_cpu = raw_smp_processor_id();
			}
			list_for_each_entry(ctx, &sqd->ctx_list, sqd_list) {
				if (ctx->ringback) {
					preempt_disable();
					if (!io_ringback_owner_mode(ctx))
						atomic_andnot(IORING_SQ_NEED_WAKEUP,
							      &ctx->rings->sq_flags);
					preempt_enable();
				} else {
					atomic_andnot(IORING_SQ_NEED_WAKEUP,
						      &ctx->rings->sq_flags);
				}
			}
		}

		finish_wait(&sqd->wait, &wait);
		timeout = jiffies + sqd->sq_thread_idle;
	}

	if (rbk) {
		set_bit(IO_RBK_STOPPING, &rbk->state);
#ifdef CONFIG_PREEMPT_NOTIFIERS
		preempt_notifier_unregister(&rbk->notifier);
#endif
		WRITE_ONCE(rbk->ready, false);
		mutex_lock(&rbk->policy_lock);
		io_rbk_restore(rbk, current);
		io_rbk_policy_unlock(rbk);
		io_rbk_return(rbk);
	}
	if (io_sq_tw_pending())
		io_rbk_sq_tw(rbk, UINT_MAX, true);

	io_uring_cancel_generic(true, sqd);
	if (rbk) {
		struct io_ring_ctx *rctx = rbk->ctx;

		/*
		 * Terminal drain of the ring-local completions left to this
		 * poller. STOPPING stops new ones (io_ringback_defer_ok()) and
		 * the grace period in io_rbk_return() ended every producer that
		 * may have left one, so the list is finite. Still the poller
		 * (sqd->thread), so still authorized; the owner may never run
		 * them: a creator spinning on the CQ does not wait, and an enter
		 * after the thread is gone returns -EOWNERDEAD.
		 */
		if (io_local_work_pending(rctx) && io_allowed_defer_tw_run(rctx)) {
			mutex_lock(&rctx->uring_lock);
			while (io_local_work_pending(rctx))
				(void)io_run_local_work_locked(rctx, INT_MAX);
			mutex_unlock(&rctx->uring_lock);
		}
		wake_up_state(rctx->ringback_owner, TASK_INTERRUPTIBLE);
	}
	rcu_assign_pointer(sqd->thread, NULL);
	put_task_struct(current);
	list_for_each_entry(ctx, &sqd->ctx_list, sqd_list)
		atomic_or(IORING_SQ_NEED_WAKEUP, &ctx->rings->sq_flags);
	io_run_task_work();
	mutex_unlock(&sqd->lock);
err_out:
	complete(&sqd->exited);
	do_exit(0);
}

void io_sqpoll_wait_sq(struct io_ring_ctx *ctx)
{
	DEFINE_WAIT(wait);

	do {
		if (!io_sqring_full(ctx))
			break;
		prepare_to_wait(&ctx->sqo_sq_wait, &wait, TASK_INTERRUPTIBLE);

		if (!io_sqring_full(ctx))
			break;
		schedule();
	} while (!signal_pending(current));

	finish_wait(&ctx->sqo_sq_wait, &wait);
}

__cold int io_sq_offload_create(struct io_ring_ctx *ctx,
				struct io_uring_params *p)
{
	int ret;

	/* Retain compatibility with failing for an invalid attach attempt */
	if ((ctx->flags & (IORING_SETUP_ATTACH_WQ | IORING_SETUP_SQPOLL)) ==
				IORING_SETUP_ATTACH_WQ) {
		CLASS(fd, f)(p->wq_fd);
		if (fd_empty(f))
			return -ENXIO;
		if (!io_is_uring_fops(fd_file(f)))
			return -EINVAL;
	}
	if (ctx->flags & IORING_SETUP_SQPOLL) {
		struct io_uring_task *tctx;
		struct task_struct *tsk;
		struct io_sq_data *sqd;
		bool attached;

		ret = security_uring_sqpoll();
		if (ret)
			return ret;

		sqd = io_get_sq_data(p, &attached);
		if (IS_ERR(sqd)) {
			ret = PTR_ERR(sqd);
			goto err;
		}
		if (!attached)
			sqd->ringback = ctx->ringback;

		ctx->sq_creds = get_current_cred();
		ctx->sq_data = sqd;
		ctx->sq_thread_idle = msecs_to_jiffies(p->sq_thread_idle);
		if (!ctx->sq_thread_idle)
			ctx->sq_thread_idle = HZ;

		io_sq_thread_park(sqd);
		list_add(&ctx->sqd_list, &sqd->ctx_list);
		io_sqd_update_thread_idle(sqd);
		/* don't attach to a dying SQPOLL thread, would be racy */
		ret = (attached && !sqd->thread) ? -ENXIO : 0;
		io_sq_thread_unpark(sqd);

		if (ret < 0)
			goto err;
		if (attached)
			return 0;

		if (p->flags & IORING_SETUP_SQ_AFF) {
			cpumask_var_t allowed_mask;
			int cpu = p->sq_thread_cpu;

			ret = -EINVAL;
			if (cpu >= nr_cpu_ids || !cpu_online(cpu))
				goto err_sqpoll;
			ret = -ENOMEM;
			if (!alloc_cpumask_var(&allowed_mask, GFP_KERNEL))
				goto err_sqpoll;
			ret = -EINVAL;
			cpuset_cpus_allowed(current, allowed_mask);
			if (!cpumask_test_cpu(cpu, allowed_mask)) {
				free_cpumask_var(allowed_mask);
				goto err_sqpoll;
			}
			free_cpumask_var(allowed_mask);
			sqd->sq_cpu = cpu;
		} else {
			sqd->sq_cpu = -1;
		}

		sqd->task_pid = current->pid;
		sqd->task_tgid = current->tgid;
		tsk = create_io_thread(io_sq_thread, sqd, NUMA_NO_NODE);
		if (IS_ERR(tsk)) {
			ret = PTR_ERR(tsk);
			goto err_sqpoll;
		}

		mutex_lock(&sqd->lock);
		rcu_assign_pointer(sqd->thread, tsk);
		mutex_unlock(&sqd->lock);

		ret = 0;
		get_task_struct(tsk);
		tctx = io_uring_alloc_task_context(tsk, ctx);
		if (!IS_ERR(tctx))
			tsk->io_uring = tctx;
		else
			ret = PTR_ERR(tctx);
		wake_up_new_task(tsk);
		if (ret)
			goto err;
	} else if (p->flags & IORING_SETUP_SQ_AFF) {
		/* Can't have SQ_AFF without SQPOLL */
		ret = -EINVAL;
		goto err;
	}
	return 0;
err_sqpoll:
	complete(&ctx->sq_data->exited);
err:
	io_sq_thread_finish(ctx);
	return ret;
}

__cold int io_sqpoll_wq_cpu_affinity(struct io_ring_ctx *ctx,
				     cpumask_var_t mask)
{
	struct io_sq_data *sqd = ctx->sq_data;
	int ret = -EINVAL;

	if (sqd) {
		struct task_struct *tsk;

		io_sq_thread_park(sqd);
		/* Don't set affinity for a dying thread */
		tsk = sqpoll_task_locked(sqd);
		if (tsk)
			ret = io_wq_cpu_affinity(tsk->io_uring, mask);
		io_sq_thread_unpark(sqd);
	}

	return ret;
}
