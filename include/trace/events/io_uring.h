/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM io_uring

#if !defined(_TRACE_IO_URING_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_IO_URING_H

#include <linux/tracepoint.h>
#include <uapi/linux/io_uring.h>
#include <linux/io_uring_types.h>
#include <linux/io_uring.h>

struct io_wq_work;

/**
 * io_uring_create - called after a new io_uring context was prepared
 *
 * @fd:		corresponding file descriptor
 * @ctx:	pointer to a ring context structure
 * @sq_entries:	actual SQ size
 * @cq_entries:	actual CQ size
 * @flags:	SQ ring flags, provided to io_uring_setup(2)
 *
 * Allows to trace io_uring creation and provide pointer to a context, that can
 * be used later to find correlated events.
 */
TRACE_EVENT(io_uring_create,

	TP_PROTO(int fd, void *ctx, u32 sq_entries, u32 cq_entries, u32 flags),

	TP_ARGS(fd, ctx, sq_entries, cq_entries, flags),

	TP_STRUCT__entry (
		__field(  int,		fd		)
		__field(  void *,	ctx		)
		__field(  u32,		sq_entries	)
		__field(  u32,		cq_entries	)
		__field(  u32,		flags		)
	),

	TP_fast_assign(
		__entry->fd		= fd;
		__entry->ctx		= ctx;
		__entry->sq_entries	= sq_entries;
		__entry->cq_entries	= cq_entries;
		__entry->flags		= flags;
	),

	TP_printk("ring %p, fd %d sq size %d, cq size %d, flags 0x%x",
			  __entry->ctx, __entry->fd, __entry->sq_entries,
			  __entry->cq_entries, __entry->flags)
);

/**
 * io_uring_register - called after a buffer/file/eventfd was successfully
 * 					   registered for a ring
 *
 * @ctx:		pointer to a ring context structure
 * @opcode:		describes which operation to perform
 * @nr_user_files:	number of registered files
 * @nr_user_bufs:	number of registered buffers
 * @ret:		return code
 *
 * Allows to trace fixed files/buffers, that could be registered to
 * avoid an overhead of getting references to them for every operation. This
 * event, together with io_uring_file_get, can provide a full picture of how
 * much overhead one can reduce via fixing.
 */
TRACE_EVENT(io_uring_register,

	TP_PROTO(void *ctx, unsigned opcode, unsigned nr_files,
			 unsigned nr_bufs, long ret),

	TP_ARGS(ctx, opcode, nr_files, nr_bufs, ret),

	TP_STRUCT__entry (
		__field(  void *,	ctx	)
		__field(  unsigned,	opcode	)
		__field(  unsigned,	nr_files)
		__field(  unsigned,	nr_bufs	)
		__field(  long,		ret	)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->opcode		= opcode;
		__entry->nr_files	= nr_files;
		__entry->nr_bufs	= nr_bufs;
		__entry->ret		= ret;
	),

	TP_printk("ring %p, opcode %d, nr_user_files %d, nr_user_bufs %d, "
			  "ret %ld",
			  __entry->ctx, __entry->opcode, __entry->nr_files,
			  __entry->nr_bufs, __entry->ret)
);

/**
 * io_uring_file_get - called before getting references to an SQE file
 *
 * @req:	pointer to a submitted request
 * @fd:		SQE file descriptor
 *
 * Allows to trace out how often an SQE file reference is obtained, which can
 * help figuring out if it makes sense to use fixed files, or check that fixed
 * files are used correctly.
 */
TRACE_EVENT(io_uring_file_get,

	TP_PROTO(struct io_kiocb *req, int fd),

	TP_ARGS(req, fd),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  void *,	req		)
		__field(  u64,		user_data	)
		__field(  int,		fd		)
	),

	TP_fast_assign(
		__entry->ctx		= req->ctx;
		__entry->req		= req;
		__entry->user_data	= req->cqe.user_data;
		__entry->fd		= fd;
	),

	TP_printk("ring %p, req %p, user_data 0x%llx, fd %d",
		__entry->ctx, __entry->req, __entry->user_data, __entry->fd)
);

/**
 * io_uring_queue_async_work - called before submitting a new async work
 *
 * @req:	pointer to a submitted request
 * @hashed:	whether async work is hashed
 *
 * Allows to trace asynchronous work submission.
 */
TRACE_EVENT(io_uring_queue_async_work,

	TP_PROTO(struct io_kiocb *req, bool hashed),

	TP_ARGS(req, hashed),

	TP_STRUCT__entry (
		__field(  void *,			ctx		)
		__field(  void *,			req		)
		__field(  u64,				user_data	)
		__field(  u8,				opcode		)
		__field(  unsigned long long,		flags		)
		__field(  struct io_wq_work *,		work		)
		__field(  bool,				hashed		)

		__string( op_str, io_uring_get_opcode(req->opcode)	)
	),

	TP_fast_assign(
		__entry->ctx		= req->ctx;
		__entry->req		= req;
		__entry->user_data	= req->cqe.user_data;
		__entry->flags		= (__force unsigned long long) req->flags;
		__entry->opcode		= req->opcode;
		__entry->work		= &req->work;
		__entry->hashed		= hashed;

		__assign_str(op_str);
	),

	TP_printk("ring %p, request %p, user_data 0x%llx, opcode %s, flags 0x%llx, %s queue, work %p",
		__entry->ctx, __entry->req, __entry->user_data,
		__get_str(op_str), __entry->flags,
		__entry->hashed ? "hashed" : "normal", __entry->work)
);

/**
 * io_uring_defer - called when an io_uring request is deferred
 *
 * @req:	pointer to a deferred request
 *
 * Allows to track deferred requests, to get an insight about what requests are
 * not started immediately.
 */
TRACE_EVENT(io_uring_defer,

	TP_PROTO(struct io_kiocb *req),

	TP_ARGS(req),

	TP_STRUCT__entry (
		__field(  void *,		ctx	)
		__field(  void *,		req	)
		__field(  unsigned long long,	data	)
		__field(  u8,			opcode	)

		__string( op_str, io_uring_get_opcode(req->opcode) )
	),

	TP_fast_assign(
		__entry->ctx	= req->ctx;
		__entry->req	= req;
		__entry->data	= req->cqe.user_data;
		__entry->opcode	= req->opcode;

		__assign_str(op_str);
	),

	TP_printk("ring %p, request %p, user_data 0x%llx, opcode %s",
		__entry->ctx, __entry->req, __entry->data,
		__get_str(op_str))
);

/**
 * io_uring_link - called before the io_uring request added into link_list of
 * 		   another request
 *
 * @req:		pointer to a linked request
 * @target_req:		pointer to a previous request, that would contain @req
 *
 * Allows to track linked requests, to understand dependencies between requests
 * and how does it influence their execution flow.
 */
TRACE_EVENT(io_uring_link,

	TP_PROTO(struct io_kiocb *req, struct io_kiocb *target_req),

	TP_ARGS(req, target_req),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  void *,	req		)
		__field(  void *,	target_req	)
	),

	TP_fast_assign(
		__entry->ctx		= req->ctx;
		__entry->req		= req;
		__entry->target_req	= target_req;
	),

	TP_printk("ring %p, request %p linked after %p",
			  __entry->ctx, __entry->req, __entry->target_req)
);

/**
 * io_uring_cqring_wait - called before start waiting for an available CQE
 *
 * @ctx:		pointer to a ring context structure
 * @min_events:	minimal number of events to wait for
 *
 * Allows to track waiting for CQE, so that we can e.g. troubleshoot
 * situations, when an application wants to wait for an event, that never
 * comes.
 */
TRACE_EVENT(io_uring_cqring_wait,

	TP_PROTO(void *ctx, int min_events),

	TP_ARGS(ctx, min_events),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  int,		min_events	)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->min_events	= min_events;
	),

	TP_printk("ring %p, min_events %d", __entry->ctx, __entry->min_events)
);

/**
 * io_uring_fail_link - called before failing a linked request
 *
 * @req:	request, which links were cancelled
 * @link:	cancelled link
 *
 * Allows to track linked requests cancellation, to see not only that some work
 * was cancelled, but also which request was the reason.
 */
TRACE_EVENT(io_uring_fail_link,

	TP_PROTO(struct io_kiocb *req, struct io_kiocb *link),

	TP_ARGS(req, link),

	TP_STRUCT__entry (
		__field(  void *,		ctx		)
		__field(  void *,		req		)
		__field(  unsigned long long,	user_data	)
		__field(  u8,			opcode		)
		__field(  void *,		link		)

		__string( op_str, io_uring_get_opcode(req->opcode) )
	),

	TP_fast_assign(
		__entry->ctx		= req->ctx;
		__entry->req		= req;
		__entry->user_data	= req->cqe.user_data;
		__entry->opcode		= req->opcode;
		__entry->link		= link;

		__assign_str(op_str);
	),

	TP_printk("ring %p, request %p, user_data 0x%llx, opcode %s, link %p",
		__entry->ctx, __entry->req, __entry->user_data,
		__get_str(op_str), __entry->link)
);

/**
 * io_uring_complete - called when completing an SQE
 *
 * @ctx:		pointer to a ring context structure
 * @req:		(optional) pointer to a submitted request
 * @cqe:		pointer to the filled in CQE being posted
 */
TRACE_EVENT(io_uring_complete,

TP_PROTO(struct io_ring_ctx *ctx, void *req, struct io_uring_cqe *cqe),

	TP_ARGS(ctx, req, cqe),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  void *,	req		)
		__field(  u64,		user_data	)
		__field(  int,		res		)
		__field(  unsigned,	cflags		)
		__field(  u64,		extra1		)
		__field(  u64,		extra2		)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->req		= req;
		__entry->user_data	= cqe->user_data;
		__entry->res		= cqe->res;
		__entry->cflags		= cqe->flags;
		__entry->extra1		= ctx->flags & IORING_SETUP_CQE32 || cqe->flags & IORING_CQE_F_32 ? cqe->big_cqe[0] : 0;
		__entry->extra2		= ctx->flags & IORING_SETUP_CQE32 || cqe->flags & IORING_CQE_F_32 ? cqe->big_cqe[1] : 0;
	),

	TP_printk("ring %p, req %p, user_data 0x%llx, result %d, cflags 0x%x "
		  "extra1 %llu extra2 %llu ",
		__entry->ctx, __entry->req,
		__entry->user_data,
		__entry->res, __entry->cflags,
		(unsigned long long) __entry->extra1,
		(unsigned long long) __entry->extra2)
);

/**
 * io_uring_submit_req - called before submitting a request
 *
 * @req:		pointer to a submitted request
 *
 * Allows to track SQE submitting, to understand what was the source of it, SQ
 * thread or io_uring_enter call.
 */
TRACE_EVENT(io_uring_submit_req,

	TP_PROTO(struct io_kiocb *req),

	TP_ARGS(req),

	TP_STRUCT__entry (
		__field(  void *,		ctx		)
		__field(  void *,		req		)
		__field(  unsigned long long,	user_data	)
		__field(  u8,			opcode		)
		__field(  unsigned long long,	flags		)
		__field(  bool,			sq_thread	)

		__string( op_str, io_uring_get_opcode(req->opcode) )
	),

	TP_fast_assign(
		__entry->ctx		= req->ctx;
		__entry->req		= req;
		__entry->user_data	= req->cqe.user_data;
		__entry->opcode		= req->opcode;
		__entry->flags		= (__force unsigned long long) req->flags;
		__entry->sq_thread	= req->ctx->flags & IORING_SETUP_SQPOLL;

		__assign_str(op_str);
	),

	TP_printk("ring %p, req %p, user_data 0x%llx, opcode %s, flags 0x%llx, "
		  "sq_thread %d", __entry->ctx, __entry->req,
		  __entry->user_data, __get_str(op_str), __entry->flags,
		  __entry->sq_thread)
);

/*
 * io_uring_poll_arm - called after arming a poll wait if successful
 *
 * @req:		pointer to the armed request
 * @mask:		request poll events mask
 * @events:		registered events of interest
 *
 * Allows to track which fds are waiting for and what are the events of
 * interest.
 */
TRACE_EVENT(io_uring_poll_arm,

	TP_PROTO(struct io_kiocb *req, int mask, int events),

	TP_ARGS(req, mask, events),

	TP_STRUCT__entry (
		__field(  void *,		ctx		)
		__field(  void *,		req		)
		__field(  unsigned long long,	user_data	)
		__field(  u8,			opcode		)
		__field(  int,			mask		)
		__field(  int,			events		)

		__string( op_str, io_uring_get_opcode(req->opcode) )
	),

	TP_fast_assign(
		__entry->ctx		= req->ctx;
		__entry->req		= req;
		__entry->user_data	= req->cqe.user_data;
		__entry->opcode		= req->opcode;
		__entry->mask		= mask;
		__entry->events		= events;

		__assign_str(op_str);
	),

	TP_printk("ring %p, req %p, user_data 0x%llx, opcode %s, mask 0x%x, events 0x%x",
		  __entry->ctx, __entry->req, __entry->user_data,
		  __get_str(op_str),
		  __entry->mask, __entry->events)
);

/*
 * io_uring_task_add - called after adding a task
 *
 * @req:		pointer to request
 * @mask:		request poll events mask
 *
 */
TRACE_EVENT(io_uring_task_add,

	TP_PROTO(struct io_kiocb *req, int mask),

	TP_ARGS(req, mask),

	TP_STRUCT__entry (
		__field(  void *,		ctx		)
		__field(  void *,		req		)
		__field(  unsigned long long,	user_data	)
		__field(  u8,			opcode		)
		__field(  int,			mask		)

		__string( op_str, io_uring_get_opcode(req->opcode) )
	),

	TP_fast_assign(
		__entry->ctx		= req->ctx;
		__entry->req		= req;
		__entry->user_data	= req->cqe.user_data;
		__entry->opcode		= req->opcode;
		__entry->mask		= mask;

		__assign_str(op_str);
	),

	TP_printk("ring %p, req %p, user_data 0x%llx, opcode %s, mask %x",
		__entry->ctx, __entry->req, __entry->user_data,
		__get_str(op_str),
		__entry->mask)
);

/*
 * io_uring_req_failed - called when an sqe is errored dring submission
 *
 * @sqe:		pointer to the io_uring_sqe that failed
 * @req:		pointer to request
 * @error:		error it failed with
 *
 * Allows easier diagnosing of malformed requests in production systems.
 */
TRACE_EVENT(io_uring_req_failed,

	TP_PROTO(const struct io_uring_sqe *sqe, struct io_kiocb *req, int error),

	TP_ARGS(sqe, req, error),

	TP_STRUCT__entry (
		__field(  void *,		ctx		)
		__field(  void *,		req		)
		__field(  unsigned long long,	user_data	)
		__field(  u8,			opcode		)
		__field(  u8,			flags		)
		__field(  u8,			ioprio		)
		__field( u64,			off		)
		__field( u64,			addr		)
		__field( u32,			len		)
		__field( u32,			op_flags	)
		__field( u16,			buf_index	)
		__field( u16,			personality	)
		__field( u32,			file_index	)
		__field( u64,			pad1		)
		__field( u64,			addr3		)
		__field( int,			error		)

		__string( op_str, io_uring_get_opcode(sqe->opcode) )
	),

	TP_fast_assign(
		__entry->ctx		= req->ctx;
		__entry->req		= req;
		__entry->user_data	= sqe->user_data;
		__entry->opcode		= sqe->opcode;
		__entry->flags		= sqe->flags;
		__entry->ioprio		= sqe->ioprio;
		__entry->off		= sqe->off;
		__entry->addr		= sqe->addr;
		__entry->len		= sqe->len;
		__entry->op_flags	= sqe->poll32_events;
		__entry->buf_index	= sqe->buf_index;
		__entry->personality	= sqe->personality;
		__entry->file_index	= sqe->file_index;
		__entry->pad1		= sqe->__pad2[0];
		__entry->addr3		= sqe->addr3;
		__entry->error		= error;

		__assign_str(op_str);
	),

	TP_printk("ring %p, req %p, user_data 0x%llx, "
		  "opcode %s, flags 0x%x, prio=%d, off=%llu, addr=%llu, "
		  "len=%u, rw_flags=0x%x, buf_index=%d, "
		  "personality=%d, file_index=%d, pad=0x%llx, addr3=%llx, "
		  "error=%d",
		  __entry->ctx, __entry->req, __entry->user_data,
		  __get_str(op_str),
		  __entry->flags, __entry->ioprio,
		  (unsigned long long)__entry->off,
		  (unsigned long long) __entry->addr, __entry->len,
		  __entry->op_flags,
		  __entry->buf_index, __entry->personality, __entry->file_index,
		  (unsigned long long) __entry->pad1,
		  (unsigned long long) __entry->addr3, __entry->error)
);


/*
 * io_uring_cqe_overflow - a CQE overflowed
 *
 * @ctx:		pointer to a ring context structure
 * @user_data:		user data associated with the request
 * @res:		CQE result
 * @cflags:		CQE flags
 * @ocqe:		pointer to the overflow cqe (if available)
 *
 */
TRACE_EVENT(io_uring_cqe_overflow,

	TP_PROTO(void *ctx, unsigned long long user_data, s32 res, u32 cflags,
		 void *ocqe),

	TP_ARGS(ctx, user_data, res, cflags, ocqe),

	TP_STRUCT__entry (
		__field(  void *,		ctx		)
		__field(  unsigned long long,	user_data	)
		__field(  s32,			res		)
		__field(  u32,			cflags		)
		__field(  void *,		ocqe		)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->user_data	= user_data;
		__entry->res		= res;
		__entry->cflags		= cflags;
		__entry->ocqe		= ocqe;
	),

	TP_printk("ring %p, user_data 0x%llx, res %d, cflags 0x%x, "
		  "overflow_cqe %p",
		  __entry->ctx, __entry->user_data, __entry->res,
		  __entry->cflags, __entry->ocqe)
);

/*
 * io_uring_task_work_run - ran task work
 *
 * @tctx:		pointer to a io_uring_task
 * @count:		how many functions it ran
 *
 */
TRACE_EVENT(io_uring_task_work_run,

	TP_PROTO(void *tctx, unsigned int count),

	TP_ARGS(tctx, count),

	TP_STRUCT__entry (
		__field(  void *,		tctx		)
		__field(  unsigned int,		count		)
	),

	TP_fast_assign(
		__entry->tctx		= tctx;
		__entry->count		= count;
	),

	TP_printk("tctx %p, count %u", __entry->tctx, __entry->count)
);

TRACE_EVENT(io_uring_short_write,

	TP_PROTO(void *ctx, u64 fpos, u64 wanted, u64 got),

	TP_ARGS(ctx, fpos, wanted, got),

	TP_STRUCT__entry(
		__field(void *,	ctx)
		__field(u64,	fpos)
		__field(u64,	wanted)
		__field(u64,	got)
	),

	TP_fast_assign(
		__entry->ctx	= ctx;
		__entry->fpos	= fpos;
		__entry->wanted	= wanted;
		__entry->got	= got;
	),

	TP_printk("ring %p, fpos %lld, wanted %lld, got %lld",
			  __entry->ctx, __entry->fpos,
			  __entry->wanted, __entry->got)
);

/*
 * io_uring_local_work_run - ran ring local task work
 *
 * @ctx:		pointer to an io_ring_ctx
 * @count:		how many functions it ran
 * @loops:		how many loops it ran
 *
 */
TRACE_EVENT(io_uring_local_work_run,

	TP_PROTO(void *ctx, int count, unsigned int loops),

	TP_ARGS(ctx, count, loops),

	TP_STRUCT__entry (
		__field(void *,		ctx	)
		__field(int,		count	)
		__field(unsigned int,	loops	)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->count		= count;
		__entry->loops		= loops;
	),

	TP_printk("ring %p, count %d, loops %u", __entry->ctx, __entry->count, __entry->loops)
);

/*
 * SpareRing (research prototype, io_uring/spare.c). A chunk is identified by
 * (ring, seq); executor events carry the executor in common_pid and the CPU
 * in the record header. Owner events run in the submitter task.
 */
#ifndef __IO_URING_SPARE_TRACE_DEFS
#define __IO_URING_SPARE_TRACE_DEFS
/* io_uring_spare_skip: why the owner kept SQEs inline */
#define IO_SPARE_SKIP_STATE		0	/* link, drain, BPF filter or restriction */
#define IO_SPARE_SKIP_BUDGET		1	/* u_chunks chunks outstanding */
#define IO_SPARE_SKIP_INELIGIBLE	2	/* head SQE not delegable */
#define IO_SPARE_SKIP_ASLEEP		3	/* AUTO with no executor awake */
#define IO_SPARE_SKIP_PENDING		4	/* u_pending chunks unclaimed */
#define IO_SPARE_SKIP_NOMEM		5	/* chunk or token allocation */
#define IO_SPARE_SKIP_SHORT		6	/* eligible run shorter than n_min */
#define IO_SPARE_SKIP_NR		7
/* io_uring_spare_issue: how an executor finished one slot */
#define IO_SPARE_ISSUE_INLINE		0
#define IO_SPARE_ISSUE_ASYNC		1
#define IO_SPARE_ISSUE_BOUNCE		2
#define IO_SPARE_ISSUE_FAILED		3
#define IO_SPARE_ISSUE_CANCELLED	4
#define IO_SPARE_ISSUE_DEFERRED	5	/* folios pinned, the owner copies */
#define IO_SPARE_ISSUE_BLOCKED	6	/* issued blocking after the scan, io-wq style */
/* io_uring_spare_bounce: why a request moved to the owner */
#define IO_SPARE_BOUNCE_FILE		0	/* io_uring fd, O_APPEND or fsnotify HSM */
#define IO_SPARE_BOUNCE_EAGAIN		1	/* nonblocking issue would block */
#define IO_SPARE_BOUNCE_REISSUE		2	/* completion asked for a reissue */
/* io_uring_spare_retire: how the owner retired a chunk */
#define IO_SPARE_RETIRE_FIN		0
#define IO_SPARE_RETIRE_RESCUE		1	/* unclaimed chunk taken back whole */
#define IO_SPARE_RETIRE_CANCEL		2	/* unclaimed chunk cancelled at exit */
/* io_uring_spare_wake */
#define IO_SPARE_WAKE_CREDIT		0	/* credit-limited policy wake */
#define IO_SPARE_WAKE_PUBLISH		1	/* published while no executor awake */
/* io_uring_spare_post: what made the owner post */
#define IO_SPARE_POST_LEASE		0	/* executor kick */
#define IO_SPARE_POST_FIN		1	/* executor's last access */
#define IO_SPARE_POST_HARVEST		2	/* owner wait, executor off CPU */
#define IO_SPARE_POST_PORT		3	/* executor's async CQE journal (chunk 0) */
#define IO_SPARE_POST_DIRECT		4	/* the executor itself, uring_lock tried and held */
/* io_uring_spare_rescue: what the owner took back */
#define IO_SPARE_RESCUE_PENDING		0	/* a whole unclaimed chunk */
#define IO_SPARE_RESCUE_TAIL		1	/* a stalled executor's unissued tail */
#define IO_SPARE_RESCUE_SPLIT		2	/* owner wait: half a running executor's tail */
/* io_uring_spare_async: who finished an async completion */
#define IO_SPARE_ASYNC_EXEC		0	/* the executor, CQE through its journal */
#define IO_SPARE_ASYNC_OWNER		1	/* the owner, CQE posted directly */
#define IO_SPARE_ASYNC_REISSUE		2	/* reissued on the owner, no CQE yet */
#endif

/**
 * io_uring_spare_register - ring attached to an executor group
 *
 * @ctx:	pointer to a ring context structure
 * @grp:	executor group, shared by attached rings
 * @attach:	joined an existing group instead of creating one
 * @nr_exec:	executors in the group
 * @n_max:	max SQEs per chunk
 * @u_pending:	max unclaimed chunks
 * @u_chunks:	max outstanding chunks
 * @mode:	IORING_SPARE_MODE_*
 */
TRACE_EVENT(io_uring_spare_register,

	TP_PROTO(void *ctx, void *grp, bool attach, u32 nr_exec, u32 n_max,
		 u32 u_pending, u32 u_chunks, u32 mode),

	TP_ARGS(ctx, grp, attach, nr_exec, n_max, u_pending, u_chunks, mode),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  void *,	grp		)
		__field(  bool,		attach		)
		__field(  u32,		nr_exec		)
		__field(  u32,		n_max		)
		__field(  u32,		u_pending	)
		__field(  u32,		u_chunks	)
		__field(  u32,		mode		)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->grp		= grp;
		__entry->attach		= attach;
		__entry->nr_exec	= nr_exec;
		__entry->n_max		= n_max;
		__entry->u_pending	= u_pending;
		__entry->u_chunks	= u_chunks;
		__entry->mode		= mode;
	),

	TP_printk("ring %p, grp %p, %s, nr_exec %u, n_max %u, u_pending %u, u_chunks %u, mode %u",
		  __entry->ctx, __entry->grp, __entry->attach ? "attach" : "create",
		  __entry->nr_exec, __entry->n_max, __entry->u_pending,
		  __entry->u_chunks, __entry->mode)
);

/**
 * io_uring_spare_detach - ring left its executor group
 *
 * @ctx:	pointer to a ring context structure
 * @grp:	executor group
 * @last:	the group had no other ring, its executors are stopping
 */
TRACE_EVENT(io_uring_spare_detach,

	TP_PROTO(void *ctx, void *grp, bool last),

	TP_ARGS(ctx, grp, last),

	TP_STRUCT__entry (
		__field(  void *,	ctx	)
		__field(  void *,	grp	)
		__field(  bool,		last	)
	),

	TP_fast_assign(
		__entry->ctx	= ctx;
		__entry->grp	= grp;
		__entry->last	= last;
	),

	TP_printk("ring %p, grp %p, last %d", __entry->ctx, __entry->grp,
		  __entry->last)
);

/**
 * io_uring_spare_free - SpareRing state of a ring freed
 *
 * @ctx:	pointer to a ring context structure
 *
 * With io_uring_spare_detach, bounds the ring teardown latency.
 */
TRACE_EVENT(io_uring_spare_free,

	TP_PROTO(void *ctx),

	TP_ARGS(ctx),

	TP_STRUCT__entry (
		__field(  void *,	ctx	)
	),

	TP_fast_assign(
		__entry->ctx	= ctx;
	),

	TP_printk("ring %p", __entry->ctx)
);

/**
 * io_uring_spare_signal - adaptive signal sampled at an owner service point
 *
 * @ctx:	pointer to a ring context structure
 * @wait:	sampled at wait entry, otherwise at submit
 * @min_events:	completions the caller asked for
 * @ready_hits:	consecutive samples that already had them (0..2)
 */
TRACE_EVENT(io_uring_spare_signal,

	TP_PROTO(void *ctx, bool wait, unsigned int min_events,
		 unsigned int ready_hits),

	TP_ARGS(ctx, wait, min_events, ready_hits),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  bool,		wait		)
		__field(  unsigned int,	min_events	)
		__field(  unsigned int,	ready_hits	)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->wait		= wait;
		__entry->min_events	= min_events;
		__entry->ready_hits	= ready_hits;
	),

	TP_printk("ring %p, %s, min_events %u, ready_hits %u", __entry->ctx,
		  __entry->wait ? "wait" : "submit", __entry->min_events,
		  __entry->ready_hits)
);

/**
 * io_uring_spare_skip - owner kept the SQEs at the SQ head inline
 *
 * @ctx:	pointer to a ring context structure
 * @reason:	IO_SPARE_SKIP_*
 * @left:	SQEs left in this submission
 */
TRACE_EVENT(io_uring_spare_skip,

	TP_PROTO(void *ctx, int reason, unsigned int left),

	TP_ARGS(ctx, reason, left),

	TP_STRUCT__entry (
		__field(  void *,	ctx	)
		__field(  int,		reason	)
		__field(  unsigned int,	left	)
	),

	TP_fast_assign(
		__entry->ctx	= ctx;
		__entry->reason	= reason;
		__entry->left	= left;
	),

	TP_printk("ring %p, %s, left %u", __entry->ctx,
		  __print_symbolic(__entry->reason,
				   { IO_SPARE_SKIP_STATE,	"state" },
				   { IO_SPARE_SKIP_BUDGET,	"budget" },
				   { IO_SPARE_SKIP_INELIGIBLE,	"ineligible" },
				   { IO_SPARE_SKIP_ASLEEP,	"asleep" },
				   { IO_SPARE_SKIP_PENDING,	"pending" },
				   { IO_SPARE_SKIP_NOMEM,	"nomem" },
				   { IO_SPARE_SKIP_SHORT,	"short" }),
		  __entry->left)
);

/**
 * io_uring_spare_delegate - owner published a chunk
 *
 * @ctx:	pointer to a ring context structure
 * @seq:	chunk sequence number in this ring
 * @n:		SQEs copied into the chunk
 * @left:	SQEs left in this submission, including these
 * @nr_pending:	unclaimed chunks, including this one
 * @nr_chunks:	outstanding chunks, including this one
 */
TRACE_EVENT(io_uring_spare_delegate,

	TP_PROTO(void *ctx, u64 seq, unsigned int n, unsigned int left,
		 unsigned int nr_pending, unsigned int nr_chunks),

	TP_ARGS(ctx, seq, n, left, nr_pending, nr_chunks),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  u64,		seq		)
		__field(  unsigned int,	n		)
		__field(  unsigned int,	left		)
		__field(  unsigned int,	nr_pending	)
		__field(  unsigned int,	nr_chunks	)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->seq		= seq;
		__entry->n		= n;
		__entry->left		= left;
		__entry->nr_pending	= nr_pending;
		__entry->nr_chunks	= nr_chunks;
	),

	TP_printk("ring %p, chunk %llu, n %u, left %u, pending %u, chunks %u",
		  __entry->ctx, (unsigned long long) __entry->seq, __entry->n,
		  __entry->left, __entry->nr_pending, __entry->nr_chunks)
);

/**
 * io_uring_spare_append - owner added a short eligible run to its last unclaimed chunk
 *
 * @ctx:	pointer to a ring context structure
 * @seq:	chunk sequence number
 * @n:		SQEs in the chunk before the append
 * @added:	SQEs appended
 */
TRACE_EVENT(io_uring_spare_append,

	TP_PROTO(void *ctx, u64 seq, unsigned int n, unsigned int added),

	TP_ARGS(ctx, seq, n, added),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  u64,		seq		)
		__field(  unsigned int,	n		)
		__field(  unsigned int,	added		)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->seq		= seq;
		__entry->n		= n;
		__entry->added		= added;
	),

	TP_printk("ring %p, chunk %llu, n %u, added %u",
		  __entry->ctx, (unsigned long long) __entry->seq, __entry->n,
		  __entry->added)
);

/**
 * io_uring_spare_wake - owner woke a sleeping executor
 *
 * @ctx:	pointer to a ring context structure
 * @reason:	IO_SPARE_WAKE_*
 * @nr_awake:	executors awake before the wake
 * @nr_live:	executors alive
 * @credit:	outstanding wake credit after this wake
 */
TRACE_EVENT(io_uring_spare_wake,

	TP_PROTO(void *ctx, int reason, int nr_awake, int nr_live, int credit),

	TP_ARGS(ctx, reason, nr_awake, nr_live, credit),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  int,		reason		)
		__field(  int,		nr_awake	)
		__field(  int,		nr_live		)
		__field(  int,		credit		)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->reason		= reason;
		__entry->nr_awake	= nr_awake;
		__entry->nr_live	= nr_live;
		__entry->credit		= credit;
	),

	TP_printk("ring %p, %s, awake %d/%d, credit %d", __entry->ctx,
		  __print_symbolic(__entry->reason,
				   { IO_SPARE_WAKE_CREDIT,	"credit" },
				   { IO_SPARE_WAKE_PUBLISH,	"publish" }),
		  __entry->nr_awake, __entry->nr_live, __entry->credit)
);

/**
 * io_uring_spare_select - executor picked the ring it will claim from
 *
 * @ctx:	pointer to a ring context structure
 * @nr_pending:	unclaimed chunks of that ring when picked
 */
TRACE_EVENT(io_uring_spare_select,

	TP_PROTO(void *ctx, unsigned int nr_pending),

	TP_ARGS(ctx, nr_pending),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  unsigned int,	nr_pending	)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->nr_pending	= nr_pending;
	),

	TP_printk("ring %p, pending %u", __entry->ctx, __entry->nr_pending)
);

/**
 * io_uring_spare_claim - executor claimed a chunk
 *
 * @ctx:	pointer to a ring context structure
 * @seq:	chunk sequence number
 * @n:		SQEs in the chunk
 */
TRACE_EVENT(io_uring_spare_claim,

	TP_PROTO(void *ctx, u64 seq, unsigned int n),

	TP_ARGS(ctx, seq, n),

	TP_STRUCT__entry (
		__field(  void *,	ctx	)
		__field(  u64,		seq	)
		__field(  unsigned int,	n	)
	),

	TP_fast_assign(
		__entry->ctx	= ctx;
		__entry->seq	= seq;
		__entry->n	= n;
	),

	TP_printk("ring %p, chunk %llu, n %u", __entry->ctx,
		  (unsigned long long) __entry->seq, __entry->n)
);

/**
 * io_uring_spare_issue - executor finished issuing one chunk slot
 *
 * @ctx:	pointer to a ring context structure
 * @seq:	chunk sequence number
 * @slot:	slot index in the chunk
 * @user_data:	user data of the SQE
 * @opcode:	opcode of the SQE
 * @outcome:	IO_SPARE_ISSUE_*
 * @res:	result for INLINE and FAILED, otherwise 0
 */
TRACE_EVENT(io_uring_spare_issue,

	TP_PROTO(void *ctx, u64 seq, unsigned int slot, u64 user_data,
		 u8 opcode, int outcome, int res),

	TP_ARGS(ctx, seq, slot, user_data, opcode, outcome, res),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  u64,		seq		)
		__field(  unsigned int,	slot		)
		__field(  u64,		user_data	)
		__field(  u8,		opcode		)
		__field(  int,		outcome		)
		__field(  int,		res		)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->seq		= seq;
		__entry->slot		= slot;
		__entry->user_data	= user_data;
		__entry->opcode		= opcode;
		__entry->outcome	= outcome;
		__entry->res		= res;
	),

	TP_printk("ring %p, chunk %llu, slot %u, user_data 0x%llx, opcode %s, %s, res %d",
		  __entry->ctx, (unsigned long long) __entry->seq, __entry->slot,
		  (unsigned long long) __entry->user_data,
		  io_uring_get_opcode(__entry->opcode),
		  __print_symbolic(__entry->outcome,
				   { IO_SPARE_ISSUE_INLINE,	"inline" },
				   { IO_SPARE_ISSUE_ASYNC,	"async" },
				   { IO_SPARE_ISSUE_BOUNCE,	"bounce" },
				   { IO_SPARE_ISSUE_FAILED,	"failed" },
				   { IO_SPARE_ISSUE_CANCELLED,	"cancelled" },
				   { IO_SPARE_ISSUE_DEFERRED,	"deferred" },
				   { IO_SPARE_ISSUE_BLOCKED,	"blocked" }),
		  __entry->res)
);

/**
 * io_uring_spare_bounce - executor handed a request to the owner task
 *
 * @ctx:	pointer to a ring context structure
 * @seq:	chunk sequence number
 * @user_data:	user data of the request
 * @reason:	IO_SPARE_BOUNCE_*
 */
TRACE_EVENT(io_uring_spare_bounce,

	TP_PROTO(void *ctx, u64 seq, u64 user_data, int reason),

	TP_ARGS(ctx, seq, user_data, reason),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  u64,		seq		)
		__field(  u64,		user_data	)
		__field(  int,		reason		)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->seq		= seq;
		__entry->user_data	= user_data;
		__entry->reason		= reason;
	),

	TP_printk("ring %p, chunk %llu, user_data 0x%llx, %s", __entry->ctx,
		  (unsigned long long) __entry->seq,
		  (unsigned long long) __entry->user_data,
		  __print_symbolic(__entry->reason,
				   { IO_SPARE_BOUNCE_FILE,	"file" },
				   { IO_SPARE_BOUNCE_EAGAIN,	"eagain" },
				   { IO_SPARE_BOUNCE_REISSUE,	"reissue" }))
);

/**
 * io_uring_spare_complete - executor stored a CQE in the chunk buffer
 *
 * @ctx:	pointer to a ring context structure
 * @seq:	chunk sequence number
 * @idx:	index in the chunk CQE buffer
 * @user_data:	user data of the CQE
 * @res:	result of the CQE
 */
TRACE_EVENT(io_uring_spare_complete,

	TP_PROTO(void *ctx, u64 seq, unsigned int idx, u64 user_data, int res),

	TP_ARGS(ctx, seq, idx, user_data, res),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  u64,		seq		)
		__field(  unsigned int,	idx		)
		__field(  u64,		user_data	)
		__field(  int,		res		)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->seq		= seq;
		__entry->idx		= idx;
		__entry->user_data	= user_data;
		__entry->res		= res;
	),

	TP_printk("ring %p, chunk %llu, idx %u, user_data 0x%llx, res %d",
		  __entry->ctx, (unsigned long long) __entry->seq, __entry->idx,
		  (unsigned long long) __entry->user_data, __entry->res)
);

/**
 * io_uring_spare_kick - executor queued the lease task_work to the owner
 *
 * @ctx:	pointer to a ring context structure
 * @seq:	chunk sequence number
 * @produced:	CQEs stored in the chunk so far
 * @kick:	kick number for this chunk, starting at 1
 */
TRACE_EVENT(io_uring_spare_kick,

	TP_PROTO(void *ctx, u64 seq, unsigned int produced, unsigned int kick),

	TP_ARGS(ctx, seq, produced, kick),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  u64,		seq		)
		__field(  unsigned int,	produced	)
		__field(  unsigned int,	kick		)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->seq		= seq;
		__entry->produced	= produced;
		__entry->kick		= kick;
	),

	TP_printk("ring %p, chunk %llu, produced %u, kick %u", __entry->ctx,
		  (unsigned long long) __entry->seq, __entry->produced,
		  __entry->kick)
);

/**
 * io_uring_spare_post - owner posted chunk CQEs to the CQ
 *
 * @ctx:	pointer to a ring context structure
 * @seq:	chunk sequence number
 * @from:	first CQE index posted
 * @to:		one past the last CQE index posted (from == to: nothing new)
 * @src:	IO_SPARE_POST_*
 */
TRACE_EVENT(io_uring_spare_post,

	TP_PROTO(void *ctx, u64 seq, unsigned int from, unsigned int to, int src),

	TP_ARGS(ctx, seq, from, to, src),

	TP_STRUCT__entry (
		__field(  void *,	ctx	)
		__field(  u64,		seq	)
		__field(  unsigned int,	from	)
		__field(  unsigned int,	to	)
		__field(  int,		src	)
	),

	TP_fast_assign(
		__entry->ctx	= ctx;
		__entry->seq	= seq;
		__entry->from	= from;
		__entry->to	= to;
		__entry->src	= src;
	),

	TP_printk("ring %p, chunk %llu, cqes [%u, %u), %s", __entry->ctx,
		  (unsigned long long) __entry->seq, __entry->from, __entry->to,
		  __print_symbolic(__entry->src,
				   { IO_SPARE_POST_LEASE,	"lease" },
				   { IO_SPARE_POST_FIN,		"fin" },
				   { IO_SPARE_POST_HARVEST,	"harvest" },
				   { IO_SPARE_POST_PORT,	"port" },
				   { IO_SPARE_POST_DIRECT,	"direct" }))
);

/**
 * io_uring_spare_async - an executor-issued request's async completion was finished
 *
 * @ctx:	pointer to a ring context structure
 * @user_data:	user data of the request
 * @res:	result of the request
 * @where:	IO_SPARE_ASYNC_*
 */
TRACE_EVENT(io_uring_spare_async,

	TP_PROTO(void *ctx, u64 user_data, int res, int where),

	TP_ARGS(ctx, user_data, res, where),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  u64,		user_data	)
		__field(  int,		res		)
		__field(  int,		where		)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->user_data	= user_data;
		__entry->res		= res;
		__entry->where		= where;
	),

	TP_printk("ring %p, user_data 0x%llx, res %d, %s", __entry->ctx,
		  (unsigned long long) __entry->user_data, __entry->res,
		  __print_symbolic(__entry->where,
				   { IO_SPARE_ASYNC_EXEC,	"exec" },
				   { IO_SPARE_ASYNC_OWNER,	"owner" },
				   { IO_SPARE_ASYNC_REISSUE,	"reissue" }))
);

/**
 * io_uring_spare_fin - executor queued the fin task_work, its last chunk access
 *
 * @ctx:	pointer to a ring context structure
 * @seq:	chunk sequence number
 * @taken:	slots the executor took
 * @handled:	of those, finished (stored, bounced or cancelled)
 * @produced:	CQEs stored in the chunk
 * @async:	issued requests whose completions finish outside the chunk (port)
 */
TRACE_EVENT(io_uring_spare_fin,

	TP_PROTO(void *ctx, u64 seq, unsigned int taken, unsigned int handled,
		 unsigned int produced, unsigned int async),

	TP_ARGS(ctx, seq, taken, handled, produced, async),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  u64,		seq		)
		__field(  unsigned int,	taken		)
		__field(  unsigned int,	handled		)
		__field(  unsigned int,	produced	)
		__field(  unsigned int,	async		)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->seq		= seq;
		__entry->taken		= taken;
		__entry->handled	= handled;
		__entry->produced	= produced;
		__entry->async		= async;
	),

	TP_printk("ring %p, chunk %llu, taken %u, handled %u, produced %u, async %u",
		  __entry->ctx, (unsigned long long) __entry->seq, __entry->taken,
		  __entry->handled, __entry->produced, __entry->async)
);

/**
 * io_uring_spare_retire - owner freed a chunk
 *
 * @ctx:	pointer to a ring context structure
 * @seq:	chunk sequence number
 * @n:		SQEs in the chunk
 * @produced:	CQEs the executor stored
 * @how:	IO_SPARE_RETIRE_*
 */
TRACE_EVENT(io_uring_spare_retire,

	TP_PROTO(void *ctx, u64 seq, unsigned int n, unsigned int produced, int how),

	TP_ARGS(ctx, seq, n, produced, how),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  u64,		seq		)
		__field(  unsigned int,	n		)
		__field(  unsigned int,	produced	)
		__field(  int,		how		)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->seq		= seq;
		__entry->n		= n;
		__entry->produced	= produced;
		__entry->how		= how;
	),

	TP_printk("ring %p, chunk %llu, n %u, produced %u, %s", __entry->ctx,
		  (unsigned long long) __entry->seq, __entry->n, __entry->produced,
		  __print_symbolic(__entry->how,
				   { IO_SPARE_RETIRE_FIN,	"fin" },
				   { IO_SPARE_RETIRE_RESCUE,	"rescue" },
				   { IO_SPARE_RETIRE_CANCEL,	"cancel" }))
);

/**
 * io_uring_spare_rescue - owner took unissued SQEs back from a chunk
 *
 * @ctx:	pointer to a ring context structure
 * @seq:	chunk sequence number
 * @nr:		SQEs taken back
 * @cancelled:	of those, marked cancelled (posted as -ECANCELED)
 * @kind:	IO_SPARE_RESCUE_*
 */
TRACE_EVENT(io_uring_spare_rescue,

	TP_PROTO(void *ctx, u64 seq, unsigned int nr, unsigned int cancelled,
		 u8 kind),

	TP_ARGS(ctx, seq, nr, cancelled, kind),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  u64,		seq		)
		__field(  unsigned int,	nr		)
		__field(  unsigned int,	cancelled	)
		__field(  u8,		kind		)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->seq		= seq;
		__entry->nr		= nr;
		__entry->cancelled	= cancelled;
		__entry->kind		= kind;
	),

	TP_printk("ring %p, chunk %llu, nr %u, cancelled %u, %s", __entry->ctx,
		  (unsigned long long) __entry->seq, __entry->nr,
		  __entry->cancelled,
		  __print_symbolic(__entry->kind,
				   { IO_SPARE_RESCUE_PENDING,	"pending" },
				   { IO_SPARE_RESCUE_TAIL,	"tail" },
				   { IO_SPARE_RESCUE_SPLIT,	"split" }))
);

/**
 * io_uring_spare_handback - executor returned unissued slots to the owner
 *
 * @ctx:	pointer to a ring context structure
 * @seq:	chunk sequence number
 * @nr:		slots returned
 * @cancelled:	of those, marked cancelled
 *
 * Happens on detach, executor stop or a fatal signal.
 */
TRACE_EVENT(io_uring_spare_handback,

	TP_PROTO(void *ctx, u64 seq, unsigned int nr, unsigned int cancelled),

	TP_ARGS(ctx, seq, nr, cancelled),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  u64,		seq		)
		__field(  unsigned int,	nr		)
		__field(  unsigned int,	cancelled	)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->seq		= seq;
		__entry->nr		= nr;
		__entry->cancelled	= cancelled;
	),

	TP_printk("ring %p, chunk %llu, nr %u, cancelled %u", __entry->ctx,
		  (unsigned long long) __entry->seq, __entry->nr,
		  __entry->cancelled)
);

/**
 * io_uring_spare_cancel - async cancel marked a delegated, unissued slot
 *
 * @ctx:	pointer to a ring context structure
 * @seq:	chunk sequence number
 * @slot:	slot index in the chunk
 * @user_data:	user data of the cancelled SQE
 */
TRACE_EVENT(io_uring_spare_cancel,

	TP_PROTO(void *ctx, u64 seq, unsigned int slot, u64 user_data),

	TP_ARGS(ctx, seq, slot, user_data),

	TP_STRUCT__entry (
		__field(  void *,	ctx		)
		__field(  u64,		seq		)
		__field(  unsigned int,	slot		)
		__field(  u64,		user_data	)
	),

	TP_fast_assign(
		__entry->ctx		= ctx;
		__entry->seq		= seq;
		__entry->slot		= slot;
		__entry->user_data	= user_data;
	),

	TP_printk("ring %p, chunk %llu, slot %u, user_data 0x%llx", __entry->ctx,
		  (unsigned long long) __entry->seq, __entry->slot,
		  (unsigned long long) __entry->user_data)
);

/**
 * io_uring_spare_exec_sleep - executor is about to sleep
 *
 * @linger_ns:	current linger budget
 * @idle_ns:	time spent idle (lingering) before sleeping
 */
TRACE_EVENT(io_uring_spare_exec_sleep,

	TP_PROTO(u64 linger_ns, u64 idle_ns),

	TP_ARGS(linger_ns, idle_ns),

	TP_STRUCT__entry (
		__field(  u64,	linger_ns	)
		__field(  u64,	idle_ns		)
	),

	TP_fast_assign(
		__entry->linger_ns	= linger_ns;
		__entry->idle_ns	= idle_ns;
	),

	TP_printk("linger %llu ns, idle %llu ns",
		  (unsigned long long) __entry->linger_ns,
		  (unsigned long long) __entry->idle_ns)
);

/**
 * io_uring_spare_exec_wake - executor woke up
 *
 * @slept_ns:	time asleep
 * @nr_pending:	unclaimed chunks in the group at wake
 * @empty:	no chunk and no completion to run (counts towards linger 0)
 */
TRACE_EVENT(io_uring_spare_exec_wake,

	TP_PROTO(u64 slept_ns, unsigned int nr_pending, bool empty),

	TP_ARGS(slept_ns, nr_pending, empty),

	TP_STRUCT__entry (
		__field(  u64,		slept_ns	)
		__field(  unsigned int,	nr_pending	)
		__field(  bool,		empty		)
	),

	TP_fast_assign(
		__entry->slept_ns	= slept_ns;
		__entry->nr_pending	= nr_pending;
		__entry->empty		= empty;
	),

	TP_printk("slept %llu ns, pending %u, %s",
		  (unsigned long long) __entry->slept_ns, __entry->nr_pending,
		  __entry->empty ? "empty" : "work")
);

/**
 * io_uring_spare_exec_exit - executor finished its exit cancellation
 *
 * @cancel_ns:	time spent returning chunks and handing its completions to owners
 */
TRACE_EVENT(io_uring_spare_exec_exit,

	TP_PROTO(u64 cancel_ns),

	TP_ARGS(cancel_ns),

	TP_STRUCT__entry (
		__field(  u64,	cancel_ns	)
	),

	TP_fast_assign(
		__entry->cancel_ns	= cancel_ns;
	),

	TP_printk("cancel %llu ns", (unsigned long long) __entry->cancel_ns)
);

/* Pull lease transitions and publication results, shared with the call sites. */
#define IO_SPARE_LEASE_ACQUIRE		0
#define IO_SPARE_LEASE_RELEASE		1
#define IO_SPARE_LEASE_HANDBACK		2
#define IO_SPARE_LEASE_TAKEOVER		3
#define IO_SPARE_LEASE_DROP		4
#define IO_SPARE_PULL_PUBLISHED		0
#define IO_SPARE_PULL_ABORTED		1
#define IO_SPARE_PULL_WITHDRAW_SELF	2
#define IO_SPARE_PULL_WITHDRAW_OWNER	3
#define IO_SPARE_PULL_CLAIMED		4

TRACE_EVENT(io_uring_spare_lease,

	TP_PROTO(void *ctx, void *exec, int op, u32 cursor, int reason),

	TP_ARGS(ctx, exec, op, cursor, reason),

	TP_STRUCT__entry (
		__field(  void *,	ctx	)
		__field(  void *,	exec	)
		__field(  int,	op	)
		__field(  u32,	cursor	)
		__field(  int,	reason	)
	),

	TP_fast_assign(
		__entry->ctx	= ctx;
		__entry->exec	= exec;
		__entry->op	= op;
		__entry->cursor	= cursor;
		__entry->reason	= reason;
	),

	TP_printk("ring %p, exec %p, op %d, cursor %u, reason %d",
		  __entry->ctx, __entry->exec, __entry->op, __entry->cursor, __entry->reason)
);

TRACE_EVENT(io_uring_spare_pull_publish,

	TP_PROTO(void *ctx, void *exec, u32 start, u32 k, int result),

	TP_ARGS(ctx, exec, start, k, result),

	TP_STRUCT__entry (
		__field(  void *,	ctx	)
		__field(  void *,	exec	)
		__field(  u32,	start	)
		__field(  u32,	k	)
		__field(  int,	result	)
	),

	TP_fast_assign(
		__entry->ctx	= ctx;
		__entry->exec	= exec;
		__entry->start	= start;
		__entry->k	= k;
		__entry->result	= result;
	),

	TP_printk("ring %p, exec %p, start %u, k %u, result %d",
		  __entry->ctx, __entry->exec, __entry->start, __entry->k, __entry->result)
);

TRACE_EVENT(io_uring_spare_head,

	TP_PROTO(void *ctx, int who, u32 want, u32 limit),

	TP_ARGS(ctx, who, want, limit),

	TP_STRUCT__entry (
		__field(  void *,	ctx	)
		__field(  int,	who	)
		__field(  u32,	want	)
		__field(  u32,	limit	)
	),

	TP_fast_assign(
		__entry->ctx	= ctx;
		__entry->who	= who;
		__entry->want	= want;
		__entry->limit	= limit;
	),

	TP_printk("ring %p, who %d, want %u, limit %u",
		  __entry->ctx, __entry->who, __entry->want, __entry->limit)
);

TRACE_EVENT(io_uring_spare_rtoken,

	TP_PROTO(void *ctx, int producer, bool queued),

	TP_ARGS(ctx, producer, queued),

	TP_STRUCT__entry (
		__field(  void *,	ctx	)
		__field(  int,	producer	)
		__field(  bool,	queued	)
	),

	TP_fast_assign(
		__entry->ctx	= ctx;
		__entry->producer	= producer;
		__entry->queued	= queued;
	),

	TP_printk("ring %p, producer %d, queued %d",
		  __entry->ctx, __entry->producer, __entry->queued)
);

TRACE_EVENT(io_uring_spare_rtimer,

	TP_PROTO(void *ctx, bool armed, bool fired, u32 pending, u32 rsv_chunks),

	TP_ARGS(ctx, armed, fired, pending, rsv_chunks),

	TP_STRUCT__entry (
		__field(  void *,	ctx	)
		__field(  bool,	armed	)
		__field(  bool,	fired	)
		__field(  u32,	pending	)
		__field(  u32,	rsv_chunks	)
	),

	TP_fast_assign(
		__entry->ctx	= ctx;
		__entry->armed	= armed;
		__entry->fired	= fired;
		__entry->pending	= pending;
		__entry->rsv_chunks	= rsv_chunks;
	),

	TP_printk("ring %p, armed %d, fired %d, pending %u, rsv_chunks %u",
		  __entry->ctx, __entry->armed, __entry->fired, __entry->pending, __entry->rsv_chunks)
);

#endif /* _TRACE_IO_URING_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
