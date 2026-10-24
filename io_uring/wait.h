// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_WAIT_H
#define IOU_WAIT_H

#include <linux/io_uring_types.h>

/*
 * ->cq_wait_nr is armed with the number of lazy task_work adds the waiter
 * still needs, and counted down by the add side, with the add reaching zero
 * issuing the (single) wake up for this wait cycle. Zero and below means no
 * wake up is to be issued: IO_CQ_WAKE_INIT when no task is waiting (also
 * what a forced wake up resets it to when claiming one), zero once the
 * countdown has fired.
 */
#define IO_CQ_WAKE_INIT		(-1)

struct ext_arg {
	size_t argsz;
	struct timespec64 ts;
	const sigset_t __user *sig;
	ktime_t min_time;
	bool ts_set;
	bool iowait;
};

int io_cqring_wait(struct io_ring_ctx *ctx, int min_events, u32 flags,
		   struct ext_arg *ext_arg);
int io_run_task_work_sig(struct io_ring_ctx *ctx);
void io_cqring_do_overflow_flush(struct io_ring_ctx *ctx);
void io_cqring_overflow_flush_locked(struct io_ring_ctx *ctx);

/*
 * The number of lazy task_work adds that may be counted before the waiter
 * is woken. A drained request is issued from the waiter's own task_work once
 * the completions queued before it have run; lazy adds only count towards
 * the wait, so a wait that includes the drained request itself (N lazy
 * completions, wait for N + 1) can never be satisfied without running them:
 * while a drain is pending, wake on the first completion.
 */
static inline int io_cq_wake_budget(struct io_ring_ctx *ctx, int nr_wait)
{
	if (unlikely(ctx->int_flags & IO_RING_F_DRAIN_ACTIVE))
		return 1;
	return nr_wait;
}

static inline unsigned int __io_cqring_events(struct io_ring_ctx *ctx)
{
	struct io_rings *rings = io_get_rings(ctx);
	return ctx->cached_cq_tail - READ_ONCE(rings->cq.head);
}

static inline unsigned int __io_cqring_events_user(struct io_ring_ctx *ctx)
{
	struct io_rings *rings = io_get_rings(ctx);

	return READ_ONCE(rings->cq.tail) - READ_ONCE(rings->cq.head);
}

/*
 * Reads the tail/head of the CQ ring while providing an acquire ordering,
 * see comment at top of io_uring.c.
 */
static inline unsigned io_cqring_events(struct io_ring_ctx *ctx)
{
	smp_rmb();
	return __io_cqring_events(ctx);
}

#endif
