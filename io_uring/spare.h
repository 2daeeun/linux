/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IOU_SPARE_H
#define IOU_SPARE_H

#include <linux/io_uring_types.h>

struct io_cancel_data;
struct seq_file;

/* Registration, uring_lock held. */
int io_register_spare(struct io_ring_ctx *ctx, void __user *arg,
		      unsigned int nr_args);
int io_unregister_spare(struct io_ring_ctx *ctx);
int io_register_spare_debug(struct io_ring_ctx *ctx, void __user *arg,
			    unsigned int nr_args);

/* Delegated SQEs that are not yet requests of the ring: IOSQE_IO_DRAIN waits for them. */
unsigned int io_spare_inflight(struct io_ring_ctx *ctx);

/* Resource tables stay frozen while attached, or while chunks or async requests are out. */
bool io_spare_frozen(struct io_ring_ctx *ctx);

/* Owner submit path, uring_lock held. */
bool io_spare_pull(struct io_ring_ctx *ctx);
void io_spare_submit_takeover(struct io_ring_ctx *ctx, unsigned int nr);
unsigned int io_spare_submit_entries(struct io_ring_ctx *ctx);
bool io_spare_took_over(struct io_ring_ctx *ctx);
void io_spare_commit_head(struct io_ring_ctx *ctx);
int io_spare_submit_ret(struct io_ring_ctx *ctx, unsigned int nr, int ret);
void io_spare_submit_start(struct io_ring_ctx *ctx, unsigned int nr);
void io_spare_submit_end(struct io_ring_ctx *ctx, unsigned int submitted);
unsigned int io_spare_delegate(struct io_ring_ctx *ctx, unsigned int left,
			       bool *stop);

/* Owner wait path, no locks held, TASK_RUNNING. Rescue returns true on progress. */
void io_spare_wait_start(struct io_ring_ctx *ctx, unsigned int min_events);
bool io_spare_rescue(struct io_ring_ctx *ctx);
/* After cq_wait_nr and the sleeping state are set: take back before sleeping? */
bool io_spare_wait_unserved(struct io_ring_ctx *ctx);
bool io_spare_wait_rescue_timer(struct io_ring_ctx *ctx);
u32 io_spare_rescue_ns(struct io_ring_ctx *ctx);
void io_spare_timer_event(struct io_ring_ctx *ctx, bool fired);
void io_spare_wait_last_check(struct io_ring_ctx *ctx);
void io_spare_wait_woke(struct io_ring_ctx *ctx);

/* Any context: async completion of an executor-issued request (io_complete_rw()). */
void io_spare_rw_done(struct io_kiocb *req);

/* Only the issuing executor task may access this request's private cache. */
struct io_alloc_cache *io_spare_rw_cache(struct io_kiocb *req);

/* Cancellation and teardown. */
int io_spare_try_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd);
bool io_spare_cancel_pending(struct io_ring_ctx *ctx, bool cancel_all);
void io_spare_ctx_exit(struct io_ring_ctx *ctx);
void io_spare_ctx_quiesce(struct io_ring_ctx *ctx);
void io_spare_ctx_free(struct io_ring_ctx *ctx);
void io_spare_show_fdinfo(struct io_ring_ctx *ctx, struct seq_file *m);

#endif
