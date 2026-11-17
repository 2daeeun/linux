/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IOU_RBCOUNT_H
#define IOU_RBCOUNT_H

#include <linux/types.h>
#include <uapi/linux/io_uring.h>

struct ext_arg;
struct io_ring_ctx;
struct seq_file;

#define IORING_RBC_WAIT_FLAGS (IORING_ENTER_WAIT_SPARE | \
			     IORING_ENTER_REGISTERED_RING | \
			     IORING_ENTER_EXT_ARG | \
			     IORING_ENTER_ABS_TIMER | \
			     IORING_ENTER_NO_IOWAIT)

int io_rbc_register(struct io_ring_ctx *ctx, unsigned int opcode,
		    void __user *arg, unsigned int nr_args);
void io_rbc_task_exit(void);
void io_rbc_ctx_exit(struct io_ring_ctx *ctx);
void io_rbc_enter(struct io_ring_ctx *ctx);
void io_rbc_enter_done(struct io_ring_ctx *ctx);
void io_rbc_activity(struct io_ring_ctx *ctx);
int io_rbc_wait_spare(struct io_ring_ctx *ctx, u32 flags,
		      struct ext_arg *ext_arg);
void io_rbc_fdinfo(struct io_ring_ctx *ctx, struct seq_file *m);

#endif
