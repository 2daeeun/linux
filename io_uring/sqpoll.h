// SPDX-License-Identifier: GPL-2.0

struct io_sq_data {
	refcount_t		refs;
	atomic_t		park_pending;
	struct mutex		lock;

	/* ctx's that are using this sqd */
	struct list_head	ctx_list;

	struct task_struct __rcu *thread;
	struct wait_queue_head	wait;

	unsigned		sq_thread_idle;
	int			sq_cpu;
	pid_t			task_pid;
	pid_t			task_tgid;

	u64			work_time;
	unsigned long		state;
	struct completion	exited;
	struct io_ringback	*ringback;
};

struct seq_file;

int io_ringback_init(struct io_ring_ctx *ctx);
void io_ringback_stop(struct io_ring_ctx *ctx);
void io_ringback_free(struct io_ring_ctx *ctx);
void io_ringback_fdinfo(struct io_ring_ctx *ctx, struct seq_file *m);
bool io_ringback_tw_lock(struct io_ring_ctx *ctx);
/* OWNER mode: published before NEED_WAKEUP, cleared before it is. */
static inline bool io_ringback_owner_mode(struct io_ring_ctx *ctx)
{
	return READ_ONCE(ctx->ringback_owner_mode);
}

void io_ringback_submitted(struct io_ring_ctx *ctx, unsigned int submitted);
bool io_ringback_dual(struct io_ring_ctx *ctx);
bool io_ringback_a2l(struct io_ring_ctx *ctx);
void io_ringback_dual_submitted(struct io_ring_ctx *ctx,
				unsigned int submitted);
void io_ringback_wake(struct io_ring_ctx *ctx);
bool io_ringback_redirect(struct io_kiocb *req);
bool io_ringback_defer_ok(struct io_kiocb *req);
void io_ringback_defer_kick(struct io_ring_ctx *ctx, bool waiter);
void io_ringback_mwait_kick(struct io_ring_ctx *ctx, struct task_struct *tsk);
void io_ringback_tw_raise(struct io_ring_ctx *ctx);
bool io_ringback_lazy_kick(struct io_ring_ctx *ctx);
void io_ringback_arm_kick(struct io_ring_ctx *ctx);

int io_sq_offload_create(struct io_ring_ctx *ctx, struct io_uring_params *p);
void io_sq_thread_finish(struct io_ring_ctx *ctx);
void io_sq_thread_stop(struct io_sq_data *sqd);
void io_sq_thread_park(struct io_sq_data *sqd);
void io_sq_thread_unpark(struct io_sq_data *sqd);
void io_put_sq_data(struct io_sq_data *sqd);
void io_sqpoll_wait_sq(struct io_ring_ctx *ctx);
int io_sqpoll_wq_cpu_affinity(struct io_ring_ctx *ctx, cpumask_var_t mask);
u64 io_sq_cpu_usec(struct task_struct *tsk);

static inline struct task_struct *sqpoll_task_locked(struct io_sq_data *sqd)
{
	return rcu_dereference_protected(sqd->thread,
					 lockdep_is_held(&sqd->lock));
}
