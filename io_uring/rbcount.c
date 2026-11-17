// SPDX-License-Identifier: GPL-2.0
#include <linux/compat.h>
#include <linux/cpumask.h>
#include <linux/hashtable.h>
#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/math64.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/stat.h>
#include <linux/sched/task.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/time_namespace.h>
#include <linux/uaccess.h>

#include "io_uring.h"
#include "rbcount.h"
#include "tctx.h"
#include "wait.h"

#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "sqpoll."

static bool sqpoll_safe_count = true;
module_param(sqpoll_safe_count, bool, 0644);
static unsigned int sqpoll_safe_count_delta_us = 50;
module_param(sqpoll_safe_count_delta_us, uint, 0644);
static unsigned int sqpoll_safe_count_hold_us = 200;
module_param(sqpoll_safe_count_hold_us, uint, 0644);
static unsigned int sqpoll_safe_count_eval_us = 100;
module_param(sqpoll_safe_count_eval_us, uint, 0644);
static unsigned int sqpoll_safe_count_timer_us = 1000;
module_param(sqpoll_safe_count_timer_us, uint, 0644);
static unsigned int sqpoll_safe_count_idle_timer_us = 16000;
module_param(sqpoll_safe_count_idle_timer_us, uint, 0644);
static unsigned int sqpoll_safe_count_rotate_us = 1000;
module_param(sqpoll_safe_count_rotate_us, uint, 0644);
static unsigned int sqpoll_safe_count_recrowd_us = 1000;
module_param(sqpoll_safe_count_recrowd_us, uint, 0644);
static unsigned int sqpoll_safe_count_holdg_max_us = 20000;
module_param(sqpoll_safe_count_holdg_max_us, uint, 0644);
static unsigned int sqpoll_safe_count_excl_learn_us = 10000;
module_param(sqpoll_safe_count_excl_learn_us, uint, 0644);
static unsigned int sqpoll_safe_count_excl_expire_us = 1000000;
module_param(sqpoll_safe_count_excl_expire_us, uint, 0644);

struct io_rbc_group {
	struct hlist_node	hnode;	/* io_rbc_mutex */
	struct mm_struct	*mm;	/* mmgrab() reference, immutable key */
	struct rcu_head		rcu;
	spinlock_t		lock;	/* group state and registration lists */
	struct list_head	regs;
	struct list_head	waitq;
	cpumask_var_t		cpus;
	struct hrtimer		timer;
	bool			timer_active, stopping, stopped, activity;
	u64			last_eval_ns;
	bool			over_run;
	u64			over_start_ns;
	unsigned int		over_evals;
	bool			free_run;
	int			free_cpu;
	u64			free_start_ns;
	struct io_rbc_reg	*crowded;
	u64			crowded_ns;
	struct io_rbc_reg	*settling;
	u64			last_grant_ns;
	unsigned int		holdg_k;
	bool			recrowded;
	u32			holdg_r;
	u8			*excl_k;
	u64			*excl_since, *excl_set_ns;
	u8			*nbuf;
	/* Updated under lock, sampled by fdinfo with data_race(). */
	u64 parks, refusals, grants, bits, rotations, settles, excl_marks;
	u64 stops, evals, eval_ns;
};

struct io_rbc_reg {
	struct io_ring_ctx	*ctx;
	struct task_struct	*task;
	struct io_rbc_group	*grp;
	struct list_head	node;
	struct list_head	wnode;
	struct rcu_head		rcu;
	unsigned int		flags;
	u64			start_ns;
	bool			queued, granted, dead;
};

static DEFINE_MUTEX(io_rbc_mutex);
static DEFINE_HASHTABLE(io_rbc_groups, 6);

static u64 io_rbc_ns(unsigned int us)
{
	return (u64)us * NSEC_PER_USEC;
}

static bool io_rbc_runnable(struct task_struct *task)
{
	/* task_is_runnable(), with explicit remote sampling. */
	return READ_ONCE(task->on_rq) && !READ_ONCE(task->se.sched_delayed);
}

static void io_rbc_clear_runs(struct io_rbc_group *g)
{
	g->over_run = false;
	g->over_evals = 0;
	g->free_run = false;
}

static void io_rbc_clear_bit(struct io_rbc_group *g)
{
	if (!g->crowded)
		return;
	rcu_read_lock();
	atomic_andnot(IORING_SQ_RB_CROWDED,
		      &io_get_rings(g->crowded->ctx)->sq_flags);
	rcu_read_unlock();
	g->crowded = NULL;
}

static void io_rbc_set_bit(struct io_rbc_group *g, struct io_rbc_reg *reg,
			   u64 now)
{
	rcu_read_lock();
	atomic_or(IORING_SQ_RB_CROWDED, &io_get_rings(reg->ctx)->sq_flags);
	rcu_read_unlock();
	g->crowded = reg;
	g->crowded_ns = now;
	g->bits++;
}

static bool io_rbc_masks_match(struct io_rbc_group *g)
{
	struct io_rbc_reg *reg;

	if (cpumask_weight(g->cpus) > 64)
		return false;
	list_for_each_entry(reg, &g->regs, node) {
		if (!cpumask_equal(READ_ONCE(reg->task->cpus_ptr), g->cpus))
			return false;
	}
	return true;
}

static void io_rbc_grant(struct io_rbc_group *g, u64 now)
{
	struct io_rbc_reg *reg;

	reg = list_first_entry(&g->waitq, struct io_rbc_reg, wnode);
	list_del_init(&reg->wnode);
	reg->queued = false;
	WRITE_ONCE(reg->granted, true);
	io_rbc_clear_bit(g);
	io_rbc_clear_runs(g);
	if (!g->recrowded)
		g->holdg_k = 0;
	g->recrowded = false;
	g->holdg_r = get_random_u32();
	g->last_grant_ns = now;
	g->grants++;
	wake_up_process(reg->task);
}

static void io_rbc_stop(struct io_rbc_group *g, u64 now)
{
	if (!g->stopped)
		g->stops++;
	g->stopped = true;
	io_rbc_clear_bit(g);
	io_rbc_clear_runs(g);
	g->settling = NULL;
	while (!list_empty(&g->waitq))
		io_rbc_grant(g, now);
}

struct io_rbc_scan {
	bool over, spare, same_free;
	int first_free;
};

static struct io_rbc_scan io_rbc_scan(struct io_rbc_group *g, u64 now)
{
	struct io_rbc_scan scan = { .first_free = -1 };
	unsigned int cpus[64], nr = 0, i, n;
	struct io_rbc_reg *reg;
	u64 mine = 0, free = 0;
	u64 start = ktime_get_ns();
	bool crowded = false;
	int cpu;

	for_each_cpu_and(cpu, g->cpus, cpu_online_mask) {
		/* Registration keeps g->cpus at 64 CPUs or fewer. */
		if (WARN_ON_ONCE(nr == ARRAY_SIZE(cpus)))
			break;
		cpus[nr++] = cpu;
	}
	list_for_each_entry(reg, &g->regs, node) {
		if (reg->queued || !io_rbc_runnable(reg->task))
			continue;
		cpu = task_cpu(reg->task);
		for (i = 0; i < nr; i++) {
			if (cpus[i] == cpu) {
				mine |= BIT_ULL(i);
				break;
			}
		}
	}
	for (i = 0; i < nr; i++) {
		bool excluded;

		cpu = cpus[i];
		n = sched_cpu_busy_nr(cpu);
		/* Never let a large run queue wrap into a free CPU sample. */
		g->nbuf[cpu] = min_t(unsigned int, n, U8_MAX);
		if (g->excl_k[cpu]) {
			if (n <= 1 || now - g->excl_set_ns[cpu] >=
			    io_rbc_ns(READ_ONCE(sqpoll_safe_count_excl_expire_us))) {
				g->excl_k[cpu] = 0;
				g->excl_since[cpu] = 0;
			} else if (n < g->excl_k[cpu]) {
				g->excl_k[cpu] = n;
			}
		}
		excluded = g->excl_k[cpu] && n >= 2 &&
			   n <= g->excl_k[cpu] && !(mine & BIT_ULL(i));
		if (n >= 2 && !excluded)
			crowded = true;
		if (!n) {
			free |= BIT_ULL(i);
			if (scan.first_free < 0)
				scan.first_free = cpu;
			if (g->free_cpu == cpu)
				scan.same_free = true;
		}
	}
	for (i = 0; i < nr; i++) {
		cpu = cpus[i];
		n = g->nbuf[cpu];
		if (n < 2 || (mine & BIT_ULL(i)) || !free) {
			g->excl_since[cpu] = 0;
			continue;
		}
		if (g->excl_k[cpu])
			continue;
		if (!g->excl_since[cpu]) {
			g->excl_since[cpu] = now;
		} else if (now - g->excl_since[cpu] >=
			   io_rbc_ns(READ_ONCE(sqpoll_safe_count_excl_learn_us))) {
			g->excl_k[cpu] = n;
			g->excl_set_ns[cpu] = now;
			g->excl_marks++;
		}
	}
	scan.over = crowded && !free;
	scan.spare = free && !crowded;
	g->evals++;
	g->eval_ns += ktime_get_ns() - start;
	return scan;
}

static struct io_rbc_reg *io_rbc_victim(struct io_rbc_group *g,
					struct io_rbc_reg *exclude)
{
	struct io_rbc_reg *reg, *victim = NULL;

	list_for_each_entry(reg, &g->regs, node) {
		if (reg == exclude || (reg->flags & IORING_RB_WORKER_BASE) ||
		    reg->queued || !io_rbc_runnable(reg->task))
			continue;
		if (!victim || reg->start_ns > victim->start_ns)
			victim = reg;
	}
	return victim;
}

static u64 io_rbc_holdg(struct io_rbc_group *g)
{
	u64 hold = READ_ONCE(sqpoll_safe_count_hold_us);
	u64 cap = READ_ONCE(sqpoll_safe_count_holdg_max_us);
	u64 base = io_rbc_ns(min(hold << g->holdg_k, cap));

	return base + mul_u64_u32_shr(base, g->holdg_r, 32);
}

static void io_rbc_recrowd(struct io_rbc_group *g, u64 now)
{
	u64 hold = READ_ONCE(sqpoll_safe_count_hold_us);
	u64 cap = READ_ONCE(sqpoll_safe_count_holdg_max_us);

	if (!g->last_grant_ns || now - g->last_grant_ns >=
	    io_rbc_ns(READ_ONCE(sqpoll_safe_count_recrowd_us)))
		return;
	g->recrowded = true;
	if (hold && g->holdg_k < 31 && (hold << (g->holdg_k + 1)) <= cap)
		g->holdg_k++;
}

static bool io_rbc_eval(struct io_rbc_group *g, u64 now, bool entry)
{
	struct io_rbc_reg *victim;
	struct io_rbc_scan scan;

	if (!READ_ONCE(sqpoll_safe_count)) {
		io_rbc_clear_bit(g);
		io_rbc_clear_runs(g);
		return false;
	}
	scan = io_rbc_scan(g, now);
	if (g->settling && !io_rbc_runnable(g->settling->task)) {
		g->settling = NULL;
		g->settles++;
		io_rbc_clear_runs(g);
	}
	if (scan.over && !g->settling) {
		if (!g->over_run) {
			g->over_run = true;
			g->over_start_ns = now;
			g->over_evals = 1;
		} else if (g->over_evals < 2) {
			g->over_evals++;
		}
		if (!g->crowded && g->over_evals >= 2 &&
		    now - g->over_start_ns >=
		    io_rbc_ns(READ_ONCE(sqpoll_safe_count_delta_us))) {
			victim = io_rbc_victim(g, NULL);
			if (victim) {
				io_rbc_set_bit(g, victim, now);
				io_rbc_recrowd(g, now);
			}
		} else if (g->crowded && now - g->crowded_ns >=
			   io_rbc_ns(READ_ONCE(sqpoll_safe_count_rotate_us))) {
			victim = io_rbc_victim(g, g->crowded);
			if (victim) {
				io_rbc_clear_bit(g);
				io_rbc_set_bit(g, victim, now);
				g->rotations++;
			}
		}
	} else {
		g->over_run = false;
		g->over_evals = 0;
		if (!scan.over)
			io_rbc_clear_bit(g);
	}
	if (!list_empty(&g->waitq) && scan.spare) {
		if (!g->free_run || !scan.same_free) {
			g->free_run = true;
			g->free_cpu = scan.first_free;
			g->free_start_ns = now;
		}
	} else {
		g->free_run = false;
	}
	if (!entry && g->free_run && !list_empty(&g->waitq) &&
	    now - g->free_start_ns >=
	    io_rbc_ns(READ_ONCE(sqpoll_safe_count_hold_us)) &&
	    now - g->last_grant_ns >= io_rbc_holdg(g)) {
		if (io_rbc_masks_match(g))
			io_rbc_grant(g, now);
		else
			io_rbc_stop(g, now);
	}
	WRITE_ONCE(g->last_eval_ns, now);
	return scan.over;
}

static void io_rbc_kick(struct io_rbc_group *g)
{
	unsigned int us = max(1U, READ_ONCE(sqpoll_safe_count_timer_us));

	if (!g->stopping && !g->timer_active) {
		WRITE_ONCE(g->timer_active, true);
		hrtimer_start(&g->timer, ns_to_ktime(io_rbc_ns(us)),
			      HRTIMER_MODE_REL_SOFT);
	}
}

static enum hrtimer_restart io_rbc_timer(struct hrtimer *timer)
{
	struct io_rbc_group *g = container_of(timer, struct io_rbc_group, timer);
	enum hrtimer_restart ret = HRTIMER_NORESTART;
	bool runnable = false, activity;
	struct io_rbc_reg *reg;
	unsigned long flags;
	unsigned int us;
	u64 now;

	spin_lock_irqsave(&g->lock, flags);
	if (g->stopping) {
		WRITE_ONCE(g->timer_active, false);
		goto out;
	}
	now = ktime_get_ns();
	activity = xchg(&g->activity, false);
	if (!io_rbc_masks_match(g))
		io_rbc_stop(g, now);
	else
		g->stopped = false;
	if (!g->stopped)
		io_rbc_eval(g, now, false);
	if (!READ_ONCE(sqpoll_safe_count)) {
		io_rbc_clear_bit(g);
		io_rbc_clear_runs(g);
		g->settling = NULL;
		while (!list_empty(&g->waitq))
			io_rbc_grant(g, now);
	}
	list_for_each_entry(reg, &g->regs, node) {
		if (io_rbc_runnable(reg->task)) {
			runnable = true;
			break;
		}
	}
	if (list_empty(&g->waitq) && !g->crowded && !activity && !runnable) {
		WRITE_ONCE(g->timer_active, false);
		/* Pairs with io_rbc_note_activity(): neither side loses a kick. */
		smp_mb();
		if (!READ_ONCE(g->activity))
			goto out;
		WRITE_ONCE(g->timer_active, true);
	}
	us = READ_ONCE(sqpoll_safe_count_timer_us);
	if (!runnable && !g->crowded)
		us = READ_ONCE(sqpoll_safe_count_idle_timer_us);
	hrtimer_forward_now(timer, ns_to_ktime(io_rbc_ns(max(1U, us))));
	ret = HRTIMER_RESTART;
out:
	spin_unlock_irqrestore(&g->lock, flags);
	return ret;
}

static void io_rbc_note_activity(struct io_rbc_group *g)
{
	unsigned long flags;

	WRITE_ONCE(g->activity, true);
	/* Pairs with the timer's final activity check after disarming. */
	smp_mb();
	if (!READ_ONCE(g->timer_active)) {
		spin_lock_irqsave(&g->lock, flags);
		io_rbc_kick(g);
		spin_unlock_irqrestore(&g->lock, flags);
	}
}

void io_rbc_activity(struct io_ring_ctx *ctx)
{
	struct io_rbc_reg *reg;

	rcu_read_lock();
	reg = rcu_dereference(ctx->rbc_reg);
	if (reg)
		io_rbc_note_activity(reg->grp);
	rcu_read_unlock();
}

void io_rbc_enter_done(struct io_ring_ctx *ctx)
{
	io_rbc_activity(ctx);
}

void io_rbc_enter(struct io_ring_ctx *ctx)
{
	struct io_rbc_group *g;
	struct io_rbc_reg *reg;
	unsigned long flags;
	u64 now, interval;

	rcu_read_lock();
	reg = rcu_dereference(ctx->rbc_reg);
	if (!reg)
		goto out;
	g = reg->grp;
	io_rbc_note_activity(g);
	now = ktime_get_ns();
	interval = io_rbc_ns(READ_ONCE(sqpoll_safe_count_eval_us));
	if (now - READ_ONCE(g->last_eval_ns) >= interval &&
	    spin_trylock_irqsave(&g->lock, flags)) {
		now = ktime_get_ns();
		if (!g->stopped && !g->stopping &&
		    now - g->last_eval_ns >= interval)
			io_rbc_eval(g, now, false);
		spin_unlock_irqrestore(&g->lock, flags);
	}
out:
	rcu_read_unlock();
}

static void io_rbc_free_arrays(struct io_rbc_group *g)
{
	kfree(g->nbuf);
	kfree(g->excl_set_ns);
	kfree(g->excl_since);
	kfree(g->excl_k);
	free_cpumask_var(g->cpus);
}

static struct io_rbc_group *io_rbc_alloc_group(void)
{
	struct io_rbc_group *g;
	int ret = -ENOMEM;

	g = kzalloc_obj(*g);
	if (!g)
		return ERR_PTR(-ENOMEM);
	if (!alloc_cpumask_var(&g->cpus, GFP_KERNEL))
		goto free_group;
	cpumask_copy(g->cpus, READ_ONCE(current->cpus_ptr));
	if (cpumask_weight(g->cpus) > 64) {
		ret = -E2BIG;
		goto free_arrays;
	}
	g->excl_k = kcalloc(nr_cpu_ids, sizeof(*g->excl_k), GFP_KERNEL);
	g->excl_since = kcalloc(nr_cpu_ids, sizeof(*g->excl_since), GFP_KERNEL);
	g->excl_set_ns = kcalloc(nr_cpu_ids, sizeof(*g->excl_set_ns), GFP_KERNEL);
	g->nbuf = kcalloc(nr_cpu_ids, sizeof(*g->nbuf), GFP_KERNEL);
	if (!g->excl_k || !g->excl_since || !g->excl_set_ns || !g->nbuf)
		goto free_arrays;
	spin_lock_init(&g->lock);
	INIT_LIST_HEAD(&g->regs);
	INIT_LIST_HEAD(&g->waitq);
	g->free_cpu = -1;
	g->mm = current->mm;
	mmgrab(g->mm);
	hrtimer_setup(&g->timer, io_rbc_timer, CLOCK_MONOTONIC,
		      HRTIMER_MODE_REL_SOFT);
	return g;

free_arrays:
	io_rbc_free_arrays(g);
free_group:
	kfree(g);
	return ERR_PTR(ret);
}

static struct io_rbc_group *io_rbc_find_group(struct mm_struct *mm)
{
	struct io_rbc_group *g;

	hash_for_each_possible(io_rbc_groups, g, hnode,
			       hash_ptr(mm, HASH_BITS(io_rbc_groups))) {
		if (g->mm == mm)
			return g;
	}
	return NULL;
}

static int io_rbc_register_worker(struct io_ring_ctx *ctx, void __user *arg,
				  unsigned int nr_args)
{
	struct io_uring_rb_worker_reg user_reg;
	struct io_rbc_group *g;
	struct io_rbc_reg *reg;
	unsigned long flags;
	int ret;

	if (nr_args != 1)
		return -EINVAL;
	if (copy_from_user(&user_reg, arg, sizeof(user_reg)))
		return -EFAULT;
	if (user_reg.flags & ~IORING_RB_WORKER_BASE || user_reg.resv[0] ||
	    user_reg.resv[1] || user_reg.resv[2] || !current->mm)
		return -EINVAL;
	if (!((ctx->flags & IORING_SETUP_SINGLE_ISSUER) &&
	      ctx->submitter_task == current) &&
	    !(ctx->ringback && ctx->ringback_owner == current))
		return -EINVAL;
	if (ctx->flags & (IORING_SETUP_IOPOLL | IORING_SETUP_R_DISABLED))
		return -EINVAL;
	/* Task-context setup may take uring_lock; no RBC locks are held. */
	ret = io_uring_add_tctx_node(ctx);
	if (ret)
		return ret;

	mutex_lock(&io_rbc_mutex);
	ret = -EBUSY;
	if (rcu_access_pointer(ctx->rbc_reg) || current->io_uring->rbc_reg)
		goto unlock;
	reg = kzalloc_obj(*reg);
	if (!reg) {
		ret = -ENOMEM;
		goto unlock;
	}
	g = io_rbc_find_group(current->mm);
	if (g) {
		if (!cpumask_equal(READ_ONCE(current->cpus_ptr), g->cpus)) {
			ret = -EINVAL;
			goto free_reg;
		}
	} else {
		g = io_rbc_alloc_group();
		if (IS_ERR(g)) {
			ret = PTR_ERR(g);
			goto free_reg;
		}
		hash_add(io_rbc_groups, &g->hnode,
			 hash_ptr(g->mm, HASH_BITS(io_rbc_groups)));
	}
	reg->ctx = ctx;
	reg->task = current;
	reg->grp = g;
	reg->flags = user_reg.flags;
	reg->start_ns = ktime_get_ns();
	INIT_LIST_HEAD(&reg->wnode);
	get_task_struct(current);
	spin_lock_irqsave(&g->lock, flags);
	list_add_tail(&reg->node, &g->regs);
	rcu_assign_pointer(ctx->rbc_reg, reg);
	current->io_uring->rbc_reg = reg;
	io_rbc_kick(g);
	spin_unlock_irqrestore(&g->lock, flags);
	mutex_unlock(&io_rbc_mutex);
	return 0;

free_reg:
	kfree(reg);
unlock:
	mutex_unlock(&io_rbc_mutex);
	return ret;
}

/*
 * A worker sleeping in WAIT_SPARE is never detached by another context.
 * Exit, exec and unregister run in that worker outside the wait syscall;
 * ring exit requires all file references gone, including the waiter's.
 */
static bool __io_rbc_detach(struct io_rbc_reg *reg, bool *empty)
{
	struct io_rbc_group *g = reg->grp;
	unsigned long flags;

	lockdep_assert_held(&io_rbc_mutex);
	spin_lock_irqsave(&g->lock, flags);
	if (reg->dead) {
		spin_unlock_irqrestore(&g->lock, flags);
		return false;
	}
	reg->dead = true;
	list_del_init(&reg->node);
	if (reg->queued) {
		list_del_init(&reg->wnode);
		reg->queued = false;
	}
	if (g->crowded == reg)
		io_rbc_clear_bit(g);
	if (g->settling == reg)
		g->settling = NULL;
	io_rbc_clear_runs(g);
	*empty = list_empty(&g->regs);
	if (*empty)
		g->stopping = true;
	spin_unlock_irqrestore(&g->lock, flags);
	RCU_INIT_POINTER(reg->ctx->rbc_reg, NULL);
	reg->task->io_uring->rbc_reg = NULL;
	if (*empty)
		hash_del(&g->hnode);
	return true;
}

/*
 * No grace period wait here: it would delay every exiting worker thread.
 * RCU readers of ctx->rbc_reg only follow reg->grp, read scalar fields and
 * compare reg->task with current; they never dereference the task. Once
 * g->stopping is set (under g->lock, before this) and the timer is
 * cancelled, nothing evaluates, kicks the timer or touches the per-CPU
 * arrays, so they can go now; the group itself is freed after a grace
 * period because readers may still take its lock.
 */
static void io_rbc_release(struct io_rbc_reg *reg, bool empty)
{
	struct io_rbc_group *g = reg->grp;

	put_task_struct(reg->task);
	kfree_rcu(reg, rcu);
	if (!empty)
		return;
	hrtimer_cancel(&g->timer);
	mmdrop(g->mm);
	io_rbc_free_arrays(g);
	kfree_rcu(g, rcu);
}

static int io_rbc_unregister_worker(struct io_ring_ctx *ctx,
				    void __user *arg, unsigned int nr_args)
{
	struct io_rbc_reg *reg;
	bool empty = false;
	int ret = 0;

	if (arg || nr_args)
		return -EINVAL;
	mutex_lock(&io_rbc_mutex);
	reg = rcu_dereference_protected(ctx->rbc_reg,
					lockdep_is_held(&io_rbc_mutex));
	if (!reg) {
		ret = -ENOENT;
	} else if (reg->task != current) {
		ret = -EPERM;
		reg = NULL;
	} else if (!__io_rbc_detach(reg, &empty)) {
		reg = NULL;
	}
	mutex_unlock(&io_rbc_mutex);
	if (reg)
		io_rbc_release(reg, empty);
	return ret;
}

int io_rbc_register(struct io_ring_ctx *ctx, unsigned int opcode,
		    void __user *arg, unsigned int nr_args)
{
	switch (opcode) {
	case IORING_REGISTER_RB_WORKER:
		return io_rbc_register_worker(ctx, arg, nr_args);
	case IORING_UNREGISTER_RB_WORKER:
		return io_rbc_unregister_worker(ctx, arg, nr_args);
	default:
		return -EINVAL;
	}
}

void io_rbc_task_exit(void)
{
	struct io_rbc_reg *reg;
	bool empty = false;

	if (!current->io_uring || !READ_ONCE(current->io_uring->rbc_reg))
		return;
	mutex_lock(&io_rbc_mutex);
	reg = current->io_uring->rbc_reg;
	if (reg && !__io_rbc_detach(reg, &empty))
		reg = NULL;
	mutex_unlock(&io_rbc_mutex);
	if (reg)
		io_rbc_release(reg, empty);
}

void io_rbc_ctx_exit(struct io_ring_ctx *ctx)
{
	struct io_rbc_reg *reg;
	bool empty = false;

	if (!rcu_access_pointer(ctx->rbc_reg))
		return;
	mutex_lock(&io_rbc_mutex);
	reg = rcu_dereference_protected(ctx->rbc_reg,
					lockdep_is_held(&io_rbc_mutex));
	if (reg && !__io_rbc_detach(reg, &empty))
		reg = NULL;
	mutex_unlock(&io_rbc_mutex);
	if (reg)
		io_rbc_release(reg, empty);
}

static bool io_rbc_pending(struct io_ring_ctx *ctx)
{
	bool pending;

	rcu_read_lock();
	pending = io_has_work_for(ctx, current) || __io_cqring_events_user(ctx) ||
		  task_work_pending(current) || READ_ONCE(ctx->check_cq);
	rcu_read_unlock();
	return pending;
}

int io_rbc_wait_spare(struct io_ring_ctx *ctx, u32 flags,
		      struct ext_arg *ext_arg)
{
	/* Not autoremove: the entry stays queued for the whole wait. */
	DEFINE_WAIT_FUNC(wait, default_wake_function);
	bool defer = ctx->flags & IORING_SETUP_DEFER_TASKRUN;
	enum hrtimer_mode mode = HRTIMER_MODE_REL;
	struct hrtimer_sleeper sleeper;
	struct io_rbc_group *g;
	struct io_rbc_reg *reg;
	unsigned long irqflags;
	bool over;
	u64 now;
	int ret;

	rcu_read_lock();
	reg = rcu_dereference(ctx->rbc_reg);
	if (!reg || reg->task != current ||
	    (reg->flags & IORING_RB_WORKER_BASE) || ext_arg->min_time) {
		rcu_read_unlock();
		return -EINVAL;
	}
	g = reg->grp;
	/* The worker and the syscall's file reference pin this registration. */
	rcu_read_unlock();

	if (ext_arg->ts_set) {
		ktime_t expires = timespec64_to_ktime(ext_arg->ts);

		if (flags & IORING_ENTER_ABS_TIMER) {
			mode = HRTIMER_MODE_ABS;
			expires = timens_ktime_to_host(ctx->clockid, expires);
		}
		hrtimer_setup_sleeper_on_stack(&sleeper, ctx->clockid, mode);
		hrtimer_set_expires(&sleeper.timer, expires);
		hrtimer_sleeper_start_expires(&sleeper, mode);
	}
	if (ext_arg->sig) {
#ifdef CONFIG_COMPAT
		if (in_compat_syscall())
			ret = set_compat_user_sigmask((const compat_sigset_t __user *)ext_arg->sig,
						      ext_arg->argsz);
		else
#endif
			ret = set_user_sigmask(ext_arg->sig, ext_arg->argsz);
		if (ret)
			goto cancel_timer;
	}
	/*
	 * Queue the wait entry while still preemptible: cq_wait.lock may be a
	 * sleeping lock (PREEMPT_RT), and the sleep below runs with preemption
	 * disabled from the acceptance on. DEFER_TASKRUN rings are woken
	 * through ->cq_wait_nr and the submitter task instead.
	 */
	if (!defer)
		add_wait_queue(&ctx->cq_wait, &wait);

	spin_lock_irqsave(&g->lock, irqflags);
	now = ktime_get_ns();
	ret = -EINVAL;
	if (reg->dead)
		goto unlock;
	if (!io_rbc_masks_match(g))
		io_rbc_stop(g, now);
	if (!reg->queued && !reg->granted) {
		ret = 0;
		if (!READ_ONCE(sqpoll_safe_count) || g->stopped)
			goto unlock;
		over = io_rbc_eval(g, now, true);
		if (g->crowded != reg || !over || g->settling) {
			g->refusals++;
			goto unlock;
		}
		io_rbc_clear_bit(g);
		io_rbc_clear_runs(g);
		reg->queued = true;
		list_add_tail(&reg->wnode, &g->waitq);
		g->settling = reg;
		g->parks++;
		io_rbc_kick(g);
	}
	/* No preemption between the acceptance and the sleep. */
	preempt_disable();
	spin_unlock_irqrestore(&g->lock, irqflags);

	for (;;) {
		/* Arm like io_cqring_wait(): a completion must wake us. */
		if (defer || io_ringback_local_runner(ctx))
			atomic_set(&ctx->cq_wait_nr, 1);
		set_current_state(TASK_INTERRUPTIBLE);
		if (READ_ONCE(reg->granted)) {
			ret = 0;
			break;
		}
		if (io_rbc_pending(ctx)) {
			ret = -EAGAIN;
			break;
		}
		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}
		if (ext_arg->ts_set && !READ_ONCE(sleeper.task)) {
			ret = -ETIME;
			break;
		}
		schedule_preempt_disabled();
	}
	__set_current_state(TASK_RUNNING);
	if (defer || !ctx->ringback || io_ringback_local_runner(ctx)) {
		atomic_set(&ctx->cq_wait_nr, IO_CQ_WAKE_INIT);
		if (ctx->ringback) {
			/* Order disarm against the producer's work push. */
			smp_mb();
		}
	}
	preempt_enable();

	spin_lock_irqsave(&g->lock, irqflags);
	if (g->settling == reg) {
		g->settling = NULL;
		io_rbc_clear_runs(g);
	}
	if (reg->granted) {
		/* A grant racing with any other wake reason still takes priority. */
		WRITE_ONCE(reg->granted, false);
		reg->start_ns = ktime_get_ns();
		ret = 0;
	}
unlock:
	spin_unlock_irqrestore(&g->lock, irqflags);
	if (!defer)
		remove_wait_queue(&ctx->cq_wait, &wait);
cancel_timer:
	if (ext_arg->ts_set) {
		hrtimer_cancel(&sleeper.timer);
		destroy_hrtimer_on_stack(&sleeper.timer);
	}
	restore_saved_sigmask_unless(ret == -EINTR);
	return ret;
}

void io_rbc_fdinfo(struct io_ring_ctx *ctx, struct seq_file *m)
{
	struct io_rbc_reg *reg, *waiter;
	struct io_rbc_group *g;
	unsigned int waiters = 0;
	unsigned long flags;

	rcu_read_lock();
	reg = rcu_dereference(ctx->rbc_reg);
	if (!reg)
		goto out;
	g = reg->grp;
	/* The wait queue is an ordinary list, not an RCU list. */
	spin_lock_irqsave(&g->lock, flags);
	list_for_each_entry(waiter, &g->waitq, wnode)
		waiters++;
	spin_unlock_irqrestore(&g->lock, flags);
	/* Diagnostic fields are independent samples, not a coherent snapshot. */
	seq_printf(m, "SqCount:\tbase=%d queued=%d granted=%d crowded=%d "
		   "settling=%d stopped=%d waiters=%u parks=%llu refusals=%llu "
		   "grants=%llu bits=%llu rotations=%llu settles=%llu "
		   "excl_marks=%llu stops=%llu evals=%llu eval_ns=%llu holdg_k=%u\n",
		   !!(reg->flags & IORING_RB_WORKER_BASE),
		   data_race(reg->queued), data_race(reg->granted),
		   data_race(g->crowded) == reg, data_race(g->settling) == reg,
		   data_race(g->stopped), waiters,
		   data_race(g->parks), data_race(g->refusals),
		   data_race(g->grants), data_race(g->bits),
		   data_race(g->rotations), data_race(g->settles),
		   data_race(g->excl_marks), data_race(g->stops),
		   data_race(g->evals), data_race(g->eval_ns),
		   data_race(g->holdg_k));
out:
	rcu_read_unlock();
}
