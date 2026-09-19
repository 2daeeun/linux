// SPDX-License-Identifier: GPL-2.0-only
/* App-facing read_iter/write_iter statistics, before cache/splitting. */
#include "fuse_i.h"
#include "workload.h"

#include <linux/ktime.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>

struct fuse_workload_identity {
	u64 file;
	u64 task_start;
	u32 tid;
};

struct fuse_workload_bank {
	struct fuse_workload_op_stats op[2];
	struct fuse_workload_identity first[2];
	u32 flags;
};

struct fuse_workload_cpu {
	raw_spinlock_t lock;
	struct fuse_workload_bank bank[2];
};

struct fuse_workload {
	struct fuse_workload_cpu __percpu *cpu;
	u64 thresholds[3];
	u64 generation;
	u64 start_ns;
	atomic64_t epoch;
};

void fuse_workload_init(struct fuse_conn *fc)
{
	mutex_init(&fc->workload_mutex);
}

static void fuse_workload_free(struct fuse_workload *monitor)
{
	if (monitor) {
		free_percpu(monitor->cpu);
		kfree(monitor);
	}
}

void fuse_workload_destroy(struct fuse_conn *fc)
{
	struct fuse_workload *monitor;

	monitor = rcu_dereference_protected(fc->workload, 1);
	RCU_INIT_POINTER(fc->workload, NULL);
	if (monitor) {
		synchronize_rcu();
		fuse_workload_free(monitor);
	}
}

static void fuse_workload_identity_add(struct fuse_workload_op_stats *op,
				      struct fuse_workload_identity *first,
				      const struct fuse_workload_identity *id,
				      unsigned int files, unsigned int requesters)
{
	if (files) {
		if (!op->files) {
			first->file = id->file;
			op->files = files;
		} else if (files > 1 || first->file != id->file) {
			op->files = 2;
		}
	}
	if (requesters) {
		if (!op->requesters) {
			first->tid = id->tid;
			first->task_start = id->task_start;
			op->requesters = requesters;
		} else if (requesters > 1 || first->tid != id->tid ||
			   first->task_start != id->task_start) {
			op->requesters = 2;
		}
	}
}

void fuse_workload_observe(struct kiocb *iocb, struct iov_iter *iter, bool write)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_file *ff = iocb->ki_filp->private_data;
	struct fuse_workload_identity id;
	struct fuse_workload_op_stats *op;
	struct fuse_workload_cpu *cpu;
	struct fuse_workload_bank *bank;
	struct fuse_workload *monitor;
	u64 size = iov_iter_count(iter), epoch;
	unsigned long irqflags;
	unsigned int bucket, flags = 0;
	bool pair = false, contiguous = false;
	loff_t offset = iocb->ki_pos;

	/* The pointer check is the only work for ordinary disabled sessions. */
	if (!rcu_access_pointer(fc->workload) || !size)
		return;
	rcu_read_lock();
	monitor = rcu_dereference(fc->workload);
	if (!monitor)
		goto out;
	epoch = atomic64_read_acquire(&monitor->epoch);
	for (bucket = 0; bucket < 3; bucket++)
		if (size < monitor->thresholds[bucket])
			break;
	if (current->flags & (PF_IO_WORKER | PF_KTHREAD))
		flags |= FUSE_WORKLOAD_WORKER;
	if (write && (iocb->ki_flags & IOCB_APPEND))
		flags |= FUSE_WORKLOAD_APPEND;
	if (FUSE_IS_DAX(inode))
		flags |= FUSE_WORKLOAD_DAX;
	if ((!(ff->open_flags & FOPEN_DIRECT_IO) &&
	     fuse_file_passthrough(ff)) || fc->extfuse_wbcache_passthrough)
		flags |= FUSE_WORKLOAD_PASSTHROUGH;

	/* Sequence state belongs to this inode incarnation, not to an open fh. */
	spin_lock(&fi->workload_lock);
	if (offset >= 0 && size <= S64_MAX - offset &&
	    !(flags & FUSE_WORKLOAD_APPEND)) {
		if (fi->workload_epoch[write] == epoch) {
			pair = true;
			contiguous = fi->workload_end[write] == offset;
		}
		fi->workload_epoch[write] = epoch;
		fi->workload_end[write] = offset + size;
	} else {
		fi->workload_epoch[write] = 0;
	}
	spin_unlock(&fi->workload_lock);

	id.file = fi->extfuse_incarnation;
	id.tid = task_pid_nr_ns(current, fc->pid_ns);
	id.task_start = current->start_boottime;
	cpu = get_cpu_ptr(monitor->cpu);
	raw_spin_lock_irqsave(&cpu->lock, irqflags);
	bank = &cpu->bank[epoch & 1];
	op = &bank->op[write];
	op->count[bucket]++;
	op->bytes[bucket] += size;
	if (!op->min_size || size < op->min_size)
		op->min_size = size;
	op->max_size = max(size, op->max_size);
	op->seq_pairs += pair;
	op->seq_contiguous += contiguous;
	fuse_workload_identity_add(op, &bank->first[write], &id, 1, 1);
	bank->flags |= flags;
	raw_spin_unlock_irqrestore(&cpu->lock, irqflags);
	put_cpu_ptr(monitor->cpu);
out:
	rcu_read_unlock();
}

static long fuse_workload_configure(struct fuse_conn *fc, void __user *argp)
{
	struct fuse_workload_config config;
	struct fuse_workload *monitor = NULL, *old;
	int cpu;

	if (copy_from_user(&config, argp, sizeof(config)))
		return -EFAULT;
	if (config.version != FUSE_WORKLOAD_VERSION ||
	    config.flags & ~FUSE_WORKLOAD_ENABLE ||
	    config.reserved[0] || config.reserved[1])
		return -EINVAL;
	if (config.flags & FUSE_WORKLOAD_ENABLE) {
		if (!config.thresholds[0] ||
		    config.thresholds[0] >= config.thresholds[1] ||
		    config.thresholds[1] >= config.thresholds[2])
			return -EINVAL;
		monitor = kzalloc(sizeof(*monitor), GFP_KERNEL_ACCOUNT);
		if (!monitor)
			return -ENOMEM;
		monitor->cpu = alloc_percpu(struct fuse_workload_cpu);
		if (!monitor->cpu) {
			kfree(monitor);
			return -ENOMEM;
		}
		for_each_possible_cpu(cpu)
			raw_spin_lock_init(&per_cpu_ptr(monitor->cpu, cpu)->lock);
		memcpy(monitor->thresholds, config.thresholds,
		       sizeof(monitor->thresholds));
	}
	mutex_lock(&fc->workload_mutex);
	old = rcu_dereference_protected(fc->workload,
				       lockdep_is_held(&fc->workload_mutex));
	if (monitor) {
		monitor->generation = ++fc->workload_generation;
		atomic64_set(&monitor->epoch, ++fc->workload_epoch_ctr);
		monitor->start_ns = ktime_get_ns();
	}
	rcu_assign_pointer(fc->workload, monitor);
	/* Collector/control operations may sleep; the I/O path never waits. */
	synchronize_rcu();
	fuse_workload_free(old);
	mutex_unlock(&fc->workload_mutex);
	return 0;
}

static long fuse_workload_snapshot(struct fuse_conn *fc, void __user *argp)
{
	struct fuse_workload_snapshot snapshot = {};
	struct fuse_workload_identity first[2] = {};
	struct fuse_workload *monitor;
	u32 version;
	u64 epoch;
	int cpu, rw, bucket;

	if (copy_from_user(&version, argp, sizeof(version)))
		return -EFAULT;
	if (version != FUSE_WORKLOAD_VERSION)
		return -EINVAL;
	mutex_lock(&fc->workload_mutex);
	monitor = rcu_dereference_protected(fc->workload,
					 lockdep_is_held(&fc->workload_mutex));
	if (!monitor) {
		mutex_unlock(&fc->workload_mutex);
		return -ENODATA;
	}
	epoch = atomic64_read(&monitor->epoch);
	snapshot.version = FUSE_WORKLOAD_VERSION;
	snapshot.generation = monitor->generation;
	snapshot.window_id = epoch;
	snapshot.start_ns = monitor->start_ns;
	snapshot.end_ns = ktime_get_ns();
	monitor->start_ns = snapshot.end_ns;
	/* Publish the cleared destination bank before an observer can use it. */
	atomic64_set_release(&monitor->epoch, ++fc->workload_epoch_ctr);
	/* All writers of the retired bank must finish before reading it. */
	synchronize_rcu();
	for_each_possible_cpu(cpu) {
		struct fuse_workload_bank *bank;

		bank = &per_cpu_ptr(monitor->cpu, cpu)->bank[epoch & 1];
		snapshot.flags |= bank->flags;
		for (rw = 0; rw < 2; rw++) {
			struct fuse_workload_op_stats *dst = &snapshot.op[rw];
			struct fuse_workload_op_stats *src = &bank->op[rw];

			for (bucket = 0; bucket < 4; bucket++) {
				dst->count[bucket] += src->count[bucket];
				dst->bytes[bucket] += src->bytes[bucket];
			}
			if (src->min_size && (!dst->min_size ||
					     src->min_size < dst->min_size))
				dst->min_size = src->min_size;
			dst->max_size = max(dst->max_size, src->max_size);
			dst->seq_pairs += src->seq_pairs;
			dst->seq_contiguous += src->seq_contiguous;
			fuse_workload_identity_add(dst, &first[rw], &bank->first[rw],
					  src->files, src->requesters);
		}
		memset(bank, 0, sizeof(*bank));
	}
	mutex_unlock(&fc->workload_mutex);
	return copy_to_user(argp, &snapshot, sizeof(snapshot)) ? -EFAULT : 0;
}

long fuse_workload_ioctl(struct fuse_conn *fc, unsigned int cmd,
			void __user *argp)
{
	/* Pairs with fuse_set_initialized() publishing negotiated features. */
	if (!smp_load_acquire(&fc->initialized))
		return -EAGAIN;
	if (!fc->workload_monitor)
		return -EOPNOTSUPP;
	if (!READ_ONCE(fc->connected))
		return -ENOTCONN;
	if (cmd == FUSE_DEV_IOC_MONITOR_CONFIG)
		return fuse_workload_configure(fc, argp);
	if (cmd == FUSE_DEV_IOC_MONITOR_SNAPSHOT)
		return fuse_workload_snapshot(fc, argp);
	return -ENOTTY;
}
