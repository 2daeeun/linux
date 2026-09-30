// SPDX-License-Identifier: GPL-2.0
/*
 * Advisory lower-cache writeback range aggregation for native passthrough.
 * This does not enable FUSE_WRITEBACK_CACHE or create an upper data cache.
 * Only empty local ext4 files are admitted; all payload I/O stays native.
 */
#include "fuse_i.h"
#include "passthrough_wb_hints.h"

#include <linux/atomic.h>
#include <linux/backing-dev.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/jiffies.h>
#include <linux/moduleparam.h>
#include <linux/pagemap.h>
#include <linux/refcount.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#define WB_HINT_BYTES SZ_1M
#define WB_HINT_PERIOD_MS 100
#define WB_HINT_EXCLUDED_IO (IOCB_DIRECT | IOCB_APPEND | IOCB_SYNC | \
			     IOCB_DSYNC | IOCB_NOWAIT | IOCB_ATOMIC)

static bool passthrough_seq_wb_hints;
module_param(passthrough_seq_wb_hints, bool, 0644);
MODULE_PARM_DESC(passthrough_seq_wb_hints,
		"Advisory writeback hints for initially empty ext4 files");

/* Ordered execution and one shared cooldown prevent per-open amplification. */
static struct workqueue_struct *wb_hint_wq;
static unsigned long wb_hint_next_global;

static atomic64_t stat_accepted_opens = ATOMIC64_INIT(0);
static atomic64_t stat_boundary_events = ATOMIC64_INIT(0);
static atomic64_t stat_queued = ATOMIC64_INIT(0);
static atomic64_t stat_worker_runs = ATOMIC64_INIT(0);
static atomic64_t stat_helper_calls = ATOMIC64_INIT(0);
static atomic64_t stat_helper_errors = ATOMIC64_INIT(0);
static atomic64_t stat_skipped_throttle = ATOMIC64_INIT(0);
static atomic64_t stat_skipped_clean = ATOMIC64_INIT(0);
static atomic64_t stat_skipped_freeze = ATOMIC64_INIT(0);
static atomic64_t stat_cancelled = ATOMIC64_INIT(0);
static atomic64_t stat_live_states = ATOMIC64_INIT(0);
static atomic64_t stat_active_workers = ATOMIC64_INIT(0);

/* Read outside measured I/O. Updates occur only in optional slow paths. */
static int wb_hint_stats_get(char *buf, const struct kernel_param *kp)
{
	int n = 0;

	n += scnprintf(buf + n, PAGE_SIZE - n, "accepted_opens=%lld ",
		       (long long)atomic64_read(&stat_accepted_opens));
	n += scnprintf(buf + n, PAGE_SIZE - n, "boundary_events=%lld ",
		       (long long)atomic64_read(&stat_boundary_events));
	n += scnprintf(buf + n, PAGE_SIZE - n, "queued=%lld ",
		       (long long)atomic64_read(&stat_queued));
	n += scnprintf(buf + n, PAGE_SIZE - n, "worker_runs=%lld ",
		       (long long)atomic64_read(&stat_worker_runs));
	n += scnprintf(buf + n, PAGE_SIZE - n, "helper_calls=%lld ",
		       (long long)atomic64_read(&stat_helper_calls));
	n += scnprintf(buf + n, PAGE_SIZE - n, "helper_errors=%lld ",
		       (long long)atomic64_read(&stat_helper_errors));
	n += scnprintf(buf + n, PAGE_SIZE - n, "skipped_throttle=%lld ",
		       (long long)atomic64_read(&stat_skipped_throttle));
	n += scnprintf(buf + n, PAGE_SIZE - n, "skipped_clean=%lld ",
		       (long long)atomic64_read(&stat_skipped_clean));
	n += scnprintf(buf + n, PAGE_SIZE - n, "skipped_freeze=%lld ",
		       (long long)atomic64_read(&stat_skipped_freeze));
	n += scnprintf(buf + n, PAGE_SIZE - n, "cancelled=%lld ",
		       (long long)atomic64_read(&stat_cancelled));
	n += scnprintf(buf + n, PAGE_SIZE - n, "live_states=%lld ",
		       (long long)atomic64_read(&stat_live_states));
	n += scnprintf(buf + n, PAGE_SIZE - n, "active_workers=%lld ",
		       (long long)atomic64_read(&stat_active_workers));
	n += scnprintf(buf + n, PAGE_SIZE - n, "\n");
	return n;
}

static const struct kernel_param_ops wb_hint_stats_ops = {
	.get = wb_hint_stats_get,
};
module_param_cb(passthrough_wb_hint_stats, &wb_hint_stats_ops, NULL, 0444);
MODULE_PARM_DESC(passthrough_wb_hint_stats,
		"Advisory writeback-hint counters; no payload counters");

static void wb_hint_put(struct fuse_passthrough_wb_hint *hint)
{
	if (!refcount_dec_and_test(&hint->refs))
		return;
	atomic64_dec(&stat_live_states);
	fput(hint->lower);
	put_cred(hint->cred);
	kfree(hint);
}

static void wb_hint_work(struct work_struct *work)
{
	struct fuse_passthrough_wb_hint *hint = container_of(
		to_delayed_work(work), struct fuse_passthrough_wb_hint, work);
	struct address_space *mapping = hint->lower->f_mapping;
	const struct cred *old_cred;
	loff_t start, end;
	int err = 0;

	atomic64_inc(&stat_worker_runs);
	atomic64_inc(&stat_active_workers);
	spin_lock(&hint->lock);
	if (READ_ONCE(hint->stopped) || !hint->valid) {
		spin_unlock(&hint->lock);
		goto done;
	}
	start = hint->start;
	end = hint->end;
	hint->valid = false;
	spin_unlock(&hint->lock);

	if (time_before(jiffies, wb_hint_next_global)) {
		atomic64_inc(&stat_skipped_throttle);
		goto done;
	}
	/* File-local tag checks do not prove that the entire device is idle. */
	if (!mapping_tagged(mapping, PAGECACHE_TAG_DIRTY) ||
	    mapping_tagged(mapping, PAGECACHE_TAG_WRITEBACK)) {
		atomic64_inc(&stat_skipped_clean);
		goto done;
	}
	/* Optional hints must not wait for a frozen lower superblock. */
	if (!file_start_write_trylock(hint->lower)) {
		atomic64_inc(&stat_skipped_freeze);
		goto done;
	}

	wb_hint_next_global = jiffies + msecs_to_jiffies(WB_HINT_PERIOD_MS);
	old_cred = override_creds(hint->cred);
	/* WB_SYNC_NONE may still sleep in filesystem allocation/journal work. */
	atomic64_inc(&stat_helper_calls);
	err = filemap_flush_range(mapping, start, end);
	if (err)
		atomic64_inc(&stat_helper_errors);
	revert_creds(old_cred);
	file_end_write(hint->lower);
	/* The cooldown starts again after this potentially slow helper returns. */
	wb_hint_next_global = jiffies + msecs_to_jiffies(WB_HINT_PERIOD_MS);
	/* The lower filesystem owns durable I/O error recording. In particular,
	 * an advisory allocation failure must not become a permanent fsync error.
	 */
done:
	spin_lock(&hint->lock);
	if (err)
		WRITE_ONCE(hint->stopped, true);
	hint->queued = false;
	/* Hints accumulated during this callback are optional and discarded. */
	hint->valid = false;
	spin_unlock(&hint->lock);
	atomic64_dec(&stat_active_workers);
	wb_hint_put(hint);
}

void fuse_passthrough_wb_hints_init(void)
{
	wb_hint_next_global = jiffies;
	/* Open samples the switch; existing states keep their lifetime policy. */
	wb_hint_wq = alloc_ordered_workqueue("fuse-wb-hints", WQ_FREEZABLE);
	/* Allocation failure leaves ordinary passthrough fully operational. */
}

void fuse_passthrough_wb_hints_exit(void)
{
	if (wb_hint_wq)
		destroy_workqueue(wb_hint_wq);
}

struct fuse_passthrough_wb_hint *
fuse_passthrough_wb_hint_open(struct file *lower, const struct cred *cred)
{
	struct inode *inode = file_inode(lower);
	struct fuse_passthrough_wb_hint *hint;

	if (!READ_ONCE(passthrough_seq_wb_hints) || !wb_hint_wq ||
	    !(lower->f_mode & FMODE_WRITE) ||
	    lower->f_flags & (O_DIRECT | O_APPEND | O_SYNC | O_DSYNC) ||
	    !S_ISREG(inode->i_mode) || IS_DAX(inode) ||
	    strcmp(inode->i_sb->s_type->name, "ext4") ||
	    !mapping_can_writeback(lower->f_mapping) || i_size_read(inode))
		return NULL;

	hint = kzalloc(sizeof(*hint), GFP_KERNEL);
	if (!hint)
		return NULL;
	spin_lock_init(&hint->lock);
	refcount_set(&hint->refs, 1);
	INIT_DELAYED_WORK(&hint->work, wb_hint_work);
	hint->lower = get_file(lower);
	hint->cred = get_cred(cred);
	hint->next_boundary = WB_HINT_BYTES;
	atomic64_inc(&stat_accepted_opens);
	atomic64_inc(&stat_live_states);
	return hint;
}

void fuse_passthrough_wb_hint_note(struct fuse_passthrough_wb_hint *hint,
				 struct kiocb *iocb, ssize_t ret)
{
	loff_t end = iocb->ki_pos;
	bool put_unqueued = false;

	if (ret <= 0 || READ_ONCE(hint->stopped))
		return;
	if (!is_sync_kiocb(iocb) || iocb->ki_flags & WB_HINT_EXCLUDED_IO) {
		WRITE_ONCE(hint->stopped, true);
		return;
	}
	/* Most 4KiB calls return from the inline helper before reaching here. */
	if (end < READ_ONCE(hint->next_boundary))
		return;
	/* Never retry a missed boundary or a contended advisory update. */
	if (end != READ_ONCE(hint->next_boundary)) {
		WRITE_ONCE(hint->stopped, true);
		return;
	}
	if (!spin_trylock(&hint->lock)) {
		WRITE_ONCE(hint->stopped, true);
		return;
	}
	if (READ_ONCE(hint->stopped) || end < hint->next_boundary)
		goto out;
	/* No large jumps or unaligned sampling; abandon the optional policy. */
	if (end != hint->next_boundary || end > LLONG_MAX - WB_HINT_BYTES) {
		WRITE_ONCE(hint->stopped, true);
		goto out;
	}
	atomic64_inc(&stat_boundary_events);
	WRITE_ONCE(hint->next_boundary, end + WB_HINT_BYTES);
	if (!hint->queued) {
		hint->start = end - WB_HINT_BYTES;
		hint->end = end - 1;
		hint->valid = true;
		hint->queued = true;
		refcount_inc(&hint->refs);
		if (!queue_delayed_work(wb_hint_wq, &hint->work,
					msecs_to_jiffies(WB_HINT_PERIOD_MS))) {
			hint->queued = false;
			hint->valid = false;
			put_unqueued = true;
		} else {
			atomic64_inc(&stat_queued);
		}
	}
out:
	spin_unlock(&hint->lock);
	if (put_unqueued)
		wb_hint_put(hint);
}

void fuse_passthrough_wb_hint_close(struct fuse_passthrough_wb_hint *hint)
{
	if (!hint)
		return;
	spin_lock(&hint->lock);
	WRITE_ONCE(hint->stopped, true);
	spin_unlock(&hint->lock);
	/* The queued callback owns a reference; close never waits for writeback. */
	if (cancel_delayed_work(&hint->work)) {
		atomic64_inc(&stat_cancelled);
		wb_hint_put(hint);
	}
	wb_hint_put(hint);
}
