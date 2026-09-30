/* SPDX-License-Identifier: GPL-2.0 */
#ifndef FUSE_PASSTHROUGH_WB_HINTS_H
#define FUSE_PASSTHROUGH_WB_HINTS_H

#include <linux/fs.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

struct cred;
struct file;
struct kiocb;
struct fuse_passthrough_wb_hint;

#ifdef CONFIG_FUSE_PASSTHROUGH
struct fuse_passthrough_wb_hint {
	spinlock_t lock;
	refcount_t refs;
	struct delayed_work work;
	struct file *lower;
	const struct cred *cred;
	loff_t next_boundary;
	loff_t start;
	loff_t end;
	bool stopped;
	bool queued;
	bool valid;
};

void fuse_passthrough_wb_hints_init(void);
void fuse_passthrough_wb_hints_exit(void);
struct fuse_passthrough_wb_hint *
fuse_passthrough_wb_hint_open(struct file *lower, const struct cred *cred);
void fuse_passthrough_wb_hint_note(struct fuse_passthrough_wb_hint *hint,
				 struct kiocb *iocb, ssize_t ret);
void fuse_passthrough_wb_hint_close(struct fuse_passthrough_wb_hint *hint);

static inline void
fuse_passthrough_wb_hint_maybe_note(struct fuse_passthrough_wb_hint *hint,
				  struct kiocb *iocb, ssize_t ret)
{
	if (unlikely(hint) && ret > 0 && !READ_ONCE(hint->stopped) &&
	    iocb->ki_pos >= READ_ONCE(hint->next_boundary))
		fuse_passthrough_wb_hint_note(hint, iocb, ret);
}
#else
static inline void fuse_passthrough_wb_hints_init(void) {}
static inline void fuse_passthrough_wb_hints_exit(void) {}
#endif

#endif
