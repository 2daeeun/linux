// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE passthrough to backing file.
 *
 * Copyright (c) 2023 CTERA Networks.
 */

#include "fuse_i.h"
#include "fuse_cpu_scope.h"
#include "extfuse_i.h"

#include <linux/file.h>
#include <linux/backing-file.h>
#include <linux/splice.h>

static struct fuse_backing *
fuse_passthrough_inode_backing_get(struct fuse_inode *fi)
{
	struct fuse_backing *fb;

	spin_lock(&fi->lock);
	fb = fuse_backing_get(fuse_inode_backing(fi));
	spin_unlock(&fi->lock);

	return fb;
}

static void fuse_passthrough_kstat_to_attr(struct fuse_conn *fc,
					   const struct kstat *stat,
					   struct fuse_attr *attr)
{
	memset(attr, 0, sizeof(*attr));
	attr->ino = stat->ino;
	attr->size = stat->size;
	attr->blocks = stat->blocks;
	attr->atime = stat->atime.tv_sec;
	attr->mtime = stat->mtime.tv_sec;
	attr->ctime = stat->ctime.tv_sec;
	attr->atimensec = stat->atime.tv_nsec;
	attr->mtimensec = stat->mtime.tv_nsec;
	attr->ctimensec = stat->ctime.tv_nsec;
	attr->mode = stat->mode;
	attr->nlink = stat->nlink;
	attr->uid = from_kuid_munged(fc->user_ns, stat->uid);
	attr->gid = from_kgid_munged(fc->user_ns, stat->gid);
	attr->rdev = new_encode_dev(stat->rdev);
	attr->blksize = stat->blksize;
}

/*
 * Best-effort synchronization of the daemon's GETATTR cache from the backing
 * inode.  Every failure is an optimization miss: the caller always sends the
 * original request and exposes only that request's result to userspace.
 */
void fuse_passthrough_attr_refresh(struct inode *inode)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct extfuse_passthrough_attr_cookie cookie;
	struct fuse_backing *fb;
	struct fuse_attr attr;
	struct kstat stat;
	const struct cred *old_cred;
	int err;
	FUSE_CPU_SCOPE(fc);

	if (!S_ISREG(inode->i_mode) ||
	    !READ_ONCE(fc->extfuse_passthrough_attr_refresh))
		return;

	fb = fuse_passthrough_inode_backing_get(fi);
	if (!fb)
		return;

	err = extfuse_passthrough_attr_prepare(fc, get_node_id(inode),
					       &cookie);
	if (err)
		goto out;

	old_cred = override_creds(fb->cred);
	err = vfs_getattr(&fb->file->f_path, &stat, STATX_BASIC_STATS,
			  AT_STATX_SYNC_AS_STAT);
	revert_creds(old_cred);
	if (err)
		goto out;
	if ((stat.result_mask & STATX_BASIC_STATS) != STATX_BASIC_STATS ||
	    !S_ISREG(stat.mode) || stat.size < 0)
		goto out;

	fuse_passthrough_kstat_to_attr(fc, &stat, &attr);
	(void)extfuse_passthrough_attr_commit(fc, get_node_id(inode),
					      &cookie, &attr);
out:
	fuse_backing_put(fb);
}

static int fuse_passthrough_extfuse_notify(struct file *file, u32 opcode,
					   u32 phase)
{
	struct fuse_file *ff = file->private_data;

	return extfuse_passthrough_notify_inode(ff->fm->fc, file_inode(file),
					       opcode, phase);
}

static int fuse_passthrough_begin_io(struct kiocb *iocb, bool write)
{
	FUSE_CPU_SCOPE(get_fuse_conn(file_inode(iocb->ki_filp)));

	return fuse_passthrough_extfuse_notify(iocb->ki_filp,
			write ? EXTFUSE_PASSTHROUGH_WRITE :
				EXTFUSE_PASSTHROUGH_READ,
			EXTFUSE_PASSTHROUGH_PHASE_BEGIN);
}

static int fuse_passthrough_end_io(struct kiocb *iocb, ssize_t ret,
				   bool write)
{
	FUSE_CPU_SCOPE(get_fuse_conn(file_inode(iocb->ki_filp)));

	(void)ret;
	if (!write)
		fuse_invalidate_atime(file_inode(iocb->ki_filp));
	return fuse_passthrough_extfuse_notify(iocb->ki_filp,
			write ? EXTFUSE_PASSTHROUGH_WRITE :
				EXTFUSE_PASSTHROUGH_READ,
			EXTFUSE_PASSTHROUGH_PHASE_END);
}

static void fuse_file_accessed(struct file *file)
{
	struct inode *inode = file_inode(file);
	FUSE_CPU_SCOPE(get_fuse_conn(inode));

	fuse_invalidate_atime(inode);
}

static void fuse_passthrough_end_write(struct kiocb *iocb, ssize_t ret)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	FUSE_CPU_SCOPE(get_fuse_conn(inode));

	fuse_write_update_attr(inode, iocb->ki_pos, ret);
}

ssize_t fuse_passthrough_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = fuse_file_passthrough(ff);
	size_t count = iov_iter_count(iter);
	ssize_t ret;
	struct backing_file_ctx ctx = {
		.cred = ff->cred,
		.begin_io = fuse_passthrough_begin_io,
		.end_io = fuse_passthrough_end_io,
		.accessed = fuse_file_accessed,
	};


	pr_debug("%s: backing_file=0x%p, pos=%lld, len=%zu\n", __func__,
		 backing_file, iocb->ki_pos, count);

	if (!count)
		return 0;
	ret = backing_file_read_iter(backing_file, iter, iocb, iocb->ki_flags,
				     &ctx);

	return ret;
}

ssize_t fuse_passthrough_write_iter(struct kiocb *iocb,
				    struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = fuse_file_passthrough(ff);
	size_t count = iov_iter_count(iter);
	ssize_t ret;
	struct backing_file_ctx ctx = {
		.cred = ff->cred,
		.begin_io = fuse_passthrough_begin_io,
		.end_io = fuse_passthrough_end_io,
		.end_write = fuse_passthrough_end_write,
	};

	pr_debug("%s: backing_file=0x%p, pos=%lld, len=%zu\n", __func__,
		 backing_file, iocb->ki_pos, count);

	if (!count)
		return 0;
	inode_lock(inode);
	ret = backing_file_write_iter(backing_file, iter, iocb, iocb->ki_flags,
				      &ctx);
	inode_unlock(inode);

	return ret;
}

ssize_t fuse_passthrough_splice_read(struct file *in, loff_t *ppos,
				     struct pipe_inode_info *pipe,
				     size_t len, unsigned int flags)
{
	struct fuse_file *ff = in->private_data;
	struct file *backing_file = fuse_file_passthrough(ff);
	struct backing_file_ctx ctx = {
		.cred = ff->cred,
		.begin_io = fuse_passthrough_begin_io,
		.end_io = fuse_passthrough_end_io,
		.accessed = fuse_file_accessed,
	};
	struct kiocb iocb;
	ssize_t ret;

	pr_debug("%s: backing_file=0x%p, pos=%lld, len=%zu, flags=0x%x\n", __func__,
		 backing_file, *ppos, len, flags);

	init_sync_kiocb(&iocb, in);
	iocb.ki_pos = *ppos;
	ret = backing_file_splice_read(backing_file, &iocb, pipe, len, flags, &ctx);
	*ppos = iocb.ki_pos;

	return ret;
}

ssize_t fuse_passthrough_splice_write(struct pipe_inode_info *pipe,
				      struct file *out, loff_t *ppos,
				      size_t len, unsigned int flags)
{
	struct fuse_file *ff = out->private_data;
	struct file *backing_file = fuse_file_passthrough(ff);
	struct inode *inode = file_inode(out);
	ssize_t ret;
	struct backing_file_ctx ctx = {
		.cred = ff->cred,
		.begin_io = fuse_passthrough_begin_io,
		.end_io = fuse_passthrough_end_io,
		.end_write = fuse_passthrough_end_write,
	};
	struct kiocb iocb;

	pr_debug("%s: backing_file=0x%p, pos=%lld, len=%zu, flags=0x%x\n", __func__,
		 backing_file, *ppos, len, flags);

	inode_lock(inode);
	init_sync_kiocb(&iocb, out);
	iocb.ki_pos = *ppos;
	ret = backing_file_splice_write(pipe, backing_file, &iocb, len, flags, &ctx);
	*ppos = iocb.ki_pos;
	inode_unlock(inode);

	return ret;
}

ssize_t fuse_passthrough_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = fuse_file_passthrough(ff);
	struct backing_file_ctx ctx = {
		.cred = ff->cred,
		.accessed = fuse_file_accessed,
	};
	int ret;

	pr_debug("%s: backing_file=0x%p, start=%lu, end=%lu\n", __func__,
		 backing_file, vma->vm_start, vma->vm_end);
	ret = fuse_passthrough_extfuse_notify(
		file, EXTFUSE_PASSTHROUGH_READ,
		EXTFUSE_PASSTHROUGH_PHASE_BEGIN);
	if (ret)
		return ret;

	/*
	 * Page faults can update lower atime, and a writable shared mapping can
	 * update size/times long after FUSE RELEASE. Install a session-lifetime
	 * BPF marker before publishing every native mapping.
	 */
	ret = fuse_passthrough_extfuse_notify(file, EXTFUSE_PASSTHROUGH_MMAP,
					      EXTFUSE_PASSTHROUGH_PHASE_BEGIN);
	if (ret)
		goto out_end;
	/* Future page faults are not bracketed, so expire the VFS attr cache too. */
	fuse_invalidate_attr(file_inode(file));

	ret = backing_file_mmap(backing_file, vma, &ctx);
out_end:
	(void)fuse_passthrough_extfuse_notify(file, EXTFUSE_PASSTHROUGH_READ,
					     EXTFUSE_PASSTHROUGH_PHASE_END);
	return ret;
}

/*
 * Setup passthrough to a backing file.
 *
 * Returns an fb object with elevated refcount to be stored in fuse inode.
 */
struct fuse_backing *fuse_passthrough_open(struct file *file, int backing_id)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fm->fc;
	struct fuse_backing *fb = NULL;
	struct file *backing_file;
	int err;

	err = -EINVAL;
	if (backing_id <= 0)
		goto out;

	err = -ENOENT;
	fb = fuse_backing_lookup(fc, backing_id);
	if (!fb)
		goto out;

	/* Allocate backing file per fuse file to store fuse path */
	backing_file = backing_file_open(&file->f_path, file->f_flags,
					 &fb->file->f_path, fb->cred);
	err = PTR_ERR(backing_file);
	if (IS_ERR(backing_file)) {
		fuse_backing_put(fb);
		goto out;
	}

	err = 0;
	ff->passthrough = backing_file;
	ff->cred = get_cred(fb->cred);
out:
	pr_debug("%s: backing_id=%d, fb=0x%p, backing_file=0x%p, err=%i\n", __func__,
		 backing_id, fb, ff->passthrough, err);

	return err ? ERR_PTR(err) : fb;
}

void fuse_passthrough_release(struct fuse_file *ff, struct fuse_backing *fb)
{
	pr_debug("%s: fb=0x%p, backing_file=0x%p\n", __func__,
		 fb, ff->passthrough);

	fput(ff->passthrough);
	ff->passthrough = NULL;
	put_cred(ff->cred);
	ff->cred = NULL;
}
