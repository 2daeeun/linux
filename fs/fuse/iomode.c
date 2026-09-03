// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE inode io modes.
 *
 * Copyright (c) 2024 CTERA Networks.
 */

#include "fuse_i.h"
#include "dev_uring_i.h"

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fs.h>

/*
 * Return true if need to wait for new opens in caching mode.
 */
static inline bool fuse_is_io_cache_wait(struct fuse_inode *fi)
{
	return READ_ONCE(fi->iocachectr) < 0 && !fuse_inode_backing(fi);
}

/*
 * Called on cached file open() and on first mmap() of direct_io file.
 * Takes cached_io inode mode reference to be dropped on file release.
 *
 * Blocks new parallel dio writes and waits for the in-progress parallel dio
 * writes to complete.
 */
static int fuse_file_cached_io_start(struct inode *inode, struct fuse_file *ff,
				     struct fuse_backing *wbcache_fb)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_backing *inode_fb;

	/* There are no io modes if server does not implement open */
	if (!ff->args && !wbcache_fb)
		return 0;

	spin_lock(&fi->lock);
	/*
	 * Setting the bit advises new direct-io writes to use an exclusive
	 * lock - without it the wait below might be forever.
	 */
	while (fuse_is_io_cache_wait(fi)) {
		set_bit(FUSE_I_CACHE_IO_MODE, &fi->state);
		spin_unlock(&fi->lock);
		wait_event(fi->direct_io_waitq, !fuse_is_io_cache_wait(fi));
		spin_lock(&fi->lock);
	}

	/*
	 * Check if inode entered passthrough io mode while waiting for parallel
	 * dio write completion.
	 */
	if (fuse_inode_backing(fi)) {
		clear_bit(FUSE_I_CACHE_IO_MODE, &fi->state);
		spin_unlock(&fi->lock);
		return -ETXTBSY;
	}

	inode_fb = fi->extfuse_wbcache_fb;
	if ((!wbcache_fb && inode_fb) ||
	    (wbcache_fb && inode_fb && inode_fb != wbcache_fb) ||
	    (wbcache_fb && !inode_fb && fi->iocachectr > 0)) {
		spin_unlock(&fi->lock);
		return -EBUSY;
	}
	if (wbcache_fb) {
		if (!inode_fb) {
			inode_fb = fuse_backing_get(wbcache_fb);
			if (WARN_ON_ONCE(!inode_fb)) {
				spin_unlock(&fi->lock);
				return -ESTALE;
			}
			fi->extfuse_wbcache_fb = inode_fb;
		}
		fi->extfuse_wbcache_open_count++;
	}

	WARN_ON(ff->iomode == IOM_UNCACHED);
	if (ff->iomode == IOM_NONE) {
		ff->iomode = IOM_CACHED;
		if (fi->iocachectr == 0)
			set_bit(FUSE_I_CACHE_IO_MODE, &fi->state);
		fi->iocachectr++;
	}
	spin_unlock(&fi->lock);
	return 0;
}

int fuse_file_cached_io_open(struct inode *inode, struct fuse_file *ff)
{
	return fuse_file_cached_io_start(inode, ff, NULL);
}

static void fuse_file_cached_io_release(struct fuse_file *ff,
					struct fuse_inode *fi)
{
	struct fuse_backing *inode_fb = NULL;
	bool wbcache = !!fuse_file_wbcache_backing(ff);

	spin_lock(&fi->lock);
	WARN_ON(fi->iocachectr <= 0);
	WARN_ON(ff->iomode != IOM_CACHED);
	if (wbcache) {
		WARN_ON(!fi->extfuse_wbcache_open_count);
		if (fi->extfuse_wbcache_open_count)
			fi->extfuse_wbcache_open_count--;
		if (!fi->extfuse_wbcache_open_count) {
			inode_fb = fi->extfuse_wbcache_fb;
			fi->extfuse_wbcache_fb = NULL;
		}
	}
	ff->iomode = IOM_NONE;
	fi->iocachectr--;
	if (fi->iocachectr == 0)
		clear_bit(FUSE_I_CACHE_IO_MODE, &fi->state);
	spin_unlock(&fi->lock);

	if (inode_fb)
		fuse_backing_put(inode_fb);
	if (wbcache)
		fuse_wbcache_passthrough_release(ff);
}

/* Start strictly uncached io mode where cache access is not allowed */
int fuse_inode_uncached_io_start(struct fuse_inode *fi, struct fuse_backing *fb)
{
	struct fuse_backing *oldfb;
	int err = 0;

	spin_lock(&fi->lock);
	/* deny conflicting backing files on same fuse inode */
	oldfb = fuse_inode_backing(fi);
	if (fb && oldfb && oldfb != fb) {
		err = -EBUSY;
		goto unlock;
	}
	if (fi->iocachectr > 0) {
		err = -ETXTBSY;
		goto unlock;
	}
	fi->iocachectr--;

	/* fuse inode holds a single refcount of backing file */
	if (fb && !oldfb) {
		oldfb = fuse_inode_backing_set(fi, fb);
		WARN_ON_ONCE(oldfb != NULL);
	} else {
		fuse_backing_put(fb);
	}
unlock:
	spin_unlock(&fi->lock);
	return err;
}

/* Takes uncached_io inode mode reference to be dropped on file release */
static int fuse_file_uncached_io_open(struct inode *inode,
				      struct fuse_file *ff,
				      struct fuse_backing *fb)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	int err;

	err = fuse_inode_uncached_io_start(fi, fb);
	if (err)
		return err;

	WARN_ON(ff->iomode != IOM_NONE);
	ff->iomode = IOM_UNCACHED;
	return 0;
}

void fuse_inode_uncached_io_end(struct fuse_inode *fi)
{
	struct fuse_backing *oldfb = NULL;

	spin_lock(&fi->lock);
	WARN_ON(fi->iocachectr >= 0);
	fi->iocachectr++;
	if (!fi->iocachectr) {
		wake_up(&fi->direct_io_waitq);
		oldfb = fuse_inode_backing_set(fi, NULL);
	}
	spin_unlock(&fi->lock);
	if (oldfb)
		fuse_backing_put(oldfb);
}

/* Drop uncached_io reference from passthrough open */
static void fuse_file_uncached_io_release(struct fuse_file *ff,
					  struct fuse_inode *fi)
{
	WARN_ON(ff->iomode != IOM_UNCACHED);
	ff->iomode = IOM_NONE;
	fuse_inode_uncached_io_end(fi);
}

/*
 * Open flags that are allowed in combination with FOPEN_PASSTHROUGH.
 * A combination of FOPEN_PASSTHROUGH and FOPEN_DIRECT_IO means that read/write
 * operations go directly to the server, but mmap is done on the backing file.
 * FOPEN_PASSTHROUGH mode should not co-exist with any users of the fuse inode
 * page cache, so FOPEN_KEEP_CACHE is a strange and undesired combination.
 */
#define FOPEN_PASSTHROUGH_MASK \
	(FOPEN_PASSTHROUGH | FOPEN_DIRECT_IO | FOPEN_PARALLEL_DIRECT_WRITES | \
	 FOPEN_NOFLUSH)

static int fuse_file_passthrough_open(struct inode *inode, struct file *file)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_backing *fb;
	int err;

	/* Check allowed conditions for file open in passthrough mode */
	if (!IS_ENABLED(CONFIG_FUSE_PASSTHROUGH) || !fc->passthrough ||
	    (ff->open_flags & ~FOPEN_PASSTHROUGH_MASK))
		return -EINVAL;

	fb = fuse_passthrough_open(file, ff->args->open_outarg.backing_id);
	if (IS_ERR(fb))
		return PTR_ERR(fb);

	/* First passthrough file open denies caching inode io mode */
	err = fuse_file_uncached_io_open(inode, ff, fb);
	if (!err)
		return 0;

	fuse_passthrough_release(ff, fb);
	fuse_backing_put(fb);

	return err;
}

#define FOPEN_EXTFUSE_WBCACHE_MASK \
	(FOPEN_EXTFUSE_WBCACHE_PASSTHROUGH | FOPEN_KEEP_CACHE | FOPEN_NOFLUSH)

static int fuse_file_wbcache_passthrough_open(struct inode *inode,
					      struct file *file)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = get_fuse_conn(inode);
	int err;

	if (!IS_ENABLED(CONFIG_EXTFUSE) ||
	    !IS_ENABLED(CONFIG_FUSE_PASSTHROUGH) ||
	    !READ_ONCE(fc->extfuse_wbcache_passthrough) ||
	    !fc->writeback_cache ||
	    (ff->open_flags & ~FOPEN_EXTFUSE_WBCACHE_MASK))
		return -EINVAL;

	err = fuse_wbcache_passthrough_open(
		file, ff->args->open_outarg.backing_id);
	if (err)
		return err;

	err = fuse_file_cached_io_start(inode, ff,
					fuse_file_wbcache_backing(ff));
	if (err)
		fuse_wbcache_passthrough_release(ff);
	return err;
}

/* Request access to submit new io to inode via open file */
int fuse_file_io_open(struct file *file, struct inode *inode)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_conn *fc = get_fuse_conn(inode);
	int err = -EINVAL;

	/*
	 * io modes are not relevant with DAX and with server that does not
	 * implement open.
	 */
	if ((FUSE_IS_DAX(inode) || !ff->args) &&
	    !(ff->open_flags & FOPEN_EXTFUSE_WBCACHE_PASSTHROUGH))
		return 0;
	if (FUSE_IS_DAX(inode) || !ff->args)
		goto fail;

	if ((ff->open_flags & FOPEN_PASSTHROUGH) &&
	    (ff->open_flags & FOPEN_EXTFUSE_WBCACHE_PASSTHROUGH))
		goto fail;
	if (ff->open_flags & FOPEN_IO_URING_ZERO_COPY) {
		/* Zero-copy is a C2 transport, never a passthrough file mode. */
		if (!S_ISREG(inode->i_mode) || !READ_ONCE(fc->io_uring) ||
		    !READ_ONCE(fc->io_uring_bufpool) ||
		    !fuse_uring_zero_copy_ready(fc) ||
		    (ff->open_flags & (FOPEN_PASSTHROUGH |
				       FOPEN_EXTFUSE_WBCACHE_PASSTHROUGH)))
			goto fail;
	}
	if ((ff->open_flags & FOPEN_EXTFUSE_WBCACHE_PASSTHROUGH) &&
	    (ff->open_flags & (FOPEN_DIRECT_IO |
			       FOPEN_PARALLEL_DIRECT_WRITES)))
		goto fail;

	/*
	 * Server is expected to use FOPEN_PASSTHROUGH for all opens of an inode
	 * which is already open for passthrough.
	 */
	if (fuse_inode_backing(fi) && !(ff->open_flags & FOPEN_PASSTHROUGH))
		goto fail;
	if (fuse_inode_wbcache_backing(fi) &&
	    !(ff->open_flags & FOPEN_EXTFUSE_WBCACHE_PASSTHROUGH))
		goto fail;

	/*
	 * FOPEN_PARALLEL_DIRECT_WRITES requires FOPEN_DIRECT_IO.
	 */
	if (!(ff->open_flags & FOPEN_DIRECT_IO))
		ff->open_flags &= ~FOPEN_PARALLEL_DIRECT_WRITES;

	/*
	 * First passthrough file open denies caching inode io mode.
	 * First caching file open enters caching inode io mode.
	 *
	 * Note that if user opens a file open with O_DIRECT, but server did
	 * not specify FOPEN_DIRECT_IO, a later fcntl() could remove O_DIRECT,
	 * so we put the inode in caching mode to prevent parallel dio.
	 */
	if ((ff->open_flags & FOPEN_DIRECT_IO) &&
	    !(ff->open_flags & (FOPEN_PASSTHROUGH |
				FOPEN_EXTFUSE_WBCACHE_PASSTHROUGH)))
		return 0;

	if (ff->open_flags & FOPEN_PASSTHROUGH)
		err = fuse_file_passthrough_open(inode, file);
	else if (ff->open_flags & FOPEN_EXTFUSE_WBCACHE_PASSTHROUGH)
		err = fuse_file_wbcache_passthrough_open(inode, file);
	else
		err = fuse_file_cached_io_open(inode, ff);
	if (err)
		goto fail;

	return 0;

fail:
	pr_debug("failed to open file in requested io mode (open_flags=0x%x, err=%i).\n",
		 ff->open_flags, err);
	/*
	 * The file open mode determines the inode io mode.
	 * Using incorrect open mode is a server mistake, which results in
	 * user visible failure of open() with EIO error.
	 */
	return -EIO;
}

/* No more pending io and no new io possible to inode via open/mmapped file */
void fuse_file_io_release(struct fuse_file *ff, struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	/*
	 * Last passthrough file close allows caching inode io mode.
	 * Last caching file close exits caching inode io mode.
	 */
	switch (ff->iomode) {
	case IOM_NONE:
		/* Nothing to do */
		break;
	case IOM_UNCACHED:
		fuse_file_uncached_io_release(ff, fi);
		break;
	case IOM_CACHED:
		fuse_file_cached_io_release(ff, fi);
		break;
	}
}
