// SPDX-License-Identifier: GPL-2.0
/*
 * ExtFUSE passthrough below the ordinary FUSE writeback cache.
 *
 * The upper inode continues to use the FUSE page cache.  Only page-backed
 * FUSE_READ and FUSE_WRITE requests selected by the ExtFUSE policy are
 * forwarded to a daemon-registered lower file.
 */

#include "fuse_i.h"
#include "extfuse_i.h"
#include "fuse_trace.h"

#include <linux/backing-file.h>
#include <linux/bvec.h>
#include <linux/file.h>
#include <linux/overflow.h>
#include <linux/uio.h>

#define FUSE_WBCACHE_INLINE_BVECS 32

struct fuse_wbcache_io {
	struct file *file;
	const struct cred *cred;
	struct bio_vec *bvec;
	unsigned int nr_bvecs;
	loff_t pos;
	size_t count;
	rwf_t rwf;
	bool write;
	bool refs_owned;
	bool bvec_owned;
};

struct fuse_wbcache_alloc {
	struct fuse_wbcache_io io;
	struct bio_vec bvec[];
};

struct fuse_wbcache_paper_io {
	struct fuse_wbcache_io io;
	/* 512 bytes on 64-bit builds; larger requests use a heap fallback. */
	struct bio_vec inline_bvec[FUSE_WBCACHE_INLINE_BVECS];
};

static int fuse_wbcache_folio_count(struct fuse_req *req,
				    unsigned int *nr_folios)
{
	struct fuse_args *args = req->args;
	struct fuse_args_pages *ap;

	switch (args->opcode) {
	case FUSE_READ:
		if (!args->out_pages || args->in_pages)
			return -EINVAL;
		break;
	case FUSE_WRITE:
		if (!args->in_pages || args->out_pages)
			return -EINVAL;
		break;
	default:
		return -EOPNOTSUPP;
	}

	ap = container_of(args, struct fuse_args_pages, args);
	if (!ap->folios || !ap->descs || !ap->num_folios ||
	    ap->num_folios > req->fm->fc->max_pages)
		return -EINVAL;

	*nr_folios = ap->num_folios;
	return 0;
}

static int fuse_wbcache_lower_open_flags(const struct file *file)
{
	int flags;

	/*
	 * Re-open only an existing lower object.  In particular, never replay
	 * create, truncate, append, direct-I/O, or path-only semantics from the
	 * upper open onto lower page-cache I/O.
	 */
	flags = file->f_flags &
		(O_ACCMODE | O_LARGEFILE | O_NOATIME | O_DSYNC | O_SYNC);

	/* Writeback cache may issue a read against an O_WRONLY upper handle. */
	if ((flags & O_ACCMODE) == O_WRONLY)
		flags = (flags & ~O_ACCMODE) | O_RDWR;

	return flags;
}

int fuse_wbcache_passthrough_open(struct file *file, int backing_id)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fm->fc;
	struct fuse_backing *fb;
	struct file *lower;
	int flags;

	if (backing_id <= 0)
		return -EINVAL;

	fb = fuse_backing_lookup(fc, backing_id);
	if (!fb)
		return -ENOENT;

	flags = fuse_wbcache_lower_open_flags(file);
	lower = backing_file_open(&file->f_path, flags, &fb->file->f_path,
				  fb->cred);
	if (IS_ERR(lower)) {
		fuse_backing_put(fb);
		return PTR_ERR(lower);
	}

	ff->extfuse_wbcache_file = lower;
	ff->extfuse_wbcache_fb = fb;
	return 0;
}

void fuse_wbcache_passthrough_release(struct fuse_file *ff)
{
	if (ff->extfuse_wbcache_file) {
		fput(ff->extfuse_wbcache_file);
		ff->extfuse_wbcache_file = NULL;
	}
	if (ff->extfuse_wbcache_fb) {
		fuse_backing_put(ff->extfuse_wbcache_fb);
		ff->extfuse_wbcache_fb = NULL;
	}
}

static int fuse_wbcache_request_shape(struct fuse_req *req,
				      struct fuse_wbcache_io *io)
{
	struct fuse_args *args = req->args;
	struct fuse_file *ff = args->extfuse_file;
	struct fuse_args_pages *ap;
	struct fuse_conn *fc = req->fm->fc;
	struct inode *inode;
	size_t remaining;
	unsigned int i;

	if (!READ_ONCE(fc->extfuse_wbcache_passthrough) || !ff ||
	    ff->fm != req->fm ||
	    !(ff->open_flags & FOPEN_EXTFUSE_WBCACHE_PASSTHROUGH) ||
	    !ff->extfuse_wbcache_file || !ff->extfuse_wbcache_fb ||
	    args->nodeid != ff->nodeid || !args->extfuse_inode ||
	    get_node_id(args->extfuse_inode) != args->nodeid || args->is_ext)
		return -EINVAL;

	inode = file_inode(ff->extfuse_wbcache_file);
	if (!S_ISREG(inode->i_mode) ||
	    inode->i_sb->s_stack_depth >= fc->max_stack_depth)
		return -ELOOP;

	switch (args->opcode) {
	case FUSE_READ: {
		const struct fuse_read_in *in;

		if (args->in_numargs != 1 || args->out_numargs != 1 ||
		    !args->out_argvar || !args->out_pages || args->in_pages ||
		    !args->in_args[0].value ||
		    args->in_args[0].size != sizeof(*in) ||
		    !(ff->extfuse_wbcache_file->f_mode & FMODE_READ))
			return -EINVAL;
		in = args->in_args[0].value;
		if (in->padding || in->fh != ff->fh || !in->size ||
		    (in->flags & O_DIRECT) ||
		    args->out_args[0].size < in->size || in->offset > LLONG_MAX)
			return -EINVAL;
		io->pos = in->offset;
		io->count = in->size;
		break;
	}
	case FUSE_WRITE: {
		const struct fuse_write_in *in;
		struct fuse_write_out *out;

		if (args->in_numargs != 2 || args->out_numargs != 1 ||
		    args->out_argvar || !args->in_pages || args->out_pages ||
		    !args->in_args[0].value ||
		    args->in_args[0].size != sizeof(*in) ||
		    !args->out_args[0].value ||
		    args->out_args[0].size != sizeof(*out) ||
		    !(ff->extfuse_wbcache_file->f_mode & FMODE_WRITE))
			return -EINVAL;
		in = args->in_args[0].value;
		out = args->out_args[0].value;
		if (in->padding || in->fh != ff->fh || !in->size ||
		    (in->flags & O_DIRECT) ||
		    args->in_args[1].size != in->size || in->offset > LLONG_MAX)
			return -EINVAL;
		memset(out, 0, sizeof(*out));
		io->pos = in->offset;
		io->count = in->size;
		io->write = true;
		if (in->flags & O_DSYNC)
			io->rwf |= RWF_DSYNC;
		if (in->flags & O_SYNC)
			io->rwf |= RWF_SYNC;
		break;
	}
	default:
		return -EOPNOTSUPP;
	}

	if (io->count > (size_t)(LLONG_MAX - io->pos))
		return -EOVERFLOW;

	ap = container_of(args, struct fuse_args_pages, args);
	if (!ap->folios || !ap->descs || !ap->num_folios ||
	    ap->num_folios > fc->max_pages)
		return -EINVAL;

	remaining = io->count;
	for (i = 0; i < ap->num_folios && remaining; i++) {
		struct fuse_folio_desc *desc = &ap->descs[i];
		size_t length;

		if (!ap->folios[i] || desc->offset >= folio_size(ap->folios[i]) ||
		    desc->length > folio_size(ap->folios[i]) - desc->offset)
			return -EINVAL;
		length = min_t(size_t, remaining, desc->length);
		if (!length)
			return -EINVAL;
		bvec_set_folio(&io->bvec[io->nr_bvecs++], ap->folios[i],
				length, desc->offset);
		remaining -= length;
	}

	return remaining ? -EINVAL : 0;
}

static int fuse_wbcache_passthrough_init(struct fuse_req *req,
					 struct fuse_wbcache_io *io,
					 struct bio_vec *preallocated_bvec,
					 unsigned int preallocated_nr,
					 bool own_refs,
					 gfp_t gfp)
{
	struct fuse_file *ff = req->args->extfuse_file;
	unsigned int nr_folios;
	int err;

	memset(io, 0, sizeof(*io));
	err = fuse_wbcache_folio_count(req, &nr_folios);
	if (err)
		return err;

	if (nr_folios <= preallocated_nr) {
		io->bvec = preallocated_bvec;
	} else {
		io->bvec = kcalloc(nr_folios, sizeof(*io->bvec), gfp);
		if (!io->bvec)
			return -ENOMEM;
		io->bvec_owned = true;
	}

	err = fuse_wbcache_request_shape(req, io);
	if (err) {
		if (io->bvec_owned)
			kfree(io->bvec);
		io->bvec = NULL;
		return err;
	}

	if (own_refs) {
		io->file = get_file(ff->extfuse_wbcache_file);
		io->cred = get_cred(ff->extfuse_wbcache_fb->cred);
		io->refs_owned = true;
	} else {
		/*
		 * The request owner holds ff until completion: synchronous I/O has
		 * the VFS file reference, while readahead and writeback hold explicit
		 * fuse_file references.  fuse_file_io_release() therefore cannot
		 * release these backing objects while this lower operation runs.
		 */
		io->file = ff->extfuse_wbcache_file;
		io->cred = ff->extfuse_wbcache_fb->cred;
	}
	return 0;
}

static void fuse_wbcache_passthrough_cleanup(struct fuse_wbcache_io *io)
{
	if (io->refs_owned) {
		put_cred(io->cred);
		fput(io->file);
	}
	if (io->bvec_owned)
		kfree(io->bvec);
}

struct fuse_wbcache_io *fuse_wbcache_passthrough_prepare(struct fuse_req *req)
{
	struct fuse_wbcache_alloc *alloc;
	struct fuse_wbcache_io *io;
	unsigned int nr_folios;
	int err;

	err = fuse_wbcache_folio_count(req, &nr_folios);
	if (err)
		return ERR_PTR(err);
	alloc = kmalloc(struct_size(alloc, bvec, nr_folios), GFP_KERNEL);
	if (!alloc)
		return ERR_PTR(-ENOMEM);
	io = &alloc->io;

	err = fuse_wbcache_passthrough_init(req, io, alloc->bvec, nr_folios,
					    true, GFP_KERNEL);
	if (err) {
		kfree(alloc);
		return ERR_PTR(err);
	}

	return io;
}

ssize_t fuse_wbcache_passthrough_execute(struct fuse_req *req,
					 struct fuse_wbcache_io *io)
{
	struct fuse_args *args = req->args;
	struct fuse_args_pages *ap =
		container_of(args, struct fuse_args_pages, args);
	struct iov_iter iter;
	const struct cred *old_cred;
	ssize_t ret;
	unsigned int i;

	iov_iter_bvec(&iter, io->write ? ITER_SOURCE : ITER_DEST, io->bvec,
		       io->nr_bvecs, io->count);
	old_cred = override_creds(io->cred);
	if (io->write)
		ret = vfs_iter_write(io->file, &iter, &io->pos, io->rwf);
	else
		ret = vfs_iter_read(io->file, &iter, &io->pos, 0);
	revert_creds(old_cred);

	if (io->write) {
		struct fuse_write_out *out = args->out_args[0].value;

		if (ret >= 0)
			out->size = (u32)ret;
		if (ret >= 0 && (size_t)ret != io->count)
			return -EIO;
		return ret < 0 ? ret : 0;
	}

	if (ret >= 0 && ret < io->count &&
	    iov_iter_zero(io->count - ret, &iter) != io->count - ret)
		return -EIO;
	if (ret >= 0) {
		args->out_args[0].size = (unsigned int)ret;
		for (i = 0; i < ap->num_folios; i++)
			flush_dcache_folio(ap->folios[i]);
	}
	return ret;
}

void fuse_wbcache_passthrough_finish(struct fuse_wbcache_io *io)
{
	struct fuse_wbcache_alloc *alloc =
		container_of(io, struct fuse_wbcache_alloc, io);

	fuse_wbcache_passthrough_cleanup(io);
	kfree(alloc);
}

#define FUSE_WBCACHE_READ_BUSY S64_MAX
#define FUSE_WBCACHE_READ_JOIN_ATTEMPTS 4

static int fuse_wbcache_read_begin(struct fuse_conn *fc, struct inode *inode,
				  bool *cohort)
{
	atomic64_t *counter = &get_fuse_inode(inode)->extfuse_wbcache_read_refs;
	s64 refs = atomic64_read_acquire(counter);
	unsigned int attempt;
	int err;

	*cohort = false;
	for (attempt = 0; refs > 0 && refs < FUSE_WBCACHE_READ_BUSY - 1 &&
	     attempt < FUSE_WBCACHE_READ_JOIN_ATTEMPTS; attempt++) {
		if (atomic64_try_cmpxchg(counter, &refs, refs + 1)) {
			*cohort = true;
			return 0;
		}
	}
	if (!refs && atomic64_try_cmpxchg(counter, &refs, FUSE_WBCACHE_READ_BUSY)) {
		err = extfuse_paper_read_notify(fc, inode,
					       EXTFUSE_PASSTHROUGH_PHASE_BEGIN);
		if (err) {
			atomic64_set_release(counter, 0);
			return err;
		}
		*cohort = true;
		atomic64_set_release(counter, 1);
		return 0;
	}
	/* Never wait behind a first BEGIN or last atime publication. */
	return extfuse_paper_read_notify(fc, inode,
					 EXTFUSE_PASSTHROUGH_PHASE_BEGIN);
}

static void fuse_wbcache_read_end(struct fuse_req *req,
				 struct fuse_wbcache_io *io, bool cohort,
				 ssize_t result)
{
	struct fuse_conn *fc = req->fm->fc;
	struct inode *inode = req->args->extfuse_inode;
	atomic64_t *counter = &get_fuse_inode(inode)->extfuse_wbcache_read_refs;
	s64 refs;
	int err;

	if (cohort) {
		refs = atomic64_read_acquire(counter);
		for (;;) {
			s64 replacement;

			if (WARN_ON_ONCE(refs <= 0 || refs == FUSE_WBCACHE_READ_BUSY)) {
				fuse_abort_conn(fc);
				return;
			}
			replacement = refs == 1 ? FUSE_WBCACHE_READ_BUSY : refs - 1;
			if (atomic64_try_cmpxchg(counter, &refs, replacement))
				break;
		}
		if (refs != 1) {
			trace_fuse_wbcache_read_shared(fc->dev, get_node_id(inode),
						       result);
			return;
		}
	}
	err = extfuse_paper_read_notify(fc, inode, EXTFUSE_PASSTHROUGH_PHASE_END);
	if (!err)
		fuse_wbcache_read_atime_refresh(inode, io->file, io->cred);
	if (cohort)
		atomic64_set_release(counter, 0);
}

ssize_t fuse_wbcache_passthrough_execute_paper(struct fuse_req *req,
						bool *lower_started)
{
	struct fuse_wbcache_paper_io paper_io;
	struct fuse_wbcache_io *io = &paper_io.io;
	struct fuse_conn *fc = req->fm->fc;
	bool read_guard;
	bool read_cohort = false;
	ssize_t ret;
	int err;

	*lower_started = false;
	err = fuse_wbcache_passthrough_init(req, io, paper_io.inline_bvec,
					    ARRAY_SIZE(paper_io.inline_bvec), false,
					    GFP_KERNEL);
	if (err)
		return err;
	read_guard = !io->write && READ_ONCE(fc->extfuse_paper_read_guard);
	if (read_guard) {
		err = fuse_wbcache_read_begin(fc, req->args->extfuse_inode,
					      &read_cohort);
		if (err) {
			fuse_wbcache_passthrough_cleanup(io);
			return err;
		}
	}

	/* Validation is complete.  From here onward the request is never replayed. */
	*lower_started = true;
	if (!READ_ONCE(req->fm->fc->connected))
		ret = -ENOTCONN;
	else
		ret = fuse_wbcache_passthrough_execute(req, io);
	if (read_guard)
		fuse_wbcache_read_end(req, io, read_cohort, ret);
	fuse_wbcache_passthrough_cleanup(io);
	return ret;
}
