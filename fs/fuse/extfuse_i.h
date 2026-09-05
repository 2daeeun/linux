/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ExtFUSE: Extension Framework for FUSE
 *
 * Internal definitions for the kernel driver. The stable BPF-visible request
 * context and selector API live in <linux/extfuse.h>.
 */
#ifndef _EXTFUSE_I_H
#define _EXTFUSE_I_H

#include <asm-generic/errno.h>

#include <linux/extfuse.h>

/* Return-value contract between a BPF handler and the FUSE driver. */
#define EXTFUSE_ERROR(x)	((x) < 0 && (x) != -ENOSYS)
#define EXTFUSE_UPCALL(x)	((x) == -ENOSYS)
#define EXTFUSE_PASSTHRU(x)	((x) > 0)
#define EXTFUSE_RETURN(x)	((x) == 0)

enum extfuse_trace_phase {
	EXTFUSE_TRACE_PHASE_PRE = 1,
	EXTFUSE_TRACE_PHASE_POST_DAEMON = 2,
	EXTFUSE_TRACE_PHASE_BEGIN = 3,
	EXTFUSE_TRACE_PHASE_END = 4,
};

enum extfuse_trace_action {
	EXTFUSE_TRACE_ACTION_HIT = 1,
	EXTFUSE_TRACE_ACTION_FALLBACK = 2,
	EXTFUSE_TRACE_ACTION_ERROR = 3,
	EXTFUSE_TRACE_ACTION_POSTED = 4,
	EXTFUSE_TRACE_ACTION_SKIPPED = 5,
	EXTFUSE_TRACE_ACTION_MUTATION = 6,
	EXTFUSE_TRACE_ACTION_FORWARD = 7,
};

enum extfuse_pre_route {
	EXTFUSE_PRE_COMPLETE,
	EXTFUSE_PRE_DAEMON,
	EXTFUSE_PRE_WBCACHE_FORWARD,
	EXTFUSE_PRE_ERROR,
};

enum extfuse_trace_reason {
	EXTFUSE_TRACE_REASON_NONE = 0,
	EXTFUSE_TRACE_REASON_NO_PROGRAM = 1,
	EXTFUSE_TRACE_REASON_PROGRAM_FALLBACK = 2,
	EXTFUSE_TRACE_REASON_PROGRAM_ERROR = 3,
	EXTFUSE_TRACE_REASON_INVALID_OUTPUT = 4,
	EXTFUSE_TRACE_REASON_ACTIVE = 5,
	EXTFUSE_TRACE_REASON_RACE = 6,
	EXTFUSE_TRACE_REASON_POST_ERROR = 7,
	EXTFUSE_TRACE_REASON_TRAILER_ABSENT = 8,
	EXTFUSE_TRACE_REASON_TRAILER_INVALID = 9,
	EXTFUSE_TRACE_REASON_TRAILER_RACE = 10,
};

#ifdef __KERNEL__

#include <linux/gfp_types.h>

struct fuse_attr;
struct fuse_args;
struct fuse_conn;
struct fuse_req;
struct inode;

#if IS_ENABLED(CONFIG_EXTFUSE)

#include <linux/bpf.h>
#include <linux/filter.h>

struct extfuse_data {
	struct bpf_prog *prog;
};

#define EXTFUSE_FLAGS		FUSE_FS_EXTFUSE

/* Private BPF slots used by optional strict/native passthrough coherence. */
#define EXTFUSE_PASSTHROUGH_READ	65
#define EXTFUSE_PASSTHROUGH_WRITE	66
#define EXTFUSE_PASSTHROUGH_MMAP	67

int extfuse_load_prog(struct fuse_conn *fc, int fd);
void extfuse_unload_prog(struct fuse_conn *fc);
int extfuse_init_reply(struct fuse_conn *fc, struct fuse_args *args);
ssize_t extfuse_request_send(struct fuse_conn *fc, struct fuse_args *args);
enum extfuse_pre_route extfuse_request_pre(struct fuse_req *req, gfp_t gfp,
					   ssize_t *result);
int extfuse_request_prepare_daemon(struct fuse_req *req, gfp_t gfp);
int extfuse_request_prepare_wbcache(struct fuse_req *req, gfp_t gfp);
void extfuse_request_complete_wbcache(struct fuse_req *req, int error);
void extfuse_request_complete(struct fuse_req *req);
void extfuse_request_cancel(struct fuse_req *req, int error);
void extfuse_request_free(struct fuse_req *req);
void extfuse_coherence_invalidate_inode(struct fuse_conn *fc,
					struct inode *inode, u32 dependencies);
void extfuse_coherence_invalidate(struct fuse_conn *fc, u64 nodeid,
				  u32 dependencies);
void extfuse_coherence_invalidate_namespace(struct fuse_conn *fc);
int extfuse_coherence_begin_inode(struct fuse_conn *fc, struct inode *inode,
				    u32 dependencies);
void extfuse_coherence_end_inode(struct inode *inode, u32 dependencies);
int extfuse_cached_write_begin(struct fuse_conn *fc, struct inode *inode,
			       u32 dependencies);
void extfuse_cached_write_end(struct inode *inode, u32 dependencies);
int extfuse_passthrough_notify_inode(struct fuse_conn *fc,
				     struct inode *inode, u32 opcode,
				     u32 phase);
int extfuse_passthrough_notify(struct fuse_conn *fc, u64 nodeid, u32 opcode,
			       u32 phase);
int extfuse_passthrough_attr_prepare(struct fuse_conn *fc, u64 nodeid,
				     struct extfuse_passthrough_attr_cookie *cookie);
int extfuse_passthrough_attr_commit(struct fuse_conn *fc, u64 nodeid,
				    const struct extfuse_passthrough_attr_cookie *cookie,
				    const struct fuse_attr *attr);
int extfuse_passthrough_attr_commit_atime(
	struct fuse_conn *fc, u64 nodeid,
	const struct extfuse_passthrough_attr_cookie *cookie,
	const struct fuse_attr *attr);
int extfuse_paper_read_notify(struct fuse_conn *fc, struct inode *inode,
			    u32 phase);

#else /* !CONFIG_EXTFUSE */

#define EXTFUSE_FLAGS		0

static inline int extfuse_load_prog(struct fuse_conn *fc, int fd)
{
	return -ENOSYS;
}

static inline void extfuse_unload_prog(struct fuse_conn *fc)
{
}

static inline int extfuse_init_reply(struct fuse_conn *fc,
				     struct fuse_args *args)
{
	return 0;
}

static inline ssize_t extfuse_request_send(struct fuse_conn *fc,
					   struct fuse_args *args)
{
	return -ENOSYS;
}

static inline enum extfuse_pre_route
extfuse_request_pre(struct fuse_req *req, gfp_t gfp, ssize_t *result)
{
	*result = -ENOSYS;
	return EXTFUSE_PRE_DAEMON;
}

static inline int extfuse_request_prepare_daemon(struct fuse_req *req,
						  gfp_t gfp)
{
	return 0;
}

static inline int extfuse_request_prepare_wbcache(struct fuse_req *req,
						   gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static inline void
extfuse_request_complete_wbcache(struct fuse_req *req, int error)
{
}

static inline void extfuse_request_complete(struct fuse_req *req)
{
}

static inline void extfuse_request_cancel(struct fuse_req *req, int error)
{
}

static inline void extfuse_request_free(struct fuse_req *req)
{
}

static inline void
extfuse_coherence_invalidate_inode(struct fuse_conn *fc, struct inode *inode,
				   u32 dependencies)
{
}

static inline void extfuse_coherence_invalidate(struct fuse_conn *fc,
						 u64 nodeid,
						 u32 dependencies)
{
}

static inline void
extfuse_coherence_invalidate_namespace(struct fuse_conn *fc)
{
}

static inline int
extfuse_coherence_begin_inode(struct fuse_conn *fc, struct inode *inode,
				    u32 dependencies)
{
	return -EOPNOTSUPP;
}

static inline void extfuse_coherence_end_inode(struct inode *inode,
					      u32 dependencies)
{
}

static inline int
extfuse_cached_write_begin(struct fuse_conn *fc, struct inode *inode,
			   u32 dependencies)
{
	return -EOPNOTSUPP;
}

static inline void
extfuse_cached_write_end(struct inode *inode, u32 dependencies)
{
}

static inline int
extfuse_passthrough_notify_inode(struct fuse_conn *fc, struct inode *inode,
				 u32 opcode, u32 phase)
{
	return 0;
}

static inline int extfuse_passthrough_notify(struct fuse_conn *fc, u64 nodeid,
					     u32 opcode, u32 phase)
{
	return 0;
}

static inline int
extfuse_passthrough_attr_prepare(struct fuse_conn *fc, u64 nodeid,
				 struct extfuse_passthrough_attr_cookie *cookie)
{
	return -EOPNOTSUPP;
}

static inline int
extfuse_passthrough_attr_commit(struct fuse_conn *fc, u64 nodeid,
				const struct extfuse_passthrough_attr_cookie *cookie,
				const struct fuse_attr *attr)
{
	return -EOPNOTSUPP;
}

static inline int extfuse_passthrough_attr_commit_atime(
	struct fuse_conn *fc, u64 nodeid,
	const struct extfuse_passthrough_attr_cookie *cookie,
	const struct fuse_attr *attr)
{
	return -EOPNOTSUPP;
}

static inline int extfuse_paper_read_notify(struct fuse_conn *fc,
					  struct inode *inode, u32 phase)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_EXTFUSE */

#endif /* __KERNEL__ */

#endif /* _EXTFUSE_I_H */
