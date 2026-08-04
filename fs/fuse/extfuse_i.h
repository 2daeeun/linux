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

#ifdef __KERNEL__

#if IS_ENABLED(CONFIG_EXTFUSE)

#include <linux/bpf.h>
#include <linux/filter.h>

struct fuse_conn;
struct fuse_args;

struct extfuse_data {
	struct bpf_prog *prog;
};

#define EXTFUSE_FLAGS		FUSE_FS_EXTFUSE

/* Private BPF tail-call slots used only by native passthrough coherence. */
#define EXTFUSE_PASSTHROUGH_READ	65
#define EXTFUSE_PASSTHROUGH_WRITE	66
#define EXTFUSE_PASSTHROUGH_MMAP	67

int extfuse_load_prog(struct fuse_conn *fc, int fd);
void extfuse_unload_prog(struct fuse_conn *fc);
int extfuse_init_reply(struct fuse_conn *fc, struct fuse_args *args);
ssize_t extfuse_request_send(struct fuse_conn *fc, struct fuse_args *args);
int extfuse_passthrough_notify(struct fuse_conn *fc, u64 nodeid, u32 opcode);

#else /* !CONFIG_EXTFUSE */

struct fuse_conn;
struct fuse_args;

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

static inline int extfuse_passthrough_notify(struct fuse_conn *fc, u64 nodeid,
					     u32 opcode)
{
	return 0;
}

#endif /* CONFIG_EXTFUSE */

#endif /* __KERNEL__ */

#endif /* _EXTFUSE_I_H */
