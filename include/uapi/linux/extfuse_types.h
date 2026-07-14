/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_EXTFUSE_TYPES_H
#define _UAPI_LINUX_EXTFUSE_TYPES_H

#include <linux/types.h>
#include <linux/fuse.h>

#define EXTFUSE_MAX_IN_ARGS	3
#define EXTFUSE_MAX_OUT_ARGS	2

/* One BPF-visible input argument descriptor. */
struct extfuse_in_arg {
	__u32 size;
	__aligned_u64 value;
};

/* One BPF-visible output argument descriptor. */
struct extfuse_arg {
	__u32 size;
	__aligned_u64 value;
};

struct extfuse_in {
	struct fuse_in_header h;
	__u32 numargs;
	struct extfuse_in_arg args[EXTFUSE_MAX_IN_ARGS];
};

struct extfuse_out {
	struct fuse_out_header h;
	__u32 argvar;
	__u32 numargs;
	struct extfuse_arg args[EXTFUSE_MAX_OUT_ARGS];
};

struct extfuse_req {
	struct extfuse_in in;
	struct extfuse_out out;
};

#endif /* _UAPI_LINUX_EXTFUSE_TYPES_H */
