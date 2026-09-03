/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_EXTFUSE_TYPES_H
#define _UAPI_LINUX_EXTFUSE_TYPES_H

#include <linux/types.h>
#include <linux/fuse.h>

#define EXTFUSE_MAX_IN_ARGS	3
#define EXTFUSE_MAX_OUT_ARGS	2

#define EXTFUSE_COHERENCE_VERSION	3
#define EXTFUSE_COHERENCE_MAX_TARGETS	4

#define EXTFUSE_COHERENCE_PHASE_PRE		1
#define EXTFUSE_COHERENCE_PHASE_POST_DAEMON	2

#define EXTFUSE_COHERENCE_DOMAIN_ATTR		(1U << 0)
#define EXTFUSE_COHERENCE_DOMAIN_XATTR		(1U << 1)
#define EXTFUSE_COHERENCE_DOMAIN_DATA		(1U << 2)
#define EXTFUSE_COHERENCE_DOMAIN_NAMESPACE	(1U << 3)
#define EXTFUSE_COHERENCE_DOMAIN_ALL		((1U << 4) - 1)

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

struct extfuse_coherence_target {
	__u64 nodeid;
	__u64 incarnation;
	__u64 attr_epoch;
	__u64 xattr_epoch;
	__u64 data_epoch;
	__u64 namespace_epoch;
	__u32 dependencies;
	__u32 active;
};

struct extfuse_coherence {
	__u32 version;
	__u16 phase;
	__u16 target_count;
	__s32 daemon_error;
	__u32 request_dependencies;
	__u32 validated_dependencies;
	__u32 reason;
	__u64 unique;
	struct extfuse_coherence_target targets[EXTFUSE_COHERENCE_MAX_TARGETS];
};

struct extfuse_req {
	struct extfuse_in in;
	struct extfuse_out out;
	struct extfuse_coherence coherence;
};

/*
 * Private passthrough I/O notifications use one input argument to bracket
 * lower I/O.  Upper-file preparation such as privilege removal completes via
 * the filesystem's ordinary operations first.  BEGIN is then emitted before
 * direct backing-file I/O can mutate metadata; END is emitted after completion,
 * including asynchronous completion.  MMAP uses BEGIN alone as a persistent
 * marker when later page faults cannot be represented by a finite I/O bracket.
 */
#define EXTFUSE_PASSTHROUGH_PHASE_BEGIN	1
#define EXTFUSE_PASSTHROUGH_PHASE_END	2

/* Private BPF tail-call slots for the passthrough attribute handshake. */
#define EXTFUSE_PASSTHROUGH_ATTR_PREPARE	68
#define EXTFUSE_PASSTHROUGH_ATTR_COMMIT	69

struct extfuse_passthrough_in {
	__u32 phase;
	__u32 reserved;
};

/* Opaque state guarding a passthrough-backed attribute refresh. */
struct extfuse_passthrough_attr_cookie {
	__u64 daemon_state;
	__u64 native_state;
};

#endif /* _UAPI_LINUX_EXTFUSE_TYPES_H */
