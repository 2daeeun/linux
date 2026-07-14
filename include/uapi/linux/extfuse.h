/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_EXTFUSE_H
#define _UAPI_LINUX_EXTFUSE_H

#include <linux/extfuse_types.h>

/*
 * Selector passed to the bpf_extfuse_read_args() / bpf_extfuse_write_args()
 * helpers to identify which field of the mirrored FUSE request to access.
 */
typedef enum {
	OPCODE = 0,
	NODEID,
	NUM_IN_ARGS,
	NUM_OUT_ARGS,
	IN_PARAM_0_SIZE,
	IN_PARAM_0_VALUE,
	IN_PARAM_1_SIZE,
	IN_PARAM_1_VALUE,
	IN_PARAM_2_SIZE,
	IN_PARAM_2_VALUE,
	OUT_PARAM_0,
	OUT_PARAM_1,
} extfuse_arg_t;

#endif /* _UAPI_LINUX_EXTFUSE_H */
