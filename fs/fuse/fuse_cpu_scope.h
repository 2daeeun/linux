/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FS_FUSE_CPU_SCOPE_H
#define _FS_FUSE_CPU_SCOPE_H

#include <linux/cleanup.h>

#include "fuse_i.h"
#include "fuse_trace.h"

/* Store only the device number so cleanup remains safe if the last fc
 * reference is dropped by the callback being measured.
 */
DEFINE_CLASS(fuse_cpu_scope, dev_t,
	     trace_fuse_cpu_scope(_T, false),
	     ({
		dev_t __connection = (fc)->dev;

		trace_fuse_cpu_scope(__connection, true);
		__connection;
	     }),
	     struct fuse_conn *fc)

#define FUSE_CPU_SCOPE(fc) CLASS(fuse_cpu_scope, scope)(fc)

#endif /* _FS_FUSE_CPU_SCOPE_H */
