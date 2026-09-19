/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _FUSE_WORKLOAD_H
#define _FUSE_WORKLOAD_H

struct fuse_conn;
struct kiocb;
struct iov_iter;

void fuse_workload_init(struct fuse_conn *fc);
void fuse_workload_destroy(struct fuse_conn *fc);
void fuse_workload_observe(struct kiocb *iocb, struct iov_iter *iter, bool write);
long fuse_workload_ioctl(struct fuse_conn *fc, unsigned int cmd,
			void __user *argp);

#endif
