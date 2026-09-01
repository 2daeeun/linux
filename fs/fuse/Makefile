# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the FUSE filesystem.
#

# Needed for trace events
ccflags-y = -I$(src)

obj-$(CONFIG_FUSE_FS) += fuse.o
obj-$(CONFIG_CUSE) += cuse.o
obj-$(CONFIG_VIRTIO_FS) += virtiofs.o
# extfuse.o is deliberately a standalone built-in object (not part of
# fuse-y): the BPF prog/verifier ops it defines are referenced from
# vmlinux (kernel/bpf via bpf_types.h), so they must be built-in even
# when CONFIG_FUSE_FS=m.
obj-$(CONFIG_EXTFUSE) += extfuse.o

fuse-y := trace.o	# put trace.o first so we see ftrace errors sooner
fuse-y += dev.o dir.o file.o inode.o control.o xattr.o acl.o readdir.o ioctl.o
fuse-y += iomode.o
fuse-$(CONFIG_FUSE_DAX) += dax.o
fuse-$(CONFIG_FUSE_PASSTHROUGH) += passthrough.o backing.o \
				    wbcache_passthrough.o
fuse-$(CONFIG_SYSCTL) += sysctl.o
fuse-$(CONFIG_FUSE_IO_URING) += dev_uring.o

virtiofs-y := virtio_fs.o
