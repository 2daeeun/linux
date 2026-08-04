// SPDX-License-Identifier: GPL-2.0
/*
 * ExtFUSE: Extension Framework for FUSE
 *
 * Lets a userspace FUSE server register a BPF program with the kernel
 * FUSE driver so that selected requests can be serviced in-kernel and
 * use an "upcall" to the userspace daemon on a miss.
 *
 * Originally written against Linux 5.2 (USENIX ATC '19). Ported to
 * Linux v6.19.x:
 *   - the request-send hook now runs on struct fuse_args (the 5.2 code
 *     hooked fuse_request_send() on struct fuse_req; that path was
 *     refactored into __fuse_simple_request() and the args/req split),
 *   - BPF_PROG_RUN() -> bpf_prog_run_pin_on_cpu(),
 *   - probe_kernel_read()/probe_kernel_write() ->
 *     copy_from_kernel_nofault()/copy_to_kernel_nofault(),
 *   - the verifier-ops template follows the modern netfilter model,
 *   - symbols are exported so a modular fuse.ko can call into this
 *     built-in object (extfuse.o is always built-in; see Kconfig).
 */
#include "extfuse_i.h"
#include "fuse_i.h"

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/uaccess.h>
#include <linux/rcupdate.h>

#undef pr_fmt
#define pr_fmt(fmt) "ExtFUSE: " fmt

/* Kernel-only state associated with one BPF invocation. */
struct extfuse_req_ctx {
	struct extfuse_req req;
	const void *in_values[EXTFUSE_MAX_IN_ARGS];
	void *out_values[EXTFUSE_MAX_OUT_ARGS];
	unsigned long out_written;
	bool split_lookup_name;
};

/*
 * Build the BPF context by mirroring the in-flight request described by
 * @args. Only the small header + pointer-free arg descriptors are exposed;
 * payload pointers remain in the kernel-private wrapper and are accessed
 * lazily by the helpers under copy_{from,to}_kernel_nofault(). The helpers
 * return an error for page-backed payloads that have no direct value pointer.
 */
static void fuse_args_to_extfuse_req(struct fuse_args *args,
				     struct extfuse_req_ctx *ctx)
{
	struct extfuse_req *ereq = &ctx->req;
	unsigned int i;
	unsigned int nin = 0;
	unsigned int nout = min_t(unsigned int, args->out_numargs,
				  EXTFUSE_MAX_OUT_ARGS);

	memset(ctx, 0, sizeof(*ctx));

	ereq->in.h.opcode = args->opcode;
	ereq->in.h.nodeid = args->nodeid;

	/*
	 * Modern FUSE represents LOOKUP's single NUL-terminated name as a
	 * zero-sized header, name bytes, and a separate one-byte terminator.
	 * Present the original ExtFUSE ABI's one logical input argument.  The
	 * read helper synthesizes the trailing NUL without reading past the qstr.
	 */
	if (args->opcode == FUSE_LOOKUP && args->in_numargs >= 3 &&
	    !args->in_args[0].size && !args->in_args[0].value &&
	    args->in_args[1].size < UINT_MAX &&
	    args->in_args[2].size == 1) {
		ereq->in.args[0].size = args->in_args[1].size + 1;
		ctx->in_values[0] = args->in_args[1].value;
		ctx->split_lookup_name = true;
		nin = 1;
		i = 3;
	} else {
		i = 0;
	}

	for (; i < args->in_numargs && nin < EXTFUSE_MAX_IN_ARGS; i++) {
		/* Hide the internal extension slot from the ExtFUSE ABI. */
		if (args->is_ext && i == args->ext_idx)
			continue;

		/* Skip the zero header used by name-only FUSE requests. */
		if (!args->in_args[i].size && !args->in_args[i].value)
			continue;

		ereq->in.args[nin].size = args->in_args[i].size;
		ctx->in_values[nin] = args->in_args[i].value;
		nin++;
	}
	ereq->in.numargs = nin;

	ereq->out.argvar = args->out_argvar;
	ereq->out.numargs = nout;
	for (i = 0; i < nout; i++) {
		ereq->out.args[i].size = args->out_args[i].size;
		ctx->out_values[i] = args->out_args[i].value;
	}
}

/*
 * Try to service @args from BPF. Returns:
 *   -ENOSYS : no program / handler miss -> caller must do the normal upcall
 *   -511..-1: request failed in-kernel with this FUSE errno
 *   0       : fixed-size request fully handled in-kernel
 *   > 0     : PASSTHRU -> caller must do the normal upcall
 *
 * The handler writes its reply directly into the caller's out_args[].value
 * buffers via bpf_extfuse_write_args(), so there is no copy-back step.
 */
ssize_t extfuse_request_send(struct fuse_conn *fc, struct fuse_args *args)
{
	struct extfuse_data *data;
	struct bpf_prog *prog;
	struct extfuse_req_ctx ctx;
	bool force_upcall;
	unsigned long required_out = 0;
	unsigned int i;
	ssize_t ret;
	int prog_ret;

	/* Avoid RCU bookkeeping for connections that did not opt in. */
	if (!rcu_access_pointer(fc->fc_priv))
		return -ENOSYS;

	rcu_read_lock();
	data = rcu_dereference(fc->fc_priv);
	if (!data) {
		ret = -ENOSYS;
		goto out_unlock;
	}

	prog = READ_ONCE(data->prog);
	if (!prog) {
		ret = -ENOSYS;
		goto out_unlock;
	}

	if (!READ_ONCE(fc->connected)) {
		ret = -ENOSYS;
		goto out_unlock;
	}

	/* Forced control requests may be observed but must reach the daemon. */
	force_upcall = args->force && args->opcode != FUSE_FLUSH;

	fuse_args_to_extfuse_req(args, &ctx);
	prog_ret = bpf_prog_run_pin_on_cpu(prog, &ctx.req);

	/* Match the normal queue path if abort raced with BPF execution. */
	if (!READ_ONCE(fc->connected)) {
		ret = -ENOTCONN;
		goto out_unlock;
	}

	if (force_upcall) {
		ret = -ENOSYS;
		goto out_unlock;
	}

	if (EXTFUSE_UPCALL(prog_ret)) {
		ret = -ENOSYS;
		goto out_unlock;
	}

	if (EXTFUSE_PASSTHRU(prog_ret)) {
		/*
		 * PASSTHRU means "handled the fast bits, now still send to the
		 * daemon".  Returning -ENOSYS here continues the request through
		 * the normal FUSE path without submitting it twice.
		 */
		ret = -ENOSYS;
		goto out_unlock;
	}

	/* Match fuse_dev_do_write(): valid FUSE errors are -511..0. */
	if (unlikely(prog_ret <= -512)) {
		pr_warn_ratelimited("invalid BPF return %d; falling back to userspace\n",
				    prog_ret);
		ret = -ENOSYS;
		goto out_unlock;
	}

	/*
	 * The BPF ABI has no channel for the actual length of an out_argvar
	 * reply. A successful fast-path reply would otherwise return the buffer
	 * capacity, so use the normal daemon path instead.
	 */
	if (prog_ret == 0 && args->out_argvar) {
		ret = -ENOSYS;
		goto out_unlock;
	}
	/* Never expose an untouched or partially copied fixed-size reply. */
	if (prog_ret == 0) {
		for (i = 0; i < ctx.req.out.numargs; i++)
			if (ctx.req.out.args[i].size)
				required_out |= BIT(i);
		if ((ctx.out_written & required_out) != required_out) {
			ret = -ENOSYS;
			goto out_unlock;
		}
	}

	ret = prog_ret;
out_unlock:
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(extfuse_request_send);

/*
 * Native passthrough does not create an ordinary FUSE READ/WRITE request, so
 * run a private BPF notification for metadata-cache invalidation. A negotiated
 * connection treats a missing or failing handler as an I/O error rather than
 * risking a stale fast-path reply.
 */
int extfuse_passthrough_notify(struct fuse_conn *fc, u64 nodeid, u32 opcode)
{
	struct fuse_args args = {
		.nodeid = nodeid,
		.opcode = opcode,
	};
	ssize_t ret;

	if (!READ_ONCE(fc->extfuse_passthrough_coherence))
		return 0;

	ret = extfuse_request_send(fc, &args);
	if (ret == 0)
		return 0;

	pr_warn_ratelimited("native passthrough notification %u failed: %zd\n",
			    opcode, ret);
	return ret < 0 && ret != -ENOSYS ? (int)ret : -EIO;
}
EXPORT_SYMBOL_GPL(extfuse_passthrough_notify);

void extfuse_unload_prog(struct fuse_conn *fc)
{
	struct extfuse_data *data;

	WRITE_ONCE(fc->extfuse_passthrough_coherence, 0);
	spin_lock(&fc->extfuse_lock);
	data = rcu_replace_pointer(fc->fc_priv, NULL,
				   lockdep_is_held(&fc->extfuse_lock));
	spin_unlock(&fc->extfuse_lock);

	if (data) {
		/* Readers hold RCU across the complete BPF invocation. */
		synchronize_rcu();
		if (data->prog) {
			bpf_prog_put(data->prog);
			pr_info("bpf prog unloaded\n");
		}
		kfree(data);
	}
}
EXPORT_SYMBOL_GPL(extfuse_unload_prog);

int extfuse_load_prog(struct fuse_conn *fc, int fd)
{
	struct bpf_prog *prog;
	struct extfuse_data *data;
	int ret = 0;

	if (rcu_access_pointer(fc->fc_priv)) {
		pr_warn("bpf prog already loaded\n");
		return -EEXIST;
	}

	prog = bpf_prog_get_type(fd, BPF_PROG_TYPE_EXTFUSE);
	if (IS_ERR(prog)) {
		pr_err("bpf prog fd=%d failed: %ld\n", fd, PTR_ERR(prog));
		return PTR_ERR(prog);
	}

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data) {
		bpf_prog_put(prog);
		return -ENOMEM;
	}

	data->prog = prog;

	spin_lock(&fc->extfuse_lock);
	if (rcu_access_pointer(fc->fc_priv)) {
		ret = -EEXIST;
	} else {
		/* Publish after data->prog is fully initialized. */
		rcu_assign_pointer(fc->fc_priv, data);
	}
	spin_unlock(&fc->extfuse_lock);

	if (ret) {
		bpf_prog_put(prog);
		kfree(data);
		pr_warn("bpf prog already loaded\n");
		return ret;
	}

	pr_info("bpf prog loaded fd=%d\n", fd);
	return 0;
}
EXPORT_SYMBOL_GPL(extfuse_load_prog);

/*
 * Resolve the daemon-provided program fd before fuse_request_end() wakes a
 * synchronous INIT waiter.  At this point current is the /dev/fuse reply
 * writer, so the numeric fd is interpreted in the correct file table.
 */
int extfuse_init_reply(struct fuse_conn *fc, struct fuse_args *args)
{
	struct fuse_init_out *arg;
	u64 flags;

	if (args->out_numargs < 1 ||
	    args->out_args[0].size < offsetofend(struct fuse_init_out, flags))
		return 0;

	arg = args->out_args[0].value;
	if (!arg)
		return 0;
	if (arg->major != FUSE_KERNEL_VERSION || arg->minor < 6)
		return 0;

	flags = arg->flags;
	if (flags & FUSE_INIT_EXT) {
		if (args->out_args[0].size <
		    offsetofend(struct fuse_init_out, flags2))
			return 0;
		flags |= (u64)arg->flags2 << 32;
	}

	if (!(flags & FUSE_FS_EXTFUSE))
		return 0;

	if (args->out_args[0].size <
	    offsetofend(struct fuse_init_out, extfuse_prog_fd))
		return -EINVAL;

	return extfuse_load_prog(fc, arg->extfuse_prog_fd);
}
EXPORT_SYMBOL_GPL(extfuse_init_reply);

/*
 * bpf_extfuse_read_args - copy a field of the mirrored request into @dst
 * @src:  pointer to the struct extfuse_req context
 * @type: which field to read (see enum extfuse_arg_t in uapi/linux/extfuse.h)
 * @dst:  destination buffer in BPF memory
 * @size: size of @dst
 */
BPF_CALL_4(bpf_extfuse_read_args, void *, src, u32, type, void *, dst,
	   size_t, size)
{
	struct extfuse_req *req = (struct extfuse_req *)src;
	struct extfuse_req_ctx *ctx;
	unsigned int num_in_args = req->in.numargs;
	unsigned int num_out_args = req->out.numargs;
	const void *inptr = NULL;
	size_t dst_size = size;
	long ret = -EINVAL;

	ctx = container_of(req, struct extfuse_req_ctx, req);

	/*
	 * ARG_PTR_TO_UNINIT_MEM makes the verifier treat the full destination
	 * range as initialized after the helper returns, including error paths.
	 */
	memset(dst, 0, dst_size);

	switch (type) {
	case OPCODE:
		if (size != sizeof(uint32_t))
			return -EINVAL;
		inptr = &req->in.h.opcode;
		break;
	case NODEID:
		if (size != sizeof(uint64_t))
			return -EINVAL;
		inptr = &req->in.h.nodeid;
		break;
	case NUM_IN_ARGS:
		if (size != sizeof(unsigned int))
			return -EINVAL;
		inptr = &req->in.numargs;
		break;
	case NUM_OUT_ARGS:
		if (size != sizeof(unsigned int))
			return -EINVAL;
		inptr = &req->out.numargs;
		break;
	case IN_PARAM_0_SIZE:
		if (size != sizeof(unsigned int) || num_in_args < 1)
			return -EINVAL;
		inptr = &req->in.args[0].size;
		break;
	case IN_PARAM_0_VALUE:
		if (num_in_args < 1)
			return -EINVAL;
		if (size < req->in.args[0].size)
			return -E2BIG;
		size = req->in.args[0].size;
		inptr = ctx->in_values[0];
		break;
	case IN_PARAM_1_SIZE:
		if (size != sizeof(unsigned int) || num_in_args < 2)
			return -EINVAL;
		inptr = &req->in.args[1].size;
		break;
	case IN_PARAM_1_VALUE:
		if (num_in_args < 2)
			return -EINVAL;
		if (size < req->in.args[1].size)
			return -E2BIG;
		size = req->in.args[1].size;
		inptr = ctx->in_values[1];
		break;
	case IN_PARAM_2_SIZE:
		if (size != sizeof(unsigned int) || num_in_args < 3)
			return -EINVAL;
		inptr = &req->in.args[2].size;
		break;
	case IN_PARAM_2_VALUE:
		if (num_in_args < 3)
			return -EINVAL;
		if (size < req->in.args[2].size)
			return -E2BIG;
		size = req->in.args[2].size;
		inptr = ctx->in_values[2];
		break;
	case OUT_PARAM_0:
		if (num_out_args < 1)
			return -EINVAL;
		if (!(ctx->out_written & BIT(0)))
			return -EACCES;
		if (size != req->out.args[0].size)
			return -E2BIG;
		inptr = ctx->out_values[0];
		break;
	case OUT_PARAM_1:
		if (num_out_args < 2)
			return -EINVAL;
		if (!(ctx->out_written & BIT(1)))
			return -EACCES;
		if (size != req->out.args[1].size)
			return -E2BIG;
		inptr = ctx->out_values[1];
		break;
	default:
		return -EBADRQC;
	}

	if (!inptr) {
		pr_debug("invalid read type %u num_in %u num_out %u size %zu\n",
			 type, num_in_args, num_out_args, size);
		return ret;
	}

	if (type == IN_PARAM_0_VALUE && ctx->split_lookup_name)
		size--;

	ret = size ? copy_from_kernel_nofault(dst, inptr, size) : 0;
	if (unlikely(ret < 0))
		memset(dst, 0, dst_size);

	return ret;
}

static const struct bpf_func_proto bpf_extfuse_read_args_proto = {
	.func		= bpf_extfuse_read_args,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};

/*
 * bpf_extfuse_write_args - copy from @src into an out-arg of the request
 * @dst:  pointer to the struct extfuse_req context
 * @type: which out-arg to write (OUT_PARAM_0 / OUT_PARAM_1)
 * @src:  source buffer in BPF memory
 * @size: number of bytes; must equal the target out-arg size
 */
BPF_CALL_4(bpf_extfuse_write_args, void *, dst, u32, type, const void *, src,
	   u32, size)
{
	struct extfuse_req *req = (struct extfuse_req *)dst;
	struct extfuse_req_ctx *ctx;
	unsigned int numargs = req->out.numargs;
	void *outptr = NULL;
	unsigned int out_idx;
	long ret = -EINVAL;

	ctx = container_of(req, struct extfuse_req_ctx, req);

	if (type == OUT_PARAM_0 && numargs >= 1 &&
	    size == req->out.args[0].size) {
		outptr = ctx->out_values[0];
		out_idx = 0;
	} else if (type == OUT_PARAM_1 && numargs >= 2 &&
		 size == req->out.args[1].size) {
		outptr = ctx->out_values[1];
		out_idx = 1;
	}

	if (!outptr) {
		pr_debug("invalid write type %u numargs %u size %u\n",
			 type, numargs, size);
		return ret;
	}

	ret = copy_to_kernel_nofault(outptr, src, size);
	if (unlikely(ret < 0))
		return ret;

	ctx->out_written |= BIT(out_idx);

	return ret;
}

static const struct bpf_func_proto bpf_extfuse_write_args_proto = {
	.func		= bpf_extfuse_write_args,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg4_type	= ARG_CONST_SIZE,
};

static const struct bpf_func_proto *
bpf_extfuse_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_extfuse_read_args:
	case BPF_FUNC_tcp_gen_syncookie: /* Original ExtFUSE helper ID. */
		return &bpf_extfuse_read_args_proto;
	case BPF_FUNC_extfuse_write_args:
	case BPF_FUNC_skb_output: /* Original ExtFUSE helper ID. */
		return &bpf_extfuse_write_args_proto;
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_tail_call:
		return &bpf_tail_call_proto;
#ifdef CONFIG_BPF_EVENTS
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
#endif
	default:
		return NULL;
	}
}

/* Direct access is limited to the scalar fields in the original API. */
static bool bpf_extfuse_is_valid_access(int off, int size,
					enum bpf_access_type type,
					const struct bpf_prog *prog,
					struct bpf_insn_access_aux *info)
{
	if (type != BPF_READ)
		return false;

	switch (off) {
	case offsetof(struct extfuse_req, in.h.opcode):
	case offsetof(struct extfuse_req, in.numargs):
	case offsetof(struct extfuse_req, in.args[0].size):
	case offsetof(struct extfuse_req, in.args[1].size):
	case offsetof(struct extfuse_req, in.args[2].size):
	case offsetof(struct extfuse_req, out.numargs):
	case offsetof(struct extfuse_req, out.argvar):
	case offsetof(struct extfuse_req, out.args[0].size):
	case offsetof(struct extfuse_req, out.args[1].size):
		return size == sizeof(__u32);
	case offsetof(struct extfuse_req, in.h.nodeid):
		return size == sizeof(__u64);
	default:
		return false;
	}
}

const struct bpf_verifier_ops extfuse_verifier_ops = {
	.get_func_proto		= bpf_extfuse_func_proto,
	.is_valid_access	= bpf_extfuse_is_valid_access,
};

const struct bpf_prog_ops extfuse_prog_ops = {
};
