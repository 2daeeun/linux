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
 *   - BPF_PROG_RUN() -> preemption-disabled bpf_prog_run() so epoch programs
 *     can safely retain per-CPU scratch across tail calls,
 *   - probe_kernel_read()/probe_kernel_write() ->
 *     copy_from_kernel_nofault()/copy_to_kernel_nofault(),
 *   - the verifier-ops template follows the modern netfilter model,
 *   - symbols are exported so a modular fuse.ko can call into this
 *     built-in object (extfuse.o is always built-in; see Kconfig).
 */
#include "extfuse_i.h"
#include "fuse_i.h"
#include "fuse_trace.h"

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <linux/preempt.h>
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
	unsigned int out_actual[EXTFUSE_MAX_OUT_ARGS];
	unsigned long out_written;
	unsigned long out_variable;
	bool split_lookup_name;
	bool post_daemon;
};

enum extfuse_domain_index {
	EXTFUSE_DOMAIN_ATTR,
	EXTFUSE_DOMAIN_XATTR,
	EXTFUSE_DOMAIN_DATA,
	EXTFUSE_DOMAIN_NAMESPACE,
	EXTFUSE_DOMAIN_COUNT,
};

struct extfuse_target_state {
	struct inode *inode;
	u32 dependencies;
	struct extfuse_coherence_target pre;
	bool active_owned;
	bool mutation_completed;
};

struct extfuse_mutation_payload {
	struct fuse_mutation_out out;
	struct fuse_mutation_node_out nodes[FUSE_MUTATION_MAX_NODES];
};

struct extfuse_req_state {
	struct extfuse_target_state targets[EXTFUSE_COHERENCE_MAX_TARGETS];
	struct extfuse_mutation_payload *mutation_out;
	u32 target_count;
	u32 request_dependencies;
	unsigned long trailer_xattr_changed;
	u64 global_pre_epoch;
	bool mutation;
	bool begun;
	bool optional_out;
	bool trailer_capable;
	bool pre_hit_allowed;
	bool pre_hit_invalidate;
	bool global_mutation;
	bool global_active_owned;
	bool global_mutation_completed;
};

static_assert(sizeof(struct extfuse_passthrough_in) == 8);
static_assert(sizeof(struct extfuse_passthrough_attr_cookie) == 16);
static_assert(sizeof(struct extfuse_coherence_target) == 56);
static_assert(sizeof(struct extfuse_coherence) == 256);
static_assert(sizeof(struct fuse_mutation_out) == 8);
static_assert(sizeof(struct fuse_mutation_node_out) == 120);
static_assert(sizeof(struct extfuse_mutation_payload) == 488);

/*
 * Build the BPF context by mirroring the in-flight request described by
 * @args. Only the small header + pointer-free arg descriptors are exposed;
 * payload pointers remain in the kernel-private wrapper and are accessed
 * lazily by the helpers under copy_{from,to}_kernel_nofault(). The helpers
 * return an error for page-backed payloads that have no direct value pointer.
 * Return false if the request shape cannot be represented without truncation.
 */
static bool fuse_args_to_extfuse_req(struct fuse_args *args,
				     const struct fuse_in_header *inh,
				     const struct extfuse_coherence *coherence,
				     bool post_daemon,
				     struct extfuse_req_ctx *ctx)
{
	struct extfuse_req *ereq = &ctx->req;
	unsigned int i;
	unsigned int nin = 0;
	unsigned int nout;

	if (args->in_numargs > ARRAY_SIZE(args->in_args) ||
	    args->out_numargs > ARRAY_SIZE(args->out_args) ||
	    args->out_numargs > EXTFUSE_MAX_OUT_ARGS ||
	    (args->is_ext && args->ext_idx >= args->in_numargs))
		return false;

	/* A hidden extension inside LOOKUP's three-part name is malformed. */
	if (args->opcode == FUSE_LOOKUP && args->is_ext && args->ext_idx < 3)
		return false;

	nout = args->out_numargs;

	memset(ctx, 0, sizeof(*ctx));

	if (inh)
		ereq->in.h = *inh;
	else {
		ereq->in.h.opcode = args->opcode;
		ereq->in.h.nodeid = args->nodeid;
	}
	if (coherence)
		ereq->coherence = *coherence;
	ctx->post_daemon = post_daemon;

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

	for (; i < args->in_numargs; i++) {
		/* Hide the internal extension slot from the ExtFUSE ABI. */
		if (args->is_ext && i == args->ext_idx)
			continue;

		/* Skip the zero header used by name-only FUSE requests. */
		if (!args->in_args[i].size && !args->in_args[i].value)
			continue;
		if (nin == EXTFUSE_MAX_IN_ARGS)
			return false;

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
		if (post_daemon && coherence && !coherence->daemon_error &&
		    args->out_args[i].value) {
			ctx->out_actual[i] = args->out_args[i].size;
			ctx->out_written |= BIT(i);
		}
	}

	return true;
}

/*
 * Try to service @args from BPF. Returns:
 *   -ENOSYS : no program / handler miss / PASSTHRU -> normal upcall
 *   -511..-1: request failed in-kernel with this FUSE errno
 *   0       : request fully handled in-kernel with no variable payload
 *   > 0     : GETXATTR variable payload length
 *
 * The handler writes its reply directly into the caller's out_args[].value
 * buffers via an ExtFUSE write helper, so there is no copy-back step.
 */
static ssize_t __extfuse_request_send_ctx(
	struct fuse_conn *fc, struct fuse_args *args,
	const struct fuse_in_header *inh,
	const struct extfuse_coherence *coherence, bool post_daemon,
	u32 *reason)
{
	struct extfuse_data *data;
	struct bpf_prog *prog;
	struct extfuse_req_ctx ctx;
	bool force_upcall;
	unsigned long required_out = 0;
	unsigned int i;
	ssize_t ret;
	int prog_ret;

	if (reason)
		*reason = EXTFUSE_TRACE_REASON_NONE;

	/* Avoid RCU bookkeeping for connections that did not opt in. */
	if (!rcu_access_pointer(fc->fc_priv)) {
		if (reason)
			*reason = EXTFUSE_TRACE_REASON_NO_PROGRAM;
		return -ENOSYS;
	}

	rcu_read_lock();
	data = rcu_dereference(fc->fc_priv);
	if (!data) {
		if (reason)
			*reason = EXTFUSE_TRACE_REASON_NO_PROGRAM;
		ret = -ENOSYS;
		goto out_unlock;
	}

	prog = READ_ONCE(data->prog);
	if (!prog) {
		if (reason)
			*reason = EXTFUSE_TRACE_REASON_NO_PROGRAM;
		ret = -ENOSYS;
		goto out_unlock;
	}

	if (!READ_ONCE(fc->connected)) {
		if (reason)
			*reason = EXTFUSE_TRACE_REASON_PROGRAM_ERROR;
		ret = -ENOSYS;
		goto out_unlock;
	}

	/*
	 * Forced control requests may be observed but must reach the daemon.
	 * The current BPF ABI also hides request extensions, so a program may
	 * perform conservative cache side effects but cannot complete them.
	 */
	force_upcall = (args->force && args->opcode != FUSE_FLUSH) ||
		args->is_ext;

	if (!fuse_args_to_extfuse_req(args, inh, coherence, post_daemon, &ctx)) {
		if (reason)
			*reason = EXTFUSE_TRACE_REASON_INVALID_OUTPUT;
		ret = -ENOSYS;
		goto out_unlock;
	}
	/*
	 * Epoch-coherent programs use per-CPU scratch across tail calls. Pinning
	 * migration alone permits same-CPU preemption reentry to corrupt that
	 * scratch, so
	 * keep the complete program invocation non-preemptible.
	 */
	preempt_disable();
	prog_ret = bpf_prog_run(prog, &ctx.req);
	preempt_enable();

	/* Match the normal queue path if abort raced with BPF execution. */
	if (!READ_ONCE(fc->connected)) {
		if (reason)
			*reason = EXTFUSE_TRACE_REASON_PROGRAM_ERROR;
		ret = -ENOTCONN;
		goto out_unlock;
	}

	if (post_daemon) {
		ret = prog_ret;
		goto out_unlock;
	}

	if (force_upcall) {
		if (reason)
			*reason = EXTFUSE_TRACE_REASON_PROGRAM_FALLBACK;
		ret = -ENOSYS;
		goto out_unlock;
	}

	if (EXTFUSE_UPCALL(prog_ret)) {
		if (reason)
			*reason = EXTFUSE_TRACE_REASON_PROGRAM_FALLBACK;
		ret = -ENOSYS;
		goto out_unlock;
	}

	if (EXTFUSE_PASSTHRU(prog_ret)) {
		/*
		 * PASSTHRU means "handled the fast bits, now still send to the
		 * daemon".  Returning -ENOSYS here continues the request through
		 * the normal FUSE path without submitting it twice.
		 */
		if (reason)
			*reason = EXTFUSE_TRACE_REASON_PROGRAM_FALLBACK;
		ret = -ENOSYS;
		goto out_unlock;
	}

	/* Match fuse_dev_do_write(): valid FUSE errors are -511..0. */
	if (unlikely(prog_ret <= -512)) {
		pr_warn_ratelimited("invalid BPF return %d; falling back to userspace\n",
				    prog_ret);
		if (reason)
			*reason = EXTFUSE_TRACE_REASON_PROGRAM_ERROR;
		ret = -ENOSYS;
		goto out_unlock;
	}

	/*
	 * Keep variable-output completion narrowly scoped until each opcode's
	 * payload validation has been audited. GETXATTR has one direct output
	 * buffer, and the write helper records its actual payload length.
	 */
	if (prog_ret == 0 && args->out_argvar &&
	    (args->opcode != FUSE_GETXATTR || args->out_numargs != 1 ||
	     args->out_pages || !args->out_args[0].value ||
	     !(ctx.out_variable & BIT(0)))) {
		if (reason)
			*reason = EXTFUSE_TRACE_REASON_INVALID_OUTPUT;
		ret = -ENOSYS;
		goto out_unlock;
	}

	/* Never expose an untouched or partially copied successful reply. */
	if (prog_ret == 0) {
		for (i = 0; i < ctx.req.out.numargs; i++)
			if (ctx.req.out.args[i].size)
				required_out |= BIT(i);
		/* A zero-length variable reply still requires an explicit write. */
		if (args->out_argvar)
			required_out |= BIT(0);
		if ((ctx.out_written & required_out) != required_out) {
			if (reason)
				*reason = EXTFUSE_TRACE_REASON_INVALID_OUTPUT;
			ret = -ENOSYS;
			goto out_unlock;
		}
		if (args->out_argvar) {
			if (ctx.out_actual[0] > ctx.req.out.args[0].size) {
				if (reason)
					*reason = EXTFUSE_TRACE_REASON_INVALID_OUTPUT;
				ret = -ENOSYS;
				goto out_unlock;
			}
			args->out_args[0].size = ctx.out_actual[0];
			ret = ctx.out_actual[0];
			goto out_unlock;
		}
	}

	ret = prog_ret;
out_unlock:
	rcu_read_unlock();
	return ret;
}

static ssize_t __extfuse_request_send(struct fuse_conn *fc,
				      struct fuse_args *args)
{
	return __extfuse_request_send_ctx(fc, args, NULL, NULL, false, NULL);
}

static void extfuse_trace_fc(struct fuse_conn *fc, u64 unique, u32 opcode,
			     u64 nodeid, u32 phase, u32 action, u32 reason,
			     s32 error, u32 dependencies)
{
	trace_fuse_extfuse_coherence(fc->dev, unique, opcode, nodeid, phase,
				     action, reason, error, dependencies);
}

static void extfuse_trace(struct fuse_req *req, u64 nodeid, u32 phase,
			  u32 action, u32 reason, s32 error,
			  u32 dependencies)
{
	extfuse_trace_fc(req->fm->fc, req->in.h.unique, req->in.h.opcode,
			  nodeid, phase, action, reason, error, dependencies);
}

static u32 extfuse_pre_action(ssize_t result, u32 reason)
{
	if (reason == EXTFUSE_TRACE_REASON_PROGRAM_ERROR ||
	    reason == EXTFUSE_TRACE_REASON_INVALID_OUTPUT)
		return EXTFUSE_TRACE_ACTION_ERROR;
	if (result == -ENOSYS)
		return EXTFUSE_TRACE_ACTION_FALLBACK;
	return EXTFUSE_TRACE_ACTION_HIT;
}

static u32 extfuse_active_mask(const struct fuse_inode *fi)
{
	u32 active = 0;
	unsigned int i;

	for (i = 0; i < EXTFUSE_DOMAIN_COUNT; i++)
		if (fi->extfuse_active[i])
			active |= BIT(i);
	return active;
}

static void extfuse_snapshot_inode(
	struct inode *inode, u32 dependencies,
	struct extfuse_coherence_target *target)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_conn *fc = get_fuse_conn(inode);
	u64 global_epoch;
	bool global_active;

	spin_lock(&fc->extfuse_global_coherence_lock);
	global_epoch = fc->extfuse_global_epoch;
	global_active = fc->extfuse_global_active;
	spin_unlock(&fc->extfuse_global_coherence_lock);

	spin_lock(&fi->extfuse_coherence_lock);
	target->nodeid = get_node_id(inode);
	target->incarnation = fi->extfuse_incarnation;
	/* Fold filesystem-wide mutations into the fixed-size epoch ABI. */
	target->attr_epoch = fi->extfuse_epoch[EXTFUSE_DOMAIN_ATTR] +
		global_epoch;
	target->xattr_epoch = fi->extfuse_epoch[EXTFUSE_DOMAIN_XATTR] +
		global_epoch;
	target->data_epoch = fi->extfuse_epoch[EXTFUSE_DOMAIN_DATA] +
		global_epoch;
	target->namespace_epoch =
		fi->extfuse_epoch[EXTFUSE_DOMAIN_NAMESPACE] +
		atomic64_read(&fc->extfuse_namespace_epoch) + global_epoch;
	target->dependencies = dependencies;
	target->active = global_active ? EXTFUSE_COHERENCE_DOMAIN_ALL :
		extfuse_active_mask(fi);
	spin_unlock(&fi->extfuse_coherence_lock);
}

static int extfuse_global_begin(struct fuse_conn *fc)
{
	spin_lock(&fc->extfuse_global_coherence_lock);
	if (fc->extfuse_global_active == U32_MAX) {
		spin_unlock(&fc->extfuse_global_coherence_lock);
		return -EOVERFLOW;
	}
	fc->extfuse_global_active++;
	fc->extfuse_global_epoch++;
	spin_unlock(&fc->extfuse_global_coherence_lock);
	return 0;
}

static void extfuse_global_end(struct fuse_conn *fc)
{
	spin_lock(&fc->extfuse_global_coherence_lock);
	if (!WARN_ON_ONCE(!fc->extfuse_global_active)) {
		fc->extfuse_global_active--;
		fc->extfuse_global_epoch++;
	}
	spin_unlock(&fc->extfuse_global_coherence_lock);
}

static bool extfuse_target_stable(
	const struct extfuse_target_state *state, u32 dependencies)
{
	struct extfuse_coherence_target snapshot = { };
	const struct extfuse_coherence_target *saved = &state->pre;

	if (!state->inode)
		return false;

	extfuse_snapshot_inode(state->inode, dependencies, &snapshot);
	if (snapshot.incarnation != saved->incarnation ||
	    (snapshot.active & dependencies))
		return false;
	if ((dependencies & EXTFUSE_COHERENCE_DOMAIN_ATTR) &&
	    snapshot.attr_epoch != saved->attr_epoch)
		return false;
	if ((dependencies & EXTFUSE_COHERENCE_DOMAIN_XATTR) &&
	    snapshot.xattr_epoch != saved->xattr_epoch)
		return false;
	if ((dependencies & EXTFUSE_COHERENCE_DOMAIN_DATA) &&
	    snapshot.data_epoch != saved->data_epoch)
		return false;
	if ((dependencies & EXTFUSE_COHERENCE_DOMAIN_NAMESPACE) &&
	    snapshot.namespace_epoch != saved->namespace_epoch)
		return false;

	return true;
}

static int extfuse_inode_begin(struct inode *inode, u32 dependencies)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	unsigned int i;

	spin_lock(&fi->extfuse_coherence_lock);
	for (i = 0; i < EXTFUSE_DOMAIN_COUNT; i++)
		if ((dependencies & BIT(i)) && fi->extfuse_active[i] == U32_MAX) {
			spin_unlock(&fi->extfuse_coherence_lock);
			return -EOVERFLOW;
		}
	for (i = 0; i < EXTFUSE_DOMAIN_COUNT; i++) {
		if (!(dependencies & BIT(i)))
			continue;
		fi->extfuse_active[i]++;
		fi->extfuse_epoch[i]++;
	}
	spin_unlock(&fi->extfuse_coherence_lock);

	return 0;
}

static void extfuse_inode_end(struct inode *inode, u32 dependencies)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	unsigned int i;

	spin_lock(&fi->extfuse_coherence_lock);
	for (i = 0; i < EXTFUSE_DOMAIN_COUNT; i++) {
		if (!(dependencies & BIT(i)))
			continue;
		if (WARN_ON_ONCE(!fi->extfuse_active[i]))
			continue;
		fi->extfuse_active[i]--;
		fi->extfuse_epoch[i]++;
	}
	spin_unlock(&fi->extfuse_coherence_lock);
}

int extfuse_coherence_begin_inode(struct fuse_conn *fc, struct inode *inode,
				    u32 dependencies)
{
	if (!READ_ONCE(fc->extfuse_coherence_epochs) || !inode || !dependencies)
		return -EOPNOTSUPP;

	return extfuse_inode_begin(inode, dependencies);
}
EXPORT_SYMBOL_GPL(extfuse_coherence_begin_inode);

void extfuse_coherence_end_inode(struct inode *inode, u32 dependencies)
{
	if (inode && dependencies)
		extfuse_inode_end(inode, dependencies);
}
EXPORT_SYMBOL_GPL(extfuse_coherence_end_inode);

static struct inode *extfuse_lookup_node(struct fuse_conn *fc, u64 nodeid)
{
	struct inode *inode;

	down_read(&fc->killsb);
	inode = fuse_ilookup(fc, nodeid, NULL);
	up_read(&fc->killsb);
	return inode;
}

void extfuse_coherence_invalidate_inode(struct fuse_conn *fc,
					struct inode *inode, u32 dependencies)
{
	struct fuse_inode *fi;
	unsigned int i;

	if (!READ_ONCE(fc->extfuse_coherence_epochs) || !inode || !dependencies)
		return;

	fi = get_fuse_inode(inode);
	spin_lock(&fi->extfuse_coherence_lock);
	for (i = 0; i < EXTFUSE_DOMAIN_COUNT; i++)
		if (dependencies & BIT(i))
			fi->extfuse_epoch[i]++;
	spin_unlock(&fi->extfuse_coherence_lock);
}
EXPORT_SYMBOL_GPL(extfuse_coherence_invalidate_inode);

void extfuse_coherence_invalidate(struct fuse_conn *fc, u64 nodeid,
				  u32 dependencies)
{
	struct inode *inode;

	if (!READ_ONCE(fc->extfuse_coherence_epochs) || !dependencies)
		return;
	inode = extfuse_lookup_node(fc, nodeid);
	if (!inode)
		return;

	extfuse_coherence_invalidate_inode(fc, inode, dependencies);
	iput(inode);
}
EXPORT_SYMBOL_GPL(extfuse_coherence_invalidate);

void extfuse_coherence_invalidate_namespace(struct fuse_conn *fc)
{
	if (READ_ONCE(fc->extfuse_coherence_epochs))
		atomic64_inc(&fc->extfuse_namespace_epoch);
}
EXPORT_SYMBOL_GPL(extfuse_coherence_invalidate_namespace);

static struct inode *extfuse_target_inode(struct fuse_req *req, u64 nodeid,
					   gfp_t gfp)
{
	struct fuse_args *args = req->args;
	struct inode *inode = NULL;
	struct fuse_conn *fc = req->fm->fc;
	struct inode *direct[] = {
		args->extfuse_inode,
		args->extfuse_inode2,
		args->extfuse_inode3,
		args->extfuse_inode4,
		args->extfuse_getattr_inode,
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(direct); i++)
		if (direct[i] && get_node_id(direct[i]) == nodeid)
			return igrab(direct[i]);

	if (!gfpflags_allow_blocking(gfp))
		return NULL;

	down_read(&fc->killsb);
	inode = fuse_ilookup(fc, nodeid, NULL);
	up_read(&fc->killsb);
	return inode;
}

static int extfuse_add_target(struct fuse_req *req,
			      struct extfuse_req_state *state, u64 nodeid,
			      u32 dependencies, gfp_t gfp)
{
	struct extfuse_target_state *target;
	unsigned int i;

	if (!nodeid || !dependencies)
		return 0;
	for (i = 0; i < state->target_count; i++) {
		target = &state->targets[i];
		if (target->pre.nodeid != nodeid)
			continue;
		target->dependencies |= dependencies;
		target->pre.dependencies |= dependencies;
		state->request_dependencies |= dependencies;
		return 0;
	}
	if (state->target_count == EXTFUSE_COHERENCE_MAX_TARGETS)
		return -E2BIG;

	target = &state->targets[state->target_count++];
	target->dependencies = dependencies;
	target->inode = extfuse_target_inode(req, nodeid, gfp);
	if (target->inode)
		extfuse_snapshot_inode(target->inode, dependencies, &target->pre);
	else {
		target->pre.nodeid = nodeid;
		target->pre.dependencies = dependencies;
		target->pre.active = EXTFUSE_COHERENCE_DOMAIN_ALL;
	}
	state->request_dependencies |= dependencies;
	return 0;
}

static bool extfuse_security_capability(const struct fuse_args *args)
{
	static const char capability[] = "security.capability";

	return args->opcode == FUSE_GETXATTR && args->in_numargs >= 2 &&
		args->in_args[1].value &&
		args->in_args[1].size == sizeof(capability) &&
		!memcmp(args->in_args[1].value, capability, sizeof(capability));
}

static u32 extfuse_validated_dependencies(const struct fuse_args *args,
					   ssize_t result)
{
	const struct fuse_getxattr_in *inarg;

	if (args->opcode != FUSE_GETXATTR)
		return 0;
	if (!extfuse_security_capability(args))
		return EXTFUSE_COHERENCE_DOMAIN_XATTR |
		       EXTFUSE_COHERENCE_DOMAIN_DATA;
	if (args->in_args[0].size < sizeof(*inarg) ||
	    !args->in_args[0].value)
		return EXTFUSE_COHERENCE_DOMAIN_XATTR |
		       EXTFUSE_COHERENCE_DOMAIN_DATA;
	inarg = args->in_args[0].value;
	/*
	 * Narrowing this exact negative capability probe is an epoch-coherence
	 * passthrough-daemon/lower-VFS policy contract, not a generic FUSE
	 * guarantee.  Every other GETXATTR result remains DATA-dependent.
	 */
	if (result == -ENODATA && !inarg->size)
		return EXTFUSE_COHERENCE_DOMAIN_XATTR;
	return EXTFUSE_COHERENCE_DOMAIN_XATTR |
	       EXTFUSE_COHERENCE_DOMAIN_DATA;
}

static void extfuse_state_put(struct extfuse_req_state *state)
{
	unsigned int i;

	if (!state)
		return;
	for (i = 0; i < state->target_count; i++)
		if (state->targets[i].inode)
			iput(state->targets[i].inode);
	kfree(state);
}

static bool extfuse_opcode_is_mutation(u32 opcode);

static bool extfuse_args_is_mutation(const struct fuse_args *args)
{
	switch (args->opcode) {
	case FUSE_OPEN: {
		const struct fuse_open_in *open;

		if (!args->in_numargs || !args->in_args[0].value ||
		    args->in_args[0].size < sizeof(*open))
			return false;
		open = args->in_args[0].value;
		return open->flags & O_TRUNC;
	}
	case FUSE_RELEASE: {
		const struct fuse_release_in *release;

		if (!args->in_numargs || !args->in_args[0].value ||
		    args->in_args[0].size < sizeof(*release))
			return false;
		release = args->in_args[0].value;
		return (release->flags & O_ACCMODE) != O_RDONLY;
	}
	default:
		return extfuse_opcode_is_mutation(args->opcode);
	}
}

static int extfuse_build_state(struct fuse_req *req, gfp_t gfp)
{
	struct fuse_args *args = req->args;
	struct extfuse_req_state *state;
	const struct fuse_copy_file_range_in *copy;
	bool allocate_trailer;
	size_t state_size;
	u32 dependencies;
	int err = 0;

	if (req->extfuse_state)
		return 0;
	if (args->opcode != FUSE_GETATTR && args->opcode != FUSE_GETXATTR &&
	    args->opcode != FUSE_LISTXATTR && args->opcode != FUSE_LOOKUP &&
	    !extfuse_opcode_is_mutation(args->opcode))
		return 0;

	allocate_trailer = READ_ONCE(req->fm->fc->extfuse_mutation_metadata) &&
		(args->opcode == FUSE_WRITE ||
		 args->opcode == FUSE_COPY_FILE_RANGE ||
		 args->opcode == FUSE_COPY_FILE_RANGE_64);
	state_size = sizeof(*state);
	if (allocate_trailer)
		state_size += sizeof(*state->mutation_out);
	state = kzalloc(state_size, gfp);
	if (!state)
		return -ENOMEM;
	if (allocate_trailer)
		state->mutation_out = (void *)(state + 1);

	switch (args->opcode) {
	case FUSE_GETATTR:
		err = extfuse_add_target(req, state, args->nodeid,
					 EXTFUSE_COHERENCE_DOMAIN_ATTR, gfp);
		break;
	case FUSE_GETXATTR:
		dependencies = EXTFUSE_COHERENCE_DOMAIN_XATTR |
			       EXTFUSE_COHERENCE_DOMAIN_DATA;
		err = extfuse_add_target(req, state, args->nodeid,
					 dependencies, gfp);
		break;
	case FUSE_LISTXATTR:
		err = extfuse_add_target(req, state, args->nodeid,
					 EXTFUSE_COHERENCE_DOMAIN_XATTR, gfp);
		break;
	case FUSE_READ:
	case FUSE_READDIR:
	case FUSE_READDIRPLUS:
	case FUSE_READLINK:
		state->mutation = true;
		state->pre_hit_allowed = true;
		state->pre_hit_invalidate = true;
		err = extfuse_add_target(req, state, args->nodeid,
					 EXTFUSE_COHERENCE_DOMAIN_ATTR, gfp);
		break;
	case FUSE_OPEN: {
		const struct fuse_open_in *open;

		if (!args->in_numargs || !args->in_args[0].value ||
		    args->in_args[0].size < sizeof(*open))
			break;
		open = args->in_args[0].value;
		if (!(open->flags & O_TRUNC))
			break;
		state->mutation = true;
		err = extfuse_add_target(req, state, args->nodeid,
					 EXTFUSE_COHERENCE_DOMAIN_ATTR |
					 EXTFUSE_COHERENCE_DOMAIN_DATA, gfp);
		break;
	}
	case FUSE_RELEASE: {
		const struct fuse_release_in *release;

		if (!args->in_numargs || !args->in_args[0].value ||
		    args->in_args[0].size < sizeof(*release))
			break;
		release = args->in_args[0].value;
		if ((release->flags & O_ACCMODE) == O_RDONLY)
			break;
		state->mutation = true;
		err = extfuse_add_target(req, state, args->nodeid,
					 EXTFUSE_COHERENCE_DOMAIN_ATTR |
					 EXTFUSE_COHERENCE_DOMAIN_DATA, gfp);
		break;
	}
	case FUSE_LOOKUP:
		err = extfuse_add_target(req, state, args->nodeid,
					 EXTFUSE_COHERENCE_DOMAIN_NAMESPACE,
					 gfp);
		break;
	case FUSE_FLUSH:
	case FUSE_FSYNC:
	case FUSE_FSYNCDIR:
	case FUSE_SYNCFS:
	case FUSE_IOCTL:
		state->mutation = true;
		if (args->opcode == FUSE_SYNCFS) {
			state->global_mutation = true;
			state->request_dependencies =
				EXTFUSE_COHERENCE_DOMAIN_ALL;
			spin_lock(&req->fm->fc->extfuse_global_coherence_lock);
			state->global_pre_epoch =
				req->fm->fc->extfuse_global_epoch;
			spin_unlock(&req->fm->fc->extfuse_global_coherence_lock);
			break;
		}
		if (args->opcode == FUSE_FSYNCDIR ||
		    (args->extfuse_inode &&
		     S_ISDIR(args->extfuse_inode->i_mode)))
			dependencies = EXTFUSE_COHERENCE_DOMAIN_ATTR |
				       EXTFUSE_COHERENCE_DOMAIN_XATTR |
				       EXTFUSE_COHERENCE_DOMAIN_NAMESPACE;
		else
			dependencies = EXTFUSE_COHERENCE_DOMAIN_ATTR |
				       EXTFUSE_COHERENCE_DOMAIN_XATTR |
				       EXTFUSE_COHERENCE_DOMAIN_DATA;
		err = extfuse_add_target(req, state, args->nodeid, dependencies,
					 gfp);
		break;
	case FUSE_SETATTR:
		state->mutation = true;
		err = extfuse_add_target(req, state, args->nodeid,
					 EXTFUSE_COHERENCE_DOMAIN_ATTR |
					 EXTFUSE_COHERENCE_DOMAIN_DATA,
					 gfp);
		break;
	case FUSE_SETXATTR:
	case FUSE_REMOVEXATTR:
		state->mutation = true;
		err = extfuse_add_target(req, state, args->nodeid,
					 EXTFUSE_COHERENCE_DOMAIN_ATTR |
					 EXTFUSE_COHERENCE_DOMAIN_XATTR,
					 gfp);
		break;
	case FUSE_WRITE:
		state->mutation = true;
		state->trailer_capable = true;
		err = extfuse_add_target(req, state, args->nodeid,
					 EXTFUSE_COHERENCE_DOMAIN_ATTR |
					 EXTFUSE_COHERENCE_DOMAIN_DATA,
					 gfp);
		break;
	case FUSE_FALLOCATE:
		state->mutation = true;
		err = extfuse_add_target(req, state, args->nodeid,
					 EXTFUSE_COHERENCE_DOMAIN_ATTR |
					 EXTFUSE_COHERENCE_DOMAIN_DATA,
					 gfp);
		break;
	case FUSE_CREATE:
	case FUSE_MKNOD:
	case FUSE_MKDIR:
	case FUSE_SYMLINK:
	case FUSE_UNLINK:
	case FUSE_RMDIR:
	case FUSE_TMPFILE:
		state->mutation = true;
		err = extfuse_add_target(req, state, args->nodeid,
					 EXTFUSE_COHERENCE_DOMAIN_ATTR |
					 EXTFUSE_COHERENCE_DOMAIN_NAMESPACE,
					 gfp);
		if (!err && (args->opcode == FUSE_UNLINK ||
			     args->opcode == FUSE_RMDIR) && args->extfuse_inode2)
			err = extfuse_add_target(req, state,
						 get_node_id(args->extfuse_inode2),
						 EXTFUSE_COHERENCE_DOMAIN_ATTR,
						 gfp);
		break;
	case FUSE_LINK: {
		const struct fuse_link_in *link;

		state->mutation = true;
		err = extfuse_add_target(req, state, args->nodeid,
					 EXTFUSE_COHERENCE_DOMAIN_ATTR |
					 EXTFUSE_COHERENCE_DOMAIN_NAMESPACE,
					 gfp);
		if (!err && args->in_numargs && args->in_args[0].value &&
		    args->in_args[0].size >= sizeof(*link)) {
			link = args->in_args[0].value;
			err = extfuse_add_target(req, state, link->oldnodeid,
						 EXTFUSE_COHERENCE_DOMAIN_ATTR,
						 gfp);
		}
		break;
	}
	case FUSE_RENAME:
	case FUSE_RENAME2: {
		const struct fuse_rename_in *rename;

		state->mutation = true;
		err = extfuse_add_target(req, state, args->nodeid,
					 EXTFUSE_COHERENCE_DOMAIN_ATTR |
					 EXTFUSE_COHERENCE_DOMAIN_NAMESPACE,
					 gfp);
		if (!err && args->in_numargs && args->in_args[0].value &&
		    args->in_args[0].size >= sizeof(*rename)) {
			rename = args->in_args[0].value;
			err = extfuse_add_target(req, state, rename->newdir,
							 EXTFUSE_COHERENCE_DOMAIN_ATTR |
							 EXTFUSE_COHERENCE_DOMAIN_NAMESPACE,
							 gfp);
		}
		if (!err && args->extfuse_inode3)
			err = extfuse_add_target(req, state,
						 get_node_id(args->extfuse_inode3),
						 EXTFUSE_COHERENCE_DOMAIN_ATTR,
						 gfp);
		if (!err && args->extfuse_inode4)
			err = extfuse_add_target(req, state,
						 get_node_id(args->extfuse_inode4),
						 EXTFUSE_COHERENCE_DOMAIN_ATTR,
						 gfp);
		break;
	}
	case FUSE_COPY_FILE_RANGE:
	case FUSE_COPY_FILE_RANGE_64:
		if (!args->in_numargs || !args->in_args[0].value ||
		    args->in_args[0].size < sizeof(*copy))
			break;
		copy = args->in_args[0].value;
		state->mutation = true;
		state->trailer_capable = true;
		err = extfuse_add_target(req, state, args->nodeid,
					 EXTFUSE_COHERENCE_DOMAIN_ATTR, gfp);
		if (!err)
			err = extfuse_add_target(req, state, copy->nodeid_out,
						 EXTFUSE_COHERENCE_DOMAIN_ATTR |
						 EXTFUSE_COHERENCE_DOMAIN_DATA,
						 gfp);
		break;
	default:
		break;
	}
	if (err || (!state->target_count && !state->global_mutation)) {
		extfuse_state_put(state);
		return err;
	}

	req->extfuse_state = state;
	return 0;
}

static bool extfuse_opcode_is_mutation(u32 opcode)
{
	switch (opcode) {
	case FUSE_SETATTR:
	case FUSE_SETXATTR:
	case FUSE_REMOVEXATTR:
	case FUSE_WRITE:
	case FUSE_FALLOCATE:
	case FUSE_CREATE:
	case FUSE_MKNOD:
	case FUSE_MKDIR:
	case FUSE_SYMLINK:
	case FUSE_UNLINK:
	case FUSE_RMDIR:
	case FUSE_TMPFILE:
	case FUSE_LINK:
	case FUSE_RENAME:
	case FUSE_RENAME2:
	case FUSE_COPY_FILE_RANGE:
	case FUSE_COPY_FILE_RANGE_64:
	case FUSE_READ:
	case FUSE_READDIR:
	case FUSE_READDIRPLUS:
	case FUSE_READLINK:
	case FUSE_OPEN:
	case FUSE_RELEASE:
	case FUSE_FLUSH:
	case FUSE_FSYNC:
	case FUSE_FSYNCDIR:
	case FUSE_SYNCFS:
	case FUSE_IOCTL:
		return true;
	default:
		return false;
	}
}

static bool extfuse_output_valid(struct fuse_req *req, ssize_t result);
static bool extfuse_pre_output_valid(struct fuse_req *req, ssize_t result);

ssize_t extfuse_request_pre(struct fuse_req *req, gfp_t gfp)
{
	struct fuse_conn *fc = req->fm->fc;
	struct extfuse_req_state *state;
	struct extfuse_coherence pre = { };
	u32 validated;
	u32 reason = EXTFUSE_TRACE_REASON_NONE;
	u32 action;
	ssize_t ret;
	unsigned int out_capacity = 0;
	unsigned int i = 0;
	int err;

	if (!READ_ONCE(fc->extfuse_coherence_epochs))
		return extfuse_request_send(fc, req->args);
	if (!req->in.h.unique)
		req->in.h.unique = fuse_get_unique(&fc->iq);

	err = extfuse_build_state(req, gfp);
	if (err == -ENOMEM) {
		if (extfuse_args_is_mutation(req->args)) {
			extfuse_trace(req, req->args->nodeid,
				       EXTFUSE_TRACE_PHASE_PRE,
				       EXTFUSE_TRACE_ACTION_ERROR,
				       EXTFUSE_TRACE_REASON_PROGRAM_ERROR,
				       err, 0);
			req->extfuse_pre_traced = true;
			return err;
		}
		extfuse_trace(req, req->args->nodeid, EXTFUSE_TRACE_PHASE_PRE,
			       EXTFUSE_TRACE_ACTION_FALLBACK,
			       EXTFUSE_TRACE_REASON_PROGRAM_FALLBACK,
			       -ENOSYS, 0);
		req->extfuse_pre_traced = true;
		return -ENOSYS;
	}
	if (err)
		return err;
	state = req->extfuse_state;
	if (!state) {
		pre.version = EXTFUSE_COHERENCE_VERSION;
		pre.phase = EXTFUSE_COHERENCE_PHASE_PRE;
		pre.unique = req->in.h.unique;
		ret = __extfuse_request_send_ctx(fc, req->args, &req->in.h,
						 &pre, false, &reason);
		action = extfuse_pre_action(ret, reason);
		extfuse_trace(req, req->args->nodeid, EXTFUSE_TRACE_PHASE_PRE,
			       action, reason, ret, 0);
		req->extfuse_pre_traced = true;
		return ret;
	}

	pre.version = EXTFUSE_COHERENCE_VERSION;
	pre.phase = EXTFUSE_COHERENCE_PHASE_PRE;
	pre.target_count = state->target_count;
	pre.request_dependencies = state->request_dependencies;
	pre.unique = req->in.h.unique;
	for (i = 0; i < state->target_count; i++)
		pre.targets[i] = state->targets[i].pre;
	if (req->args->opcode == FUSE_GETXATTR && req->args->out_argvar &&
	    req->args->out_numargs)
		out_capacity = req->args->out_args[0].size;

	ret = __extfuse_request_send_ctx(fc, req->args, &req->in.h,
					 &pre, false, &reason);
	if (state->mutation && !state->pre_hit_allowed && ret != -ENOSYS) {
		ret = -ENOSYS;
		reason = EXTFUSE_TRACE_REASON_PROGRAM_FALLBACK;
	}
	if (ret != -ENOSYS && !extfuse_pre_output_valid(req, ret)) {
		ret = -ENOSYS;
		reason = EXTFUSE_TRACE_REASON_INVALID_OUTPUT;
	}

	validated = state->request_dependencies;
	if (req->args->opcode == FUSE_GETXATTR)
		validated = extfuse_validated_dependencies(req->args, ret);
	if (ret != -ENOSYS) {
		for (i = 0; i < state->target_count; i++) {
			u32 dependencies = state->targets[i].dependencies &
				validated;

			if (state->targets[i].pre.active & dependencies) {
				ret = -ENOSYS;
				reason = EXTFUSE_TRACE_REASON_ACTIVE;
				break;
			}
			if (dependencies &&
			    !extfuse_target_stable(&state->targets[i],
						    dependencies)) {
				ret = -ENOSYS;
				reason = EXTFUSE_TRACE_REASON_RACE;
				break;
			}
		}
	}
	if (ret != -ENOSYS && ret >= 0 && state->pre_hit_invalidate)
		for (i = 0; i < state->target_count; i++)
			extfuse_coherence_invalidate_inode(fc,
						 state->targets[i].inode,
						 state->targets[i].dependencies);
	if (ret == -ENOSYS && out_capacity)
		req->args->out_args[0].size = out_capacity;

	action = extfuse_pre_action(ret, reason);
	extfuse_trace(req, req->args->nodeid, EXTFUSE_TRACE_PHASE_PRE,
		       action, reason, ret, validated);
	req->extfuse_pre_traced = true;
	return ret;
}
EXPORT_SYMBOL_GPL(extfuse_request_pre);

static void extfuse_optional_out_remove(struct fuse_req *req)
{
	struct extfuse_req_state *state = req->extfuse_state;
	struct fuse_args *args = req->args;

	if (!state || !state->optional_out)
		return;
	if (WARN_ON_ONCE(args->out_numargs != 2 ||
			 args->out_args[1].value != state->mutation_out))
		return;
	args->out_numargs--;
	args->out_args[1].size = 0;
	args->out_args[1].value = NULL;
	args->out_arg_optional = false;
	args->out_arg_optional_invalid = false;
	state->optional_out = false;
}

int extfuse_request_prepare_daemon(struct fuse_req *req, gfp_t gfp)
{
	struct fuse_conn *fc = req->fm->fc;
	struct extfuse_req_state *state;
	struct fuse_args *args = req->args;
	unsigned int i = 0;
	int err;

	if (!READ_ONCE(fc->extfuse_coherence_epochs))
		return 0;
	if (!req->in.h.unique)
		req->in.h.unique = fuse_get_unique(&fc->iq);
	err = extfuse_build_state(req, gfp);
	if (err == -ENOMEM && !extfuse_args_is_mutation(args)) {
		if (!req->extfuse_pre_traced) {
			extfuse_trace(req, args->nodeid, EXTFUSE_TRACE_PHASE_PRE,
				       EXTFUSE_TRACE_ACTION_SKIPPED,
				       EXTFUSE_TRACE_REASON_PROGRAM_FALLBACK,
				       -ENOSYS, 0);
			req->extfuse_pre_traced = true;
		}
		return 0;
	}
	if (err)
		return err;
	state = req->extfuse_state;
	if (!state) {
		if (!req->extfuse_pre_traced) {
			extfuse_trace(req, args->nodeid, EXTFUSE_TRACE_PHASE_PRE,
				       EXTFUSE_TRACE_ACTION_SKIPPED,
				       EXTFUSE_TRACE_REASON_PROGRAM_FALLBACK,
				       -ENOSYS, 0);
			req->extfuse_pre_traced = true;
		}
		return 0;
	}

	if (state->trailer_capable &&
	    READ_ONCE(fc->extfuse_mutation_metadata)) {
		if (args->out_numargs != 1 || args->out_argvar)
			return -EINVAL;
		if (WARN_ON_ONCE(!state->mutation_out))
			return -ENOMEM;
		args->out_numargs = 2;
		args->out_args[1].size = sizeof(*state->mutation_out);
		args->out_args[1].value = state->mutation_out;
		args->out_arg_optional = true;
		args->out_arg_optional_invalid = false;
		state->optional_out = true;
	}
	if (!req->extfuse_pre_traced) {
		extfuse_trace(req, args->nodeid, EXTFUSE_TRACE_PHASE_PRE,
			       EXTFUSE_TRACE_ACTION_SKIPPED,
			       EXTFUSE_TRACE_REASON_PROGRAM_FALLBACK,
			       -ENOSYS, state->request_dependencies);
		req->extfuse_pre_traced = true;
	}

	if (!state->mutation || state->begun)
		return 0;
	if (state->global_mutation) {
		err = extfuse_global_begin(fc);
		if (err)
			goto undo;
		state->global_active_owned = true;
		extfuse_trace(req, args->nodeid, EXTFUSE_TRACE_PHASE_BEGIN,
			       EXTFUSE_TRACE_ACTION_MUTATION,
			       EXTFUSE_TRACE_REASON_NONE, 0,
			       state->request_dependencies);
	}
	for (i = 0; i < state->target_count; i++) {
		if (!state->targets[i].inode) {
			err = -ESTALE;
			goto undo;
		}
		err = extfuse_inode_begin(state->targets[i].inode,
					  state->targets[i].dependencies);
		if (err)
			goto undo;
		state->targets[i].active_owned = true;
		extfuse_trace(req, state->targets[i].pre.nodeid,
			       EXTFUSE_TRACE_PHASE_BEGIN,
			       EXTFUSE_TRACE_ACTION_MUTATION,
			       EXTFUSE_TRACE_REASON_NONE, 0,
			       state->targets[i].dependencies);
	}
	state->begun = true;
	return 0;

undo:
	while (i--) {
		if (!state->targets[i].active_owned)
			continue;
		extfuse_inode_end(state->targets[i].inode,
				   state->targets[i].dependencies);
		state->targets[i].active_owned = false;
		extfuse_trace(req, state->targets[i].pre.nodeid,
			       EXTFUSE_TRACE_PHASE_END,
			       EXTFUSE_TRACE_ACTION_MUTATION,
			       EXTFUSE_TRACE_REASON_PROGRAM_ERROR, err,
			       state->targets[i].dependencies);
	}
	if (state->global_active_owned) {
		extfuse_global_end(fc);
		state->global_active_owned = false;
		extfuse_trace(req, args->nodeid, EXTFUSE_TRACE_PHASE_END,
			       EXTFUSE_TRACE_ACTION_MUTATION,
			       EXTFUSE_TRACE_REASON_PROGRAM_ERROR, err,
			       state->request_dependencies);
	}
	extfuse_optional_out_remove(req);
	return err;
}
EXPORT_SYMBOL_GPL(extfuse_request_prepare_daemon);

static void extfuse_request_end_mutation(struct fuse_req *req, int error)
{
	struct extfuse_req_state *state = req->extfuse_state;
	unsigned int i;

	if (!state || !state->begun)
		return;
	state->begun = false;
	for (i = 0; i < state->target_count; i++) {
		if (!state->targets[i].active_owned)
			continue;
		extfuse_inode_end(state->targets[i].inode,
				   state->targets[i].dependencies);
		state->targets[i].active_owned = false;
		state->targets[i].mutation_completed = true;
		extfuse_trace(req, state->targets[i].pre.nodeid,
			       EXTFUSE_TRACE_PHASE_END,
			       EXTFUSE_TRACE_ACTION_MUTATION,
			       EXTFUSE_TRACE_REASON_NONE, error,
			       state->targets[i].dependencies);
	}
	if (state->global_active_owned) {
		extfuse_global_end(req->fm->fc);
		state->global_active_owned = false;
		state->global_mutation_completed = true;
		extfuse_trace(req, req->args->nodeid, EXTFUSE_TRACE_PHASE_END,
			       EXTFUSE_TRACE_ACTION_MUTATION,
			       EXTFUSE_TRACE_REASON_NONE, error,
			       state->request_dependencies);
	}
}

static bool extfuse_getxattr_request_valid(struct fuse_args *args,
					   const struct fuse_getxattr_in **in)
{
	if (args->in_numargs != 2 || !args->in_args[0].value ||
	    args->in_args[0].size != sizeof(**in) ||
	    !args->in_args[1].value || args->in_args[1].size < 2 ||
	    args->in_args[1].size > XATTR_NAME_MAX + 1 ||
	    strnlen(args->in_args[1].value, args->in_args[1].size) !=
		args->in_args[1].size - 1 || args->out_numargs != 1 ||
	    !args->out_args[0].value)
		return false;
	*in = args->in_args[0].value;
	return !(*in)->padding;
}

static bool extfuse_daemon_getxattr_success_valid(struct fuse_req *req)
{
	const struct fuse_getxattr_in *in;
	const struct fuse_getxattr_out *out;
	struct fuse_args *args = req->args;

	if (!extfuse_getxattr_request_valid(args, &in))
		return false;
	if (in->size)
		return args->out_argvar && args->out_args[0].size <= in->size;
	if (args->out_argvar || args->out_args[0].size != sizeof(*out))
		return false;
	out = args->out_args[0].value;
	return !out->padding && out->size <= XATTR_SIZE_MAX;
}

static bool extfuse_output_valid(struct fuse_req *req, ssize_t result)
{
	struct extfuse_req_state *state = req->extfuse_state;
	struct fuse_args *args = req->args;

	if (result)
		return true;
	if (args->opcode == FUSE_GETXATTR)
		return extfuse_daemon_getxattr_success_valid(req);

	switch (args->opcode) {
	case FUSE_GETATTR:
	case FUSE_SETATTR: {
		const struct fuse_attr_out *out;

		if (!args->out_numargs || !args->out_args[0].value ||
		    args->out_args[0].size < sizeof(*out))
			return false;
		out = args->out_args[0].value;
		return out->attr_valid_nsec < NSEC_PER_SEC &&
		       !fuse_invalid_attr((struct fuse_attr *)&out->attr) &&
		       (!state->targets[0].inode ||
			!inode_wrong_type(state->targets[0].inode,
					  out->attr.mode));
	}
	case FUSE_LOOKUP: {
		const struct fuse_entry_out *out;

		if (!args->out_numargs || !args->out_args[0].value ||
		    args->out_args[0].size < sizeof(*out))
			return false;
		out = args->out_args[0].value;
		if (out->entry_valid_nsec >= NSEC_PER_SEC ||
		    out->attr_valid_nsec >= NSEC_PER_SEC)
			return false;
		if (!out->nodeid)
			return true;
		return !invalid_nodeid(out->nodeid) &&
		       !fuse_invalid_attr((struct fuse_attr *)&out->attr);
	}
	case FUSE_CREATE:
	case FUSE_MKNOD:
	case FUSE_MKDIR:
	case FUSE_SYMLINK:
	case FUSE_LINK:
	case FUSE_TMPFILE: {
		const struct fuse_entry_out *out;

		if (!args->out_numargs || !args->out_args[0].value ||
		    args->out_args[0].size < sizeof(*out))
			return false;
		out = args->out_args[0].value;
		return out->entry_valid_nsec < NSEC_PER_SEC &&
		       out->attr_valid_nsec < NSEC_PER_SEC &&
		       !invalid_nodeid(out->nodeid) &&
		       !fuse_invalid_attr((struct fuse_attr *)&out->attr);
	}
	case FUSE_WRITE: {
		const struct fuse_write_in *in;
		const struct fuse_write_out *out;

		if (!args->in_numargs || !args->out_numargs ||
		    !args->in_args[0].value || !args->out_args[0].value ||
		    args->in_args[0].size < sizeof(*in) ||
		    args->out_args[0].size < sizeof(*out))
			return false;
		in = args->in_args[0].value;
		out = args->out_args[0].value;
		return out->size <= in->size;
	}
	case FUSE_COPY_FILE_RANGE:
	case FUSE_COPY_FILE_RANGE_64: {
		const struct fuse_copy_file_range_in *in;
		u64 copied;

		if (!args->in_numargs || !args->out_numargs ||
		    !args->in_args[0].value || !args->out_args[0].value ||
		    args->in_args[0].size < sizeof(*in))
			return false;
		in = args->in_args[0].value;
		if (args->opcode == FUSE_COPY_FILE_RANGE_64) {
			const struct fuse_copy_file_range_out *out;

			if (args->out_args[0].size < sizeof(*out))
				return false;
			out = args->out_args[0].value;
			copied = out->bytes_copied;
		} else {
			const struct fuse_write_out *out;

			if (args->out_args[0].size < sizeof(*out))
				return false;
			out = args->out_args[0].value;
			copied = out->size;
		}
		return copied <= in->len;
	}
	default:
		return true;
	}
}

static bool extfuse_pre_getxattr_valid(struct fuse_req *req, ssize_t result)
{
	const struct fuse_getxattr_in *in;
	const struct fuse_getxattr_out *out;
	struct fuse_args *args = req->args;

	if (!extfuse_getxattr_request_valid(args, &in))
		return false;

	if (!in->size) {
		if (result == -ENODATA)
			return true;
		if (result || args->out_argvar ||
		    args->out_args[0].size != sizeof(*out))
			return false;
		out = args->out_args[0].value;
		return !out->padding && out->size <= XATTR_SIZE_MAX;
	}

	if (result == -ERANGE)
		return true;
	if (result < 0 || !args->out_argvar)
		return false;
	return result <= in->size && args->out_args[0].size == result;
}

static bool extfuse_pre_output_valid(struct fuse_req *req, ssize_t result)
{
	switch (req->args->opcode) {
	case FUSE_GETATTR:
	case FUSE_LOOKUP:
		if (result)
			return false;
		break;
	case FUSE_GETXATTR:
		return extfuse_pre_getxattr_valid(req, result);
	default:
		if (result)
			return true;
		break;
	}

	return extfuse_output_valid(req, 0);
}

static bool extfuse_registered_node(const struct extfuse_req_state *state,
					     u64 nodeid, u32 *index)
{
	unsigned int i;

	for (i = 0; i < state->target_count; i++) {
		if (state->targets[i].pre.nodeid != nodeid)
			continue;
		*index = i;
		return true;
	}
	return false;
}

static u32 extfuse_validate_mutation_out(struct fuse_req *req)
{
	struct extfuse_req_state *state = req->extfuse_state;
	struct extfuse_mutation_payload *payload = state->mutation_out;
	struct fuse_args *args = req->args;
	unsigned long xattr_changed = 0;
	unsigned long seen = 0;
	size_t expected;
	u32 index;
	unsigned int i;

	if (!state->trailer_capable)
		return EXTFUSE_TRACE_REASON_NONE;
	if (!state->optional_out || !payload || req->out.h.error ||
	    !args->out_args[1].size)
		return EXTFUSE_TRACE_REASON_TRAILER_ABSENT;
	if (args->out_arg_optional_invalid ||
	    args->out_args[1].size < sizeof(payload->out))
		return EXTFUSE_TRACE_REASON_TRAILER_INVALID;
	if (payload->out.version != FUSE_MUTATION_OUT_VERSION ||
	    !payload->out.count ||
	    payload->out.count > FUSE_MUTATION_MAX_NODES ||
	    payload->out.flags)
		return EXTFUSE_TRACE_REASON_TRAILER_INVALID;
	expected = sizeof(payload->out) +
		   payload->out.count * sizeof(payload->nodes[0]);
	if (args->out_args[1].size != expected)
		return EXTFUSE_TRACE_REASON_TRAILER_INVALID;

	for (i = 0; i < payload->out.count; i++) {
		struct fuse_mutation_node_out *node = &payload->nodes[i];
		u32 xattr = FUSE_MUTATION_NODE_XATTR_UNCHANGED |
			    FUSE_MUTATION_NODE_XATTR_CHANGED;
		u32 allowed = FUSE_MUTATION_NODE_ATTR_VALID | xattr;

		if (!extfuse_registered_node(state, node->nodeid, &index) ||
		    test_and_set_bit(index, &seen) || node->reserved ||
		    (node->flags & ~allowed) ||
		    (node->flags & xattr) == xattr)
			return EXTFUSE_TRACE_REASON_TRAILER_INVALID;
		if ((node->flags & FUSE_MUTATION_NODE_ATTR_VALID) &&
		    (node->attr.attr_valid_nsec >= NSEC_PER_SEC ||
		     fuse_invalid_attr(&node->attr.attr) ||
		     (state->targets[index].inode &&
			      inode_wrong_type(state->targets[index].inode,
				       node->attr.attr.mode))))
			return EXTFUSE_TRACE_REASON_TRAILER_INVALID;
		if (node->flags & FUSE_MUTATION_NODE_XATTR_CHANGED)
			xattr_changed |= BIT(index);
	}
	/*
	 * XATTR_UNCHANGED needs no eager action: ordinary xattr hits remain
	 * DATA-dependent.  Commit CHANGED only after every record validates.
	 */
	state->trailer_xattr_changed = xattr_changed;
	return EXTFUSE_TRACE_REASON_NONE;
}

static void extfuse_apply_trailer_xattr_changes(struct fuse_req *req)
{
	struct extfuse_req_state *state = req->extfuse_state;
	unsigned int i;

	for (i = 0; i < state->target_count; i++)
		if (state->trailer_xattr_changed & BIT(i))
			extfuse_coherence_invalidate_inode(req->fm->fc,
						 state->targets[i].inode,
						 EXTFUSE_COHERENCE_DOMAIN_XATTR);
}

static bool extfuse_post_stable(struct fuse_conn *fc,
				 struct extfuse_req_state *state,
				 u32 validated, bool mutation)
{
	u64 global_epoch;
	u32 global_active;
	unsigned int i;

	if (state->global_mutation) {
		spin_lock(&fc->extfuse_global_coherence_lock);
		global_epoch = fc->extfuse_global_epoch;
		global_active = fc->extfuse_global_active;
		spin_unlock(&fc->extfuse_global_coherence_lock);
		if (!state->global_mutation_completed || global_active ||
		    global_epoch != state->global_pre_epoch + 2)
			return false;
	}
	for (i = 0; i < state->target_count; i++) {
		struct extfuse_coherence_target snapshot = { };
		u32 dependencies = state->targets[i].dependencies & validated;

		if (!dependencies || !state->targets[i].inode)
			return false;
		if (!mutation) {
			if (!extfuse_target_stable(&state->targets[i],
						    dependencies))
				return false;
			continue;
		}
		extfuse_snapshot_inode(state->targets[i].inode, dependencies,
					 &snapshot);
		if (!state->targets[i].mutation_completed ||
		    snapshot.incarnation != state->targets[i].pre.incarnation ||
		    (snapshot.active & dependencies))
			return false;
		if ((dependencies & EXTFUSE_COHERENCE_DOMAIN_ATTR) &&
		    snapshot.attr_epoch != state->targets[i].pre.attr_epoch + 2)
			return false;
		if ((dependencies & EXTFUSE_COHERENCE_DOMAIN_XATTR) &&
		    snapshot.xattr_epoch != state->targets[i].pre.xattr_epoch + 2)
			return false;
		if ((dependencies & EXTFUSE_COHERENCE_DOMAIN_DATA) &&
		    snapshot.data_epoch != state->targets[i].pre.data_epoch + 2)
			return false;
		if ((dependencies & EXTFUSE_COHERENCE_DOMAIN_NAMESPACE) &&
		    snapshot.namespace_epoch !=
			state->targets[i].pre.namespace_epoch + 2)
			return false;
	}
	return true;
}

static void extfuse_post_daemon(struct fuse_req *req, u32 reason)
{
	struct extfuse_req_state *state = req->extfuse_state;
	struct extfuse_coherence post = { };
	u32 validated = state->request_dependencies;
	u32 post_reason = EXTFUSE_TRACE_REASON_NONE;
	ssize_t ret;
	unsigned int i;

	if (req->args->opcode == FUSE_GETXATTR)
		validated = extfuse_validated_dependencies(req->args,
							 req->out.h.error);
	if (!reason && !extfuse_post_stable(req->fm->fc, state, validated,
						  state->mutation))
		reason = state->trailer_capable ?
			 EXTFUSE_TRACE_REASON_TRAILER_RACE :
			 EXTFUSE_TRACE_REASON_RACE;
	if (reason) {
		extfuse_trace(req, req->args->nodeid,
			       EXTFUSE_TRACE_PHASE_POST_DAEMON,
			       EXTFUSE_TRACE_ACTION_SKIPPED, reason,
			       req->out.h.error, validated);
		return;
	}

	post.version = EXTFUSE_COHERENCE_VERSION;
	post.phase = EXTFUSE_COHERENCE_PHASE_POST_DAEMON;
	post.target_count = state->target_count;
	post.daemon_error = req->out.h.error;
	post.request_dependencies = state->request_dependencies;
	post.validated_dependencies = validated;
	post.reason = EXTFUSE_TRACE_REASON_NONE;
	post.unique = req->in.h.unique;
	for (i = 0; i < state->target_count; i++)
		extfuse_snapshot_inode(state->targets[i].inode,
					 state->targets[i].dependencies,
					 &post.targets[i]);

	ret = __extfuse_request_send_ctx(req->fm->fc, req->args, &req->in.h,
					 &post, true, &post_reason);
	if (ret) {
		extfuse_trace(req, req->args->nodeid,
			       EXTFUSE_TRACE_PHASE_POST_DAEMON,
			       EXTFUSE_TRACE_ACTION_SKIPPED,
			       EXTFUSE_TRACE_REASON_POST_ERROR,
			       req->out.h.error, validated);
		return;
	}
	extfuse_trace(req, req->args->nodeid,
		       EXTFUSE_TRACE_PHASE_POST_DAEMON,
		       EXTFUSE_TRACE_ACTION_POSTED,
		       EXTFUSE_TRACE_REASON_NONE, req->out.h.error,
		       validated);
}

void extfuse_request_complete(struct fuse_req *req)
{
	struct extfuse_req_state *state = req->extfuse_state;
	u32 reason;

	if (!state)
		return;
	if (!req->extfuse_reply_received) {
		reason = EXTFUSE_TRACE_REASON_POST_ERROR;
	} else if (!extfuse_output_valid(req, req->out.h.error)) {
		req->out.h.error = -EIO;
		reason = EXTFUSE_TRACE_REASON_INVALID_OUTPUT;
	} else {
		reason = extfuse_validate_mutation_out(req);
	}
	extfuse_request_end_mutation(req, req->out.h.error);
	if (!reason)
		extfuse_apply_trailer_xattr_changes(req);
	extfuse_post_daemon(req, reason);
	extfuse_optional_out_remove(req);
}
EXPORT_SYMBOL_GPL(extfuse_request_complete);

void extfuse_request_cancel(struct fuse_req *req, int error)
{
	extfuse_request_end_mutation(req, error);
	extfuse_optional_out_remove(req);
}
EXPORT_SYMBOL_GPL(extfuse_request_cancel);

void extfuse_request_free(struct fuse_req *req)
{
	extfuse_request_end_mutation(req, -ECANCELED);
	extfuse_optional_out_remove(req);
	extfuse_state_put(req->extfuse_state);
	req->extfuse_state = NULL;
}
EXPORT_SYMBOL_GPL(extfuse_request_free);

static ssize_t extfuse_release_race_fallback(struct fuse_conn *fc)
{
	return READ_ONCE(fc->connected) ? -ENOSYS : -ENOTCONN;
}

static ssize_t extfuse_getattr_after_release(struct fuse_conn *fc,
					     struct fuse_args *args,
					     struct inode *inode)
{
	struct fuse_attr_release_barrier_snapshot snapshot;
	ssize_t ret;

	if (!READ_ONCE(fc->connected) ||
	    !fuse_attr_release_barrier_enabled(fc))
		return extfuse_release_race_fallback(fc);

	args->extfuse_getattr_refresh(inode);
	if (!READ_ONCE(fc->connected) ||
	    !fuse_attr_release_barrier_enabled(fc))
		return extfuse_release_race_fallback(fc);

	/* A new RELEASE gets normal userspace fallback instead of another wait. */
	snapshot = fuse_attr_release_barrier_snapshot(inode);
	if (snapshot.pending)
		return extfuse_release_race_fallback(fc);

	ret = __extfuse_request_send(fc, args);
	if (!READ_ONCE(fc->connected) ||
	    !fuse_attr_release_barrier_enabled(fc) ||
	    fuse_attr_release_barrier_changed(inode, &snapshot))
		return extfuse_release_race_fallback(fc);

	return ret;
}

/* Keep this symbol as the stable tracing and request-accounting boundary. */
noinline ssize_t extfuse_request_send(struct fuse_conn *fc,
				      struct fuse_args *args)
{
	struct fuse_attr_release_barrier_snapshot snapshot;
	struct inode *inode = args->extfuse_getattr_inode;
	bool release_barrier;
	ssize_t ret;

	/*
	 * GETATTR supplies its inode directly: resolving nodeid here would race
	 * eviction and would add a global lookup to every ExtFUSE request.
	 */
	release_barrier = args->opcode == FUSE_GETATTR && inode &&
		args->extfuse_getattr_refresh && S_ISREG(inode->i_mode) &&
		get_node_id(inode) == args->nodeid &&
		fuse_attr_release_barrier_enabled(fc);
	if (!release_barrier)
		return __extfuse_request_send(fc, args);

	snapshot = fuse_attr_release_barrier_snapshot(inode);
	if (!snapshot.pending) {
		ret = __extfuse_request_send(fc, args);
		if (!fuse_attr_release_barrier_changed(inode, &snapshot))
			return ret;
	}

	/*
	 * RELEASE completion publishes daemon metadata before its end callback
	 * drops pending.  Discard even a successful first dispatch if RELEASE
	 * overlapped it; a signal, bounded-wait timeout, or capability loss takes
	 * the safe ordinary fallback instead.
	 */
	if (fuse_attr_release_barrier_wait(fc, inode))
		return extfuse_release_race_fallback(fc);
	if (!READ_ONCE(fc->connected) ||
	    !fuse_attr_release_barrier_enabled(fc))
		return extfuse_release_race_fallback(fc);

	return extfuse_getattr_after_release(fc, args, inode);
}
EXPORT_SYMBOL_GPL(extfuse_request_send);

/*
 * These two operations are implementation details of the passthrough GETATTR
 * refresh handshake.  They intentionally bypass extfuse_request_send(), so
 * request tracing continues to count only ordinary FUSE requests and the
 * pre-existing native-I/O coherence notifications.
 */
int extfuse_passthrough_attr_prepare(struct fuse_conn *fc, u64 nodeid,
				     struct extfuse_passthrough_attr_cookie *cookie)
{
	struct fuse_args args = {
		.nodeid = nodeid,
		.opcode = EXTFUSE_PASSTHROUGH_ATTR_PREPARE,
		.out_numargs = 1,
		.out_args[0] = {
			.size = sizeof(*cookie),
			.value = cookie,
		},
	};

	if (!cookie)
		return -EINVAL;

	memset(cookie, 0, sizeof(*cookie));
	if (!READ_ONCE(fc->extfuse_passthrough_attr_refresh))
		return -EOPNOTSUPP;

	return __extfuse_request_send(fc, &args);
}
EXPORT_SYMBOL_GPL(extfuse_passthrough_attr_prepare);

int extfuse_passthrough_attr_commit(struct fuse_conn *fc, u64 nodeid,
				    const struct extfuse_passthrough_attr_cookie *cookie,
				    const struct fuse_attr *attr)
{
	struct fuse_args args = {
		.nodeid = nodeid,
		.opcode = EXTFUSE_PASSTHROUGH_ATTR_COMMIT,
		.in_numargs = 2,
		.in_args[0] = {
			.size = sizeof(*cookie),
			.value = cookie,
		},
		.in_args[1] = {
			.size = sizeof(*attr),
			.value = attr,
		},
	};

	if (!cookie || !attr)
		return -EINVAL;
	if (!READ_ONCE(fc->extfuse_passthrough_attr_refresh))
		return -EOPNOTSUPP;

	return __extfuse_request_send(fc, &args);
}
EXPORT_SYMBOL_GPL(extfuse_passthrough_attr_commit);

/*
 * Native passthrough does not create an ordinary FUSE READ/WRITE request.
 * Epoch coherence therefore runs one private BPF policy hook before lower
 * I/O and completes the matching epoch entirely in the kernel. A missing or
 * failing BEGIN handler prevents lower I/O rather than risking a stale hit.
 */
static int __extfuse_passthrough_notify(struct fuse_conn *fc,
					struct inode *inode, u64 nodeid,
					u32 opcode, u32 phase)
{
	struct extfuse_passthrough_in in = {
		.phase = phase,
	};
	struct fuse_args args = { };
	u32 dependencies = opcode == EXTFUSE_PASSTHROUGH_READ ?
		EXTFUSE_COHERENCE_DOMAIN_ATTR :
		EXTFUSE_COHERENCE_DOMAIN_ATTR |
		EXTFUSE_COHERENCE_DOMAIN_DATA;
	u32 reason = EXTFUSE_TRACE_REASON_NONE;
	u32 action;
	ssize_t ret;
	unsigned int coherence;
	bool coherence_epochs = READ_ONCE(fc->extfuse_coherence_epochs);
	bool epoch_mutation = coherence_epochs &&
		(opcode == EXTFUSE_PASSTHROUGH_READ ||
		 opcode == EXTFUSE_PASSTHROUGH_WRITE);

	if (coherence_epochs && !inode)
		return -EINVAL;
	args.nodeid = nodeid;
	args.opcode = opcode;
	args.extfuse_inode = inode;

	coherence = READ_ONCE(fc->extfuse_passthrough_coherence);
	if (!coherence && !coherence_epochs)
		return 0;
	if (coherence_epochs)
		coherence = max(coherence, 2U);
	if (phase != EXTFUSE_PASSTHROUGH_PHASE_BEGIN &&
	    phase != EXTFUSE_PASSTHROUGH_PHASE_END)
		return -EINVAL;
	if (epoch_mutation && phase == EXTFUSE_PASSTHROUGH_PHASE_END) {
		extfuse_inode_end(inode, dependencies);
		extfuse_trace_fc(fc, 0, opcode, nodeid,
				  EXTFUSE_TRACE_PHASE_END,
				  EXTFUSE_TRACE_ACTION_MUTATION,
				  EXTFUSE_TRACE_REASON_NONE, 0,
				  dependencies);
		return 0;
	}
	if (coherence >= 2) {
		args.in_numargs = 1;
		args.in_args[0].size = sizeof(in);
		args.in_args[0].value = &in;
	}
	if (epoch_mutation) {
		ret = extfuse_inode_begin(inode, dependencies);
		if (ret)
			return ret;
		extfuse_trace_fc(fc, 0, opcode, nodeid,
				  EXTFUSE_TRACE_PHASE_BEGIN,
				  EXTFUSE_TRACE_ACTION_MUTATION,
				  EXTFUSE_TRACE_REASON_NONE, 0,
				  dependencies);
	} else if (coherence_epochs &&
		   opcode == EXTFUSE_PASSTHROUGH_MMAP &&
		   phase == EXTFUSE_PASSTHROUGH_PHASE_BEGIN) {
		extfuse_coherence_invalidate_inode(fc, inode, dependencies);
	}

	ret = __extfuse_request_send_ctx(fc, &args, NULL, NULL, false,
					 &reason);
	if (!ret)
		action = EXTFUSE_TRACE_ACTION_HIT;
	else if (ret == -ENOSYS)
		action = EXTFUSE_TRACE_ACTION_FALLBACK;
	else
		action = EXTFUSE_TRACE_ACTION_ERROR;
	extfuse_trace_fc(fc, 0, opcode, nodeid, EXTFUSE_TRACE_PHASE_PRE,
			  action, reason, ret, dependencies);

	if (epoch_mutation && ret) {
		extfuse_inode_end(inode, dependencies);
		extfuse_trace_fc(fc, 0, opcode, nodeid,
				  EXTFUSE_TRACE_PHASE_END,
				  EXTFUSE_TRACE_ACTION_MUTATION,
				  EXTFUSE_TRACE_REASON_PROGRAM_ERROR, ret,
				  dependencies);
	}
	if (!ret)
		return 0;

	pr_warn_ratelimited("native passthrough notification %u failed: %zd\n",
			    opcode, ret);
	return ret < 0 && ret != -ENOSYS ? (int)ret : -EIO;
}

int extfuse_passthrough_notify_inode(struct fuse_conn *fc,
				     struct inode *inode, u32 opcode,
				     u32 phase)
{
	if (!inode)
		return -EINVAL;

	return __extfuse_passthrough_notify(fc, inode, get_node_id(inode),
					      opcode, phase);
}
EXPORT_SYMBOL_GPL(extfuse_passthrough_notify_inode);

/* Compatibility entry point for callers that only retain a node ID. */
int extfuse_passthrough_notify(struct fuse_conn *fc, u64 nodeid, u32 opcode,
			       u32 phase)
{
	struct inode *inode;
	int ret;

	if (!READ_ONCE(fc->extfuse_passthrough_coherence) &&
	    !READ_ONCE(fc->extfuse_coherence_epochs))
		return 0;
	if (!READ_ONCE(fc->extfuse_coherence_epochs))
		return __extfuse_passthrough_notify(fc, NULL, nodeid, opcode,
						    phase);
	inode = extfuse_lookup_node(fc, nodeid);
	if (!inode)
		return -ESTALE;
	ret = extfuse_passthrough_notify_inode(fc, inode, opcode, phase);
	iput(inode);
	return ret;
}
EXPORT_SYMBOL_GPL(extfuse_passthrough_notify);

void extfuse_unload_prog(struct fuse_conn *fc)
{
	struct extfuse_data *data;

	WRITE_ONCE(fc->extfuse_passthrough_attr_release_barrier, 0);
	WRITE_ONCE(fc->extfuse_passthrough_attr_refresh, 0);
	WRITE_ONCE(fc->extfuse_passthrough_coherence, 0);
	WRITE_ONCE(fc->extfuse_notify_inval_xattr, 0);
	WRITE_ONCE(fc->extfuse_mutation_metadata, 0);
	WRITE_ONCE(fc->extfuse_coherence_epochs, 0);
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
	bool post_output = false;
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
		if ((!ctx->post_daemon && size != ctx->out_actual[0]) ||
		    (ctx->post_daemon && size < ctx->out_actual[0]))
			return -E2BIG;
		size = ctx->out_actual[0];
		inptr = ctx->out_values[0];
		post_output = ctx->post_daemon;
		break;
	case OUT_PARAM_1:
		if (num_out_args < 2)
			return -EINVAL;
		if (!(ctx->out_written & BIT(1)))
			return -EACCES;
		if ((!ctx->post_daemon && size != ctx->out_actual[1]) ||
		    (ctx->post_daemon && size < ctx->out_actual[1]))
			return -E2BIG;
		size = ctx->out_actual[1];
		inptr = ctx->out_values[1];
		post_output = ctx->post_daemon;
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

	return ret ?: (post_output ? size : 0);
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

static long extfuse_write_arg(void *dst, u32 type, const void *src, u32 size,
			      bool variable)
{
	struct extfuse_req *req = (struct extfuse_req *)dst;
	struct extfuse_req_ctx *ctx;
	unsigned int numargs = req->out.numargs;
	void *outptr = NULL;
	unsigned int out_idx;
	unsigned int capacity;
	long ret = -EINVAL;

	ctx = container_of(req, struct extfuse_req_ctx, req);
	if (ctx->post_daemon)
		return -EPERM;

	if (type == OUT_PARAM_0 && numargs >= 1) {
		outptr = ctx->out_values[0];
		out_idx = 0;
	} else if (type == OUT_PARAM_1 && numargs >= 2) {
		outptr = ctx->out_values[1];
		out_idx = 1;
	} else {
		pr_debug("invalid write type %u numargs %u size %u\n",
			 type, numargs, size);
		return ret;
	}

	capacity = req->out.args[out_idx].size;
	if (variable &&
	    (req->in.h.opcode != FUSE_GETXATTR || !req->out.argvar ||
	     numargs != 1 || out_idx != 0)) {
		pr_debug("invalid variable write type %u numargs %u size %u\n",
			 type, numargs, size);
		return ret;
	}
	if (!outptr || (variable ? size > capacity : size != capacity)) {
		pr_debug("invalid write type %u numargs %u size %u\n",
			 type, numargs, size);
		return ret;
	}

	ret = size ? copy_to_kernel_nofault(outptr, src, size) : 0;
	if (unlikely(ret < 0))
		return ret;

	ctx->out_actual[out_idx] = size;
	ctx->out_written |= BIT(out_idx);
	if (variable)
		ctx->out_variable |= BIT(out_idx);
	else
		ctx->out_variable &= ~BIT(out_idx);

	return ret;
}

/*
 * bpf_extfuse_write_args - copy a complete fixed-size output argument
 * @dst:  pointer to the struct extfuse_req context
 * @type: which out-arg to write (OUT_PARAM_0 / OUT_PARAM_1)
 * @src:  source buffer in BPF memory
 * @size: number of bytes; must equal the target out-arg size
 */
BPF_CALL_4(bpf_extfuse_write_args, void *, dst, u32, type, const void *, src,
	   u32, size)
{
	return extfuse_write_arg(dst, type, src, size, false);
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

/*
 * bpf_extfuse_write_args_var - copy a variable GETXATTR output argument
 * @dst:  pointer to the struct extfuse_req context
 * @type: must select the single direct output argument
 * @src:  source buffer in BPF memory
 * @size: actual reply length, from zero through the output buffer capacity
 */
BPF_CALL_4(bpf_extfuse_write_args_var, void *, dst, u32, type,
	   const void *, src, u32, size)
{
	return extfuse_write_arg(dst, type, src, size, true);
}

static const struct bpf_func_proto bpf_extfuse_write_args_var_proto = {
	.func		= bpf_extfuse_write_args_var,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg4_type	= ARG_CONST_SIZE_OR_ZERO,
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
	case BPF_FUNC_extfuse_write_args_var:
		return &bpf_extfuse_write_args_var_proto;
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

/* Direct access is limited to stable scalar fields in the request context. */
static bool bpf_extfuse_is_valid_access(int off, int size,
					enum bpf_access_type type,
					const struct bpf_prog *prog,
					struct bpf_insn_access_aux *info)
{
	unsigned int i;

	if (type != BPF_READ)
		return false;

	switch (off) {
	case offsetof(struct extfuse_req, in.h.opcode):
	case offsetof(struct extfuse_req, in.h.uid):
	case offsetof(struct extfuse_req, in.h.gid):
	case offsetof(struct extfuse_req, in.h.pid):
	case offsetof(struct extfuse_req, in.numargs):
	case offsetof(struct extfuse_req, in.args[0].size):
	case offsetof(struct extfuse_req, in.args[1].size):
	case offsetof(struct extfuse_req, in.args[2].size):
	case offsetof(struct extfuse_req, out.numargs):
	case offsetof(struct extfuse_req, out.argvar):
	case offsetof(struct extfuse_req, out.args[0].size):
	case offsetof(struct extfuse_req, out.args[1].size):
	case offsetof(struct extfuse_req, coherence.version):
	case offsetof(struct extfuse_req, coherence.daemon_error):
	case offsetof(struct extfuse_req, coherence.request_dependencies):
	case offsetof(struct extfuse_req, coherence.validated_dependencies):
	case offsetof(struct extfuse_req, coherence.reason):
		return size == sizeof(__u32);
	case offsetof(struct extfuse_req, in.h.nodeid):
	case offsetof(struct extfuse_req, in.h.unique):
	case offsetof(struct extfuse_req, coherence.unique):
		return size == sizeof(__u64);
	case offsetof(struct extfuse_req, coherence.phase):
	case offsetof(struct extfuse_req, coherence.target_count):
		return size == sizeof(__u16);
	default:
		break;
	}

	for (i = 0; i < EXTFUSE_COHERENCE_MAX_TARGETS; i++) {
		const int base = offsetof(struct extfuse_req,
					  coherence.targets) +
			i * sizeof(struct extfuse_coherence_target);

		switch (off - base) {
		case offsetof(struct extfuse_coherence_target, nodeid):
		case offsetof(struct extfuse_coherence_target, incarnation):
		case offsetof(struct extfuse_coherence_target, attr_epoch):
		case offsetof(struct extfuse_coherence_target, xattr_epoch):
		case offsetof(struct extfuse_coherence_target, data_epoch):
		case offsetof(struct extfuse_coherence_target,
			      namespace_epoch):
			return size == sizeof(__u64);
		case offsetof(struct extfuse_coherence_target, dependencies):
		case offsetof(struct extfuse_coherence_target, active):
			return size == sizeof(__u32);
		default:
			break;
		}
	}
	return false;
}

const struct bpf_verifier_ops extfuse_verifier_ops = {
	.get_func_proto		= bpf_extfuse_func_proto,
	.is_valid_access	= bpf_extfuse_is_valid_access,
};

const struct bpf_prog_ops extfuse_prog_ops = {
};
