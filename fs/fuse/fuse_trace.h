/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM fuse

#if !defined(_TRACE_FUSE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_FUSE_H

#include <linux/tracepoint.h>

#define OPCODES							\
	EM( FUSE_LOOKUP,		"FUSE_LOOKUP")		\
	EM( FUSE_FORGET,		"FUSE_FORGET")		\
	EM( FUSE_GETATTR,		"FUSE_GETATTR")		\
	EM( FUSE_SETATTR,		"FUSE_SETATTR")		\
	EM( FUSE_READLINK,		"FUSE_READLINK")	\
	EM( FUSE_SYMLINK,		"FUSE_SYMLINK")		\
	EM( FUSE_MKNOD,			"FUSE_MKNOD")		\
	EM( FUSE_MKDIR,			"FUSE_MKDIR")		\
	EM( FUSE_UNLINK,		"FUSE_UNLINK")		\
	EM( FUSE_RMDIR,			"FUSE_RMDIR")		\
	EM( FUSE_RENAME,		"FUSE_RENAME")		\
	EM( FUSE_LINK,			"FUSE_LINK")		\
	EM( FUSE_OPEN,			"FUSE_OPEN")		\
	EM( FUSE_READ,			"FUSE_READ")		\
	EM( FUSE_WRITE,			"FUSE_WRITE")		\
	EM( FUSE_STATFS,		"FUSE_STATFS")		\
	EM( FUSE_RELEASE,		"FUSE_RELEASE")		\
	EM( FUSE_FSYNC,			"FUSE_FSYNC")		\
	EM( FUSE_SETXATTR,		"FUSE_SETXATTR")	\
	EM( FUSE_GETXATTR,		"FUSE_GETXATTR")	\
	EM( FUSE_LISTXATTR,		"FUSE_LISTXATTR")	\
	EM( FUSE_REMOVEXATTR,		"FUSE_REMOVEXATTR")	\
	EM( FUSE_FLUSH,			"FUSE_FLUSH")		\
	EM( FUSE_INIT,			"FUSE_INIT")		\
	EM( FUSE_OPENDIR,		"FUSE_OPENDIR")		\
	EM( FUSE_READDIR,		"FUSE_READDIR")		\
	EM( FUSE_RELEASEDIR,		"FUSE_RELEASEDIR")	\
	EM( FUSE_FSYNCDIR,		"FUSE_FSYNCDIR")	\
	EM( FUSE_GETLK,			"FUSE_GETLK")		\
	EM( FUSE_SETLK,			"FUSE_SETLK")		\
	EM( FUSE_SETLKW,		"FUSE_SETLKW")		\
	EM( FUSE_ACCESS,		"FUSE_ACCESS")		\
	EM( FUSE_CREATE,		"FUSE_CREATE")		\
	EM( FUSE_INTERRUPT,		"FUSE_INTERRUPT")	\
	EM( FUSE_BMAP,			"FUSE_BMAP")		\
	EM( FUSE_DESTROY,		"FUSE_DESTROY")		\
	EM( FUSE_IOCTL,			"FUSE_IOCTL")		\
	EM( FUSE_POLL,			"FUSE_POLL")		\
	EM( FUSE_NOTIFY_REPLY,		"FUSE_NOTIFY_REPLY")	\
	EM( FUSE_BATCH_FORGET,		"FUSE_BATCH_FORGET")	\
	EM( FUSE_FALLOCATE,		"FUSE_FALLOCATE")	\
	EM( FUSE_READDIRPLUS,		"FUSE_READDIRPLUS")	\
	EM( FUSE_RENAME2,		"FUSE_RENAME2")		\
	EM( FUSE_LSEEK,			"FUSE_LSEEK")		\
	EM( FUSE_COPY_FILE_RANGE,	"FUSE_COPY_FILE_RANGE")	\
	EM( FUSE_SETUPMAPPING,		"FUSE_SETUPMAPPING")	\
	EM( FUSE_REMOVEMAPPING,		"FUSE_REMOVEMAPPING")	\
	EM( FUSE_SYNCFS,		"FUSE_SYNCFS")		\
	EM( FUSE_TMPFILE,		"FUSE_TMPFILE")		\
	EM( FUSE_STATX,			"FUSE_STATX")		\
	EM(FUSE_COPY_FILE_RANGE_64,	"FUSE_COPY_FILE_RANGE_64") \
	EMe(CUSE_INIT,			"CUSE_INIT")

/*
 * This will turn the above table into TRACE_DEFINE_ENUM() for each of the
 * entries.
 */
#undef EM
#undef EMe
#define EM(a, b)	TRACE_DEFINE_ENUM(a);
#define EMe(a, b)	TRACE_DEFINE_ENUM(a);

OPCODES

/*
 * Stable request-count trace ABI.  Keep these numeric values append-only:
 * experiment consumers use this event instead of FUSE implementation
 * functions or private request state.  EXTFUSE_DECISION is emitted once after
 * routing; a WBCACHE action is followed by exactly one WBCACHE_TERMINAL.
 * WBCACHE_COMPLETE means that the lower path owns the result and the request
 * must not be replayed through the daemon, even when that result is an error.
 * DAEMON_DELIVERY is emitted only after a classic copy or io_uring userspace
 * publication succeeds; it does not claim that a userspace handler ran.
 * REQUEST_QUEUE records the pre-delivery queue boundary so cancellations and
 * delivery gaps remain diagnostic; DAEMON_DELIVERY is the canonical userspace
 * request count.  Both use this event's single histogram gate.
 * semantic_key packs version/stage/action/result_class into successive bytes
 * from most to least significant.  Keep the high-rate count event limited to
 * the four fields needed by an aggregate consumer.  Optional request detail,
 * including request identity, exact results and GETXATTR names, uses a
 * separately gated event.
 */
#ifndef FUSE_REQUEST_COUNT_ABI_VERSION
#define FUSE_REQUEST_COUNT_ABI_VERSION			2

#define FUSE_REQUEST_COUNT_STAGE_EXTFUSE_DECISION	1
#define FUSE_REQUEST_COUNT_STAGE_WBCACHE_TERMINAL	2
/* Stage 3 stays unused: per-command transport counting is intentionally off. */
#define FUSE_REQUEST_COUNT_STAGE_DAEMON_DELIVERY	4
#define FUSE_REQUEST_COUNT_STAGE_REQUEST_QUEUE		5

#define FUSE_REQUEST_COUNT_ACTION_EXTFUSE_COMPLETE	1
#define FUSE_REQUEST_COUNT_ACTION_EXTFUSE_DAEMON		2
#define FUSE_REQUEST_COUNT_ACTION_EXTFUSE_WBCACHE	3
#define FUSE_REQUEST_COUNT_ACTION_EXTFUSE_ERROR		4
#define FUSE_REQUEST_COUNT_ACTION_WBCACHE_COMPLETE	5
#define FUSE_REQUEST_COUNT_ACTION_WBCACHE_FALLBACK	6
#define FUSE_REQUEST_COUNT_ACTION_WBCACHE_CANCEL		7
/* Action 8 is reserved with the unused per-command transport stage. */
#define FUSE_REQUEST_COUNT_ACTION_LOCAL_FALLBACK	9
#define FUSE_REQUEST_COUNT_ACTION_DAEMON_CLASSIC	10
#define FUSE_REQUEST_COUNT_ACTION_DAEMON_URING		11
#define FUSE_REQUEST_COUNT_ACTION_REQUEST_QUEUE		12

#define FUSE_REQUEST_COUNT_RESULT_NONE		0
#define FUSE_REQUEST_COUNT_RESULT_ZERO		1
#define FUSE_REQUEST_COUNT_RESULT_POSITIVE	2
#define FUSE_REQUEST_COUNT_RESULT_ENOSYS		3
#define FUSE_REQUEST_COUNT_RESULT_ENODATA	4
#define FUSE_REQUEST_COUNT_RESULT_ERANGE		5
#define FUSE_REQUEST_COUNT_RESULT_OTHER_ERROR	6

/*
 * tracefs histograms accept at most TRACING_MAP_KEYS_MAX fields (currently
 * three).  Pack the versioned event semantics into one append-only key so a
 * consumer can aggregate on (opcode, semantic_key) without losing validation
 * information.  Each component is an unsigned byte; zero remains reserved.
 */
#define FUSE_REQUEST_COUNT_SEMANTIC_KEY(stage, action, result_class) \
	(((u32)FUSE_REQUEST_COUNT_ABI_VERSION << 24) | \
	 ((u32)(stage) << 16) | ((u32)(action) << 8) | (u32)(result_class))

static __always_inline u32 fuse_request_count_result_class(s64 result)
{
	if (!result)
		return FUSE_REQUEST_COUNT_RESULT_ZERO;
	if (result > 0)
		return FUSE_REQUEST_COUNT_RESULT_POSITIVE;
	if (result == -ENOSYS)
		return FUSE_REQUEST_COUNT_RESULT_ENOSYS;
	if (result == -ENODATA)
		return FUSE_REQUEST_COUNT_RESULT_ENODATA;
	if (result == -ERANGE)
		return FUSE_REQUEST_COUNT_RESULT_ERANGE;
	return FUSE_REQUEST_COUNT_RESULT_OTHER_ERROR;
}
#endif

/* Now we redfine it with the table that __print_symbolic needs. */
#undef EM
#undef EMe
#define EM(a, b)	{a, b},
#define EMe(a, b)	{a, b}

TRACE_EVENT(fuse_request_send,
	TP_PROTO(const struct fuse_req *req),

	TP_ARGS(req),

	TP_STRUCT__entry(
		__field(dev_t,			connection)
		__field(uint64_t,		unique)
		__field(enum fuse_opcode,	opcode)
		__field(uint32_t,		len)
		__field(uint64_t,		nodeid)
		__field(uint32_t,		header_pid)
	),

	TP_fast_assign(
		__entry->connection	=	req->fm->fc->dev;
		__entry->unique		=	req->in.h.unique;
		__entry->opcode		=	req->in.h.opcode;
		__entry->len		=	req->in.h.len;
		__entry->nodeid		=	req->in.h.nodeid;
		__entry->header_pid	=	req->in.h.pid;
	),

	TP_printk("connection %u req %llu opcode %u (%s) len %u nodeid %llu header_pid %u",
		  __entry->connection, __entry->unique, __entry->opcode,
		  __print_symbolic(__entry->opcode, OPCODES), __entry->len,
		  __entry->nodeid, __entry->header_pid)
);

TRACE_EVENT(fuse_request_end,
	TP_PROTO(const struct fuse_req *req),

	TP_ARGS(req),

	TP_STRUCT__entry(
		__field(dev_t,		connection)
		__field(uint64_t,	unique)
		__field(uint32_t,	len)
		__field(int32_t,	error)
	),

	TP_fast_assign(
		__entry->connection	=	req->fm->fc->dev;
		__entry->unique		=	req->in.h.unique;
		__entry->len		=	req->out.h.len;
		__entry->error		=	req->out.h.error;
	),

	TP_printk("connection %u req %llu len %u error %d", __entry->connection,
		  __entry->unique, __entry->len, __entry->error)
);

TRACE_EVENT(fuse_extfuse_coherence,
	TP_PROTO(dev_t connection, u64 unique, u32 opcode, u64 nodeid,
		 u32 phase, u32 action, u32 reason, s32 error,
		 u32 dependencies),

	TP_ARGS(connection, unique, opcode, nodeid, phase, action, reason,
		error, dependencies),

	TP_STRUCT__entry(
		__field(dev_t,	connection)
		__field(u64,	unique)
		__field(u32,	opcode)
		__field(u64,	nodeid)
		__field(u32,	phase)
		__field(u32,	action)
		__field(u32,	reason)
		__field(s32,	error)
		__field(u32,	dependencies)
	),

	TP_fast_assign(
		__entry->connection = connection;
		__entry->unique = unique;
		__entry->opcode = opcode;
		__entry->nodeid = nodeid;
		__entry->phase = phase;
		__entry->action = action;
		__entry->reason = reason;
		__entry->error = error;
		__entry->dependencies = dependencies;
	),

	TP_printk("connection %u unique %llu opcode %u nodeid %llu phase %u action %u reason %u error %d dependencies %#x",
		  __entry->connection, __entry->unique, __entry->opcode,
		  __entry->nodeid, __entry->phase, __entry->action,
		  __entry->reason, __entry->error, __entry->dependencies)
);

TRACE_EVENT(fuse_request_count,
	TP_PROTO(dev_t connection, u32 opcode, u32 stage, u32 action,
		 u32 result_class),

	TP_ARGS(connection, opcode, stage, action, result_class),

	TP_STRUCT__entry(
		__field(u32,	version)
		__field(u32,	semantic_key)
		__field(dev_t,	connection)
		__field(u32,	opcode)
	),

	TP_fast_assign(
		__entry->version = FUSE_REQUEST_COUNT_ABI_VERSION;
		__entry->semantic_key = FUSE_REQUEST_COUNT_SEMANTIC_KEY(
			stage, action, result_class);
		__entry->connection = connection;
		__entry->opcode = opcode;
	),

	TP_printk("version %u semantic_key %#x connection %u opcode %u",
		  __entry->version, __entry->semantic_key,
		  __entry->connection, __entry->opcode)
);

TRACE_EVENT(fuse_request_detail,
	TP_PROTO(dev_t connection, u64 unique, u32 opcode, u64 nodeid,
		 u32 stage, u32 action, u32 result_class, s64 result,
		 u64 request_size, s64 payload_size, const char *name,
		 u32 name_len),

	TP_ARGS(connection, unique, opcode, nodeid, stage, action, result_class,
		result, request_size, payload_size, name, name_len),

	TP_STRUCT__entry(
		__field(u32,	version)
		__field(u32,	semantic_key)
		__field(dev_t,	connection)
		__field(u64,	unique)
		__field(u32,	opcode)
		__field(u64,	nodeid)
		__field(u32,	stage)
		__field(u32,	action)
		__field(u32,	result_class)
		__field(s64,	result)
		__field(u64,	request_size)
		__field(s64,	payload_size)
		__string_len(name, name, name_len)
	),

	TP_fast_assign(
		__entry->version = FUSE_REQUEST_COUNT_ABI_VERSION;
		__entry->semantic_key = FUSE_REQUEST_COUNT_SEMANTIC_KEY(
			stage, action, result_class);
		__entry->connection = connection;
		__entry->unique = unique;
		__entry->opcode = opcode;
		__entry->nodeid = nodeid;
		__entry->stage = stage;
		__entry->action = action;
		__entry->result_class = result_class;
		__entry->result = result;
		__entry->request_size = request_size;
		__entry->payload_size = payload_size;
		__assign_str(name);
	),

	TP_printk("version %u semantic_key %#x connection %u unique %llu opcode %u nodeid %llu stage %u action %u result_class %u result %lld request_size %llu payload_size %lld name \"%s\"",
		  __entry->version, __entry->semantic_key,
		  __entry->connection, __entry->unique,
		  __entry->opcode, __entry->nodeid, __entry->stage,
		  __entry->action, __entry->result_class, __entry->result,
		  __entry->request_size, __entry->payload_size,
		  __get_str(name))
);

/*
 * Marks inclusive kernel CPU work performed on behalf of one FUSE
 * connection.  Consumers keep a per-TID stack because FUSE callbacks may be
 * nested, including through another FUSE filesystem.
 */
TRACE_EVENT(fuse_cpu_scope,
	TP_PROTO(dev_t connection, bool enter),

	TP_ARGS(connection, enter),

	TP_STRUCT__entry(
		__field(dev_t,	connection)
		__field(bool,	enter)
	),

	TP_fast_assign(
		__entry->connection	=	connection;
		__entry->enter		=	enter;
	),

	TP_printk("connection %u enter %u", __entry->connection,
		  __entry->enter)
);

#endif /* _TRACE_FUSE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE fuse_trace
#include <trace/define_trace.h>
