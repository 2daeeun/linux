// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE: Filesystem in Userspace
 * Copyright (c) 2023-2024 DataDirect Networks.
 */

#include "fuse_i.h"
#include "fuse_cpu_scope.h"
#include "dev_uring_i.h"
#include "fuse_dev_i.h"
#include "fuse_trace.h"

#include <linux/bitmap.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/io_uring/cmd.h>
#include <linux/overflow.h>

static bool __read_mostly enable_uring;
module_param(enable_uring, bool, 0644);
MODULE_PARM_DESC(enable_uring,
		 "Enable userspace communication through io-uring");

#define FUSE_URING_IOV_SEGS 2 /* header and payload */
#define FUSE_URING_IOV_HEADERS 0
#define FUSE_URING_IOV_PAYLOAD 1

#define FUSE_URING_ADD_QUEUE_FLAGS	FUSE_URING_ZERO_COPY

static_assert(sizeof(struct fuse_uring_ent_in_out) == 32);
static_assert(sizeof(struct fuse_uring_cmd_req) == 40);

bool fuse_uring_enabled(void)
{
	return enable_uring;
}

bool fuse_uring_zero_copy_ready(struct fuse_conn *fc)
{
	struct fuse_ring *ring;
	unsigned int qid;

	/* Pairs with smp_store_release() in fuse_uring_create(). */
	ring = smp_load_acquire(&fc->ring);
	if (!ring)
		return false;
	/* Pairs with smp_store_release() in fuse_uring_do_register(). */
	if (!smp_load_acquire(&ring->ready))
		return false;

	for (qid = 0; qid < ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue = READ_ONCE(ring->queues[qid]);
		struct fuse_bufpool *pool;

		if (!queue || !READ_ONCE(queue->zero_copy) ||
		    READ_ONCE(queue->payload_mode) != FUSE_PAYLOAD_BUFPOOL)
			return false;
		pool = READ_ONCE(queue->bufpool);
		if (!pool || !READ_ONCE(pool->registered))
			return false;
	}

	return true;
}

struct fuse_uring_pdu {
	struct fuse_ring_ent *ent;
};

struct fuse_zero_copy_bvs {
	unsigned int nr_bvs;
	struct bio_vec bvs[];
};

static const struct fuse_iqueue_ops fuse_io_uring_ops;
static void fuse_uring_recycle_buffer(struct fuse_ring_ent *ent);

enum fuse_uring_header_type {
	/* struct fuse_in_header / struct fuse_out_header */
	FUSE_URING_HEADER_IN_OUT,
	/* per-opcode input header */
	FUSE_URING_HEADER_OP,
	/* struct fuse_uring_ent_in_out */
	FUSE_URING_HEADER_RING_ENT,
};

static inline bool bufpool_enabled(struct fuse_ring_queue *queue)
{
	return queue->payload_mode == FUSE_PAYLOAD_BUFPOOL;
}

static inline bool bufpool_registered(struct fuse_ring_queue *queue)
{
	return queue->bufpool && queue->bufpool->registered;
}

/*
 * A registered buffer pool lives in sparse slot zero.  Every command that
 * imports a pool payload must therefore name that exact fixed-buffer slot.
 * This is called only from an io_uring command issue handler, while cmd->sqe
 * is valid.
 */
static inline bool fuse_uring_same_ctx(struct io_uring_cmd *cmd,
				       struct fuse_ring_queue *queue)
{
	return io_uring_cmd_ctx_handle(cmd) == READ_ONCE(queue->uring_ctx);
}

static inline bool fuse_uring_cmd_index_ok(struct io_uring_cmd *cmd,
					   struct fuse_ring_queue *queue)
{
	if (!fuse_uring_same_ctx(cmd, queue))
		return false;
	if (!bufpool_registered(queue))
		return true;

	return (cmd->flags & IORING_URING_CMD_FIXED) &&
	       READ_ONCE(cmd->sqe->buf_index) == queue->bufpool->registered_index;
}

static void uring_cmd_set_ring_ent(struct io_uring_cmd *cmd,
				   struct fuse_ring_ent *ring_ent)
{
	struct fuse_uring_pdu *pdu =
		io_uring_cmd_to_pdu(cmd, struct fuse_uring_pdu);

	pdu->ent = ring_ent;
}

static struct fuse_ring_ent *uring_cmd_to_ring_ent(struct io_uring_cmd *cmd)
{
	struct fuse_uring_pdu *pdu =
		io_uring_cmd_to_pdu(cmd, struct fuse_uring_pdu);

	return pdu->ent;
}

static void fuse_uring_flush_bg(struct fuse_ring_queue *queue)
{
	struct fuse_ring *ring = queue->ring;
	struct fuse_conn *fc = ring->fc;

	lockdep_assert_held(&queue->lock);
	lockdep_assert_held(&fc->bg_lock);

	/*
	 * Allow one bg request per queue, ignoring global fc limits.
	 * This prevents a single queue from consuming all resources and
	 * eliminates the need for remote queue wake-ups when global
	 * limits are met but this queue has no more waiting requests.
	 */
	while ((fc->active_background < fc->max_background ||
		!queue->active_background) &&
	       (!list_empty(&queue->fuse_req_bg_queue))) {
		struct fuse_req *req;

		req = list_first_entry(&queue->fuse_req_bg_queue,
				       struct fuse_req, list);
		fc->active_background++;
		queue->active_background++;

		list_move_tail(&req->list, &queue->fuse_req_queue);
	}
}

static bool can_zero_copy_req(struct fuse_ring_ent *ent, struct fuse_req *req)
{
	struct fuse_args *args = req->args;

	if (!ent->queue->zero_copy || !args->zero_copy)
		return false;

	if (args->opcode == FUSE_READ)
		return args->out_pages && !args->in_pages;
	if (args->opcode == FUSE_WRITE)
		return args->in_pages && !args->out_pages;

	return false;
}

static void zero_copy_unregister(struct io_uring_cmd *cmd,
				 struct fuse_ring_ent *ent,
				 unsigned int issue_flags)
{
	int err;

	if (!ent->zero_copied)
		return;
	if (WARN_ON_ONCE(!cmd))
		return;

	err = io_buffer_unregister_bvec(cmd, ent->zero_copy_index, issue_flags);
	if (err)
		pr_warn_ratelimited("qid=%d zero-copy unregister failed: %d\n",
				    ent->queue->qid, err);
	ent->zero_copied = false;
}

static void fuse_uring_req_end(struct fuse_ring_ent *ent, struct fuse_req *req,
			       int error, unsigned int issue_flags)
{
	struct fuse_ring_queue *queue = ent->queue;
	struct fuse_ring *ring = queue->ring;
	struct fuse_conn *fc = ring->fc;

	lockdep_assert_not_held(&queue->lock);
	spin_lock(&queue->lock);
	ent->fuse_req = NULL;
	list_del_init(&req->list);
	if (test_bit(FR_BACKGROUND, &req->flags)) {
		queue->active_background--;
		spin_lock(&fc->bg_lock);
		fuse_request_bg_finish(fc, req);
		fuse_uring_flush_bg(queue);
		spin_unlock(&fc->bg_lock);
	}

	spin_unlock(&queue->lock);

	zero_copy_unregister(ent->cmd, ent, issue_flags);

	if (error)
		req->out.h.error = error;

	clear_bit(FR_SENT, &req->flags);
	fuse_request_end(req);
}

/* Abort all list queued request on the given ring queue */
static void fuse_uring_abort_end_queue_requests(struct fuse_ring_queue *queue)
{
	struct fuse_req *req;
	LIST_HEAD(req_list);

	spin_lock(&queue->lock);
	list_for_each_entry(req, &queue->fuse_req_queue, list)
		clear_bit(FR_PENDING, &req->flags);
	list_splice_init(&queue->fuse_req_queue, &req_list);
	spin_unlock(&queue->lock);

	/* must not hold queue lock to avoid order issues with fi->lock */
	fuse_dev_end_requests(&req_list);
}

void fuse_uring_abort_end_requests(struct fuse_ring *ring)
{
	int qid;
	struct fuse_ring_queue *queue;
	struct fuse_conn *fc = ring->fc;

	for (qid = 0; qid < ring->nr_queues; qid++) {
		queue = READ_ONCE(ring->queues[qid]);
		if (!queue)
			continue;

		WARN_ON_ONCE(ring->fc->max_background != UINT_MAX);
		spin_lock(&queue->lock);
		queue->stopped = true;
		spin_lock(&fc->bg_lock);
		fuse_uring_flush_bg(queue);
		spin_unlock(&fc->bg_lock);
		spin_unlock(&queue->lock);
		fuse_uring_abort_end_queue_requests(queue);
	}
}

static bool ent_list_request_expired(struct fuse_conn *fc, struct list_head *list)
{
	struct fuse_ring_ent *ent;
	struct fuse_req *req;

	ent = list_first_entry_or_null(list, struct fuse_ring_ent, list);
	if (!ent)
		return false;

	req = ent->fuse_req;

	return time_is_before_jiffies(req->create_time +
				      fc->timeout.req_timeout);
}

bool fuse_uring_request_expired(struct fuse_conn *fc)
{
	struct fuse_ring *ring = fc->ring;
	struct fuse_ring_queue *queue;
	int qid;

	if (!ring)
		return false;

	for (qid = 0; qid < ring->nr_queues; qid++) {
		queue = READ_ONCE(ring->queues[qid]);
		if (!queue)
			continue;

		spin_lock(&queue->lock);
		if (fuse_request_expired(fc, &queue->fuse_req_queue) ||
		    fuse_request_expired(fc, &queue->fuse_req_bg_queue) ||
		    ent_list_request_expired(fc, &queue->ent_w_req_queue) ||
		    ent_list_request_expired(fc, &queue->ent_in_userspace)) {
			spin_unlock(&queue->lock);
			return true;
		}
		spin_unlock(&queue->lock);
	}

	return false;
}

void fuse_uring_destruct(struct fuse_conn *fc)
{
	struct fuse_ring *ring = fc->ring;
	int qid;

	if (!ring)
		return;

	for (qid = 0; qid < ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue = READ_ONCE(ring->queues[qid]);
		struct fuse_ring_ent *ent, *next;

		if (!queue)
			continue;

		WARN_ON(!list_empty(&queue->ent_avail_queue));
		WARN_ON(!list_empty(&queue->ent_w_req_queue));
		WARN_ON(!list_empty(&queue->ent_commit_queue));
		WARN_ON(!list_empty(&queue->ent_in_userspace));

		list_for_each_entry_safe(ent, next, &queue->ent_released,
					 list) {
			list_del_init(&ent->list);
			kfree(ent);
		}

		kfree(queue->fpq.processing);
		kfree(queue->bufpool);
		kfree(queue);
		WRITE_ONCE(ring->queues[qid], NULL);
	}

	kfree(ring->queues);
	kfree(ring);
	fc->ring = NULL;
}

/*
 * Basic ring setup for this connection based on the provided configuration
 */
static struct fuse_ring *fuse_uring_create(struct fuse_conn *fc)
{
	struct fuse_ring *ring;
	size_t nr_queues = num_possible_cpus();
	struct fuse_ring *res = NULL;
	size_t max_payload_size;

	ring = kzalloc(sizeof(*fc->ring), GFP_KERNEL_ACCOUNT);
	if (!ring)
		return NULL;

	ring->queues = kcalloc(nr_queues, sizeof(struct fuse_ring_queue *),
			       GFP_KERNEL_ACCOUNT);
	if (!ring->queues)
		goto out_err;

	max_payload_size = max(FUSE_MIN_READ_BUFFER, fc->max_write);
	max_payload_size = max(max_payload_size, fc->max_pages * PAGE_SIZE);

	spin_lock(&fc->lock);
	if (!fc->connected) {
		spin_unlock(&fc->lock);
		goto out_err;
	}
	if (fc->ring) {
		/* race, another thread created the ring in the meantime */
		spin_unlock(&fc->lock);
		res = fc->ring;
		goto out_err;
	}

	init_waitqueue_head(&ring->stop_waitq);
	atomic_set(&ring->bg_queue_seq, 0);

	ring->nr_queues = nr_queues;
	ring->fc = fc;
	ring->max_payload_sz = max_payload_size;
	smp_store_release(&fc->ring, ring);

	spin_unlock(&fc->lock);
	return ring;

out_err:
	kfree(ring->queues);
	kfree(ring);
	return res;
}

static struct fuse_ring_queue *
fuse_uring_create_queue(struct fuse_ring *ring, int qid, bool zero_copy,
			bool fail_if_exists, void *uring_ctx)
{
	struct fuse_conn *fc = ring->fc;
	struct fuse_ring_queue *queue;
	struct list_head *pq;

	queue = kzalloc(sizeof(*queue), GFP_KERNEL_ACCOUNT);
	if (!queue)
		return ERR_PTR(-ENOMEM);
	pq = kcalloc(FUSE_PQ_HASH_SIZE, sizeof(struct list_head), GFP_KERNEL);
	if (!pq) {
		kfree(queue);
		return ERR_PTR(-ENOMEM);
	}

	queue->qid = qid;
	queue->ring = ring;
	queue->uring_ctx = uring_ctx;
	spin_lock_init(&queue->lock);
	queue->zero_copy = zero_copy;

	INIT_LIST_HEAD(&queue->ent_avail_queue);
	INIT_LIST_HEAD(&queue->ent_commit_queue);
	INIT_LIST_HEAD(&queue->ent_w_req_queue);
	INIT_LIST_HEAD(&queue->ent_in_userspace);
	INIT_LIST_HEAD(&queue->fuse_req_queue);
	INIT_LIST_HEAD(&queue->fuse_req_bg_queue);
	INIT_LIST_HEAD(&queue->ent_released);

	queue->fpq.processing = pq;
	fuse_pqueue_init(&queue->fpq);

	spin_lock(&fc->lock);
	if (ring->queues[qid]) {
		spin_unlock(&fc->lock);
		kfree(queue->fpq.processing);
		kfree(queue);
		return fail_if_exists ? ERR_PTR(-EEXIST) :
			READ_ONCE(ring->queues[qid]);
	}

	/*
	 * fc->lock serializes creators.  The release store publishes every
	 * initialized queue field to lockless readers.
	 */
	/* Pairs with smp_load_acquire() readers of ring->queues[]. */
	smp_store_release(&ring->queues[qid], queue);
	spin_unlock(&fc->lock);

	return queue;
}

static void fuse_uring_stop_fuse_req_end(struct fuse_req *req)
{
	clear_bit(FR_SENT, &req->flags);
	req->out.h.error = -ECONNABORTED;
	fuse_request_end(req);
}

/*
 * Release a request/entry on connection tear down
 */
static void fuse_uring_entry_teardown(struct fuse_ring_ent *ent)
{
	struct fuse_req *req;
	struct io_uring_cmd *cmd;

	struct fuse_ring_queue *queue = ent->queue;

	spin_lock(&queue->lock);
	cmd = ent->cmd;
	ent->cmd = NULL;
	req = ent->fuse_req;
	ent->fuse_req = NULL;
	if (req) {
		/* remove entry from queue->fpq->processing */
		list_del_init(&req->list);
	}

	/*
	 * The entry must not be freed immediately, due to access of direct
	 * pointer access of entries through IO_URING_F_CANCEL - there is a risk
	 * of race between daemon termination (which triggers IO_URING_F_CANCEL
	 * and accesses entries without checking the list state first
	 */
	list_move(&ent->list, &queue->ent_released);
	ent->state = FRRS_RELEASED;
	spin_unlock(&queue->lock);

	if (cmd)
		io_uring_cmd_done(cmd, -ENOTCONN, IO_URING_F_UNLOCKED);

	if (req)
		fuse_uring_stop_fuse_req_end(req);
}

static void fuse_uring_stop_list_entries(struct list_head *head,
					 struct fuse_ring_queue *queue,
					 enum fuse_ring_req_state exp_state)
{
	struct fuse_ring *ring = queue->ring;
	struct fuse_ring_ent *ent, *next;
	ssize_t queue_refs = SSIZE_MAX;
	LIST_HEAD(to_teardown);

	spin_lock(&queue->lock);
	list_for_each_entry_safe(ent, next, head, list) {
		if (ent->state != exp_state) {
			pr_warn("entry teardown qid=%d state=%d expected=%d",
				queue->qid, ent->state, exp_state);
			continue;
		}

		ent->state = FRRS_TEARDOWN;
		list_move(&ent->list, &to_teardown);
	}
	spin_unlock(&queue->lock);

	/* no queue lock to avoid lock order issues */
	list_for_each_entry_safe(ent, next, &to_teardown, list) {
		fuse_uring_entry_teardown(ent);
		queue_refs = atomic_dec_return(&ring->queue_refs);
		WARN_ON_ONCE(queue_refs < 0);
	}
}

static void fuse_uring_teardown_entries(struct fuse_ring_queue *queue)
{
	fuse_uring_stop_list_entries(&queue->ent_in_userspace, queue,
				     FRRS_USERSPACE);
	fuse_uring_stop_list_entries(&queue->ent_avail_queue, queue,
				     FRRS_AVAILABLE);
}

/*
 * Log state debug info
 */
static void fuse_uring_log_ent_state(struct fuse_ring *ring)
{
	int qid;
	struct fuse_ring_ent *ent;

	for (qid = 0; qid < ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue = READ_ONCE(ring->queues[qid]);

		if (!queue)
			continue;

		spin_lock(&queue->lock);
		/*
		 * Log entries from the intermediate queue, the other queues
		 * should be empty
		 */
		list_for_each_entry(ent, &queue->ent_w_req_queue, list) {
			pr_info(" ent-req-queue ring=%p qid=%d ent=%p state=%d\n",
				ring, qid, ent, ent->state);
		}
		list_for_each_entry(ent, &queue->ent_commit_queue, list) {
			pr_info(" ent-commit-queue ring=%p qid=%d ent=%p state=%d\n",
				ring, qid, ent, ent->state);
		}
		spin_unlock(&queue->lock);
	}
	ring->stop_debug_log = 1;
}

static void fuse_uring_async_stop_queues(struct work_struct *work)
{
	int qid;
	struct fuse_ring *ring =
		container_of(work, struct fuse_ring, async_teardown_work.work);
	FUSE_CPU_SCOPE(ring->fc);

	/* XXX code dup */
	for (qid = 0; qid < ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue = READ_ONCE(ring->queues[qid]);

		if (!queue)
			continue;

		fuse_uring_teardown_entries(queue);
	}

	/*
	 * Some ring entries might be in the middle of IO operations,
	 * i.e. in process to get handled by file_operations::uring_cmd
	 * or on the way to userspace - we could handle that with conditions in
	 * run time code, but easier/cleaner to have an async tear down handler
	 * If there are still queue references left
	 */
	if (atomic_read(&ring->queue_refs) > 0) {
		if (time_after(jiffies,
			       ring->teardown_time + FUSE_URING_TEARDOWN_TIMEOUT))
			fuse_uring_log_ent_state(ring);

		schedule_delayed_work(&ring->async_teardown_work,
				      FUSE_URING_TEARDOWN_INTERVAL);
	} else {
		wake_up_all(&ring->stop_waitq);
		fuse_conn_put(ring->fc);
	}
}

/*
 * Stop the ring queues
 */
void fuse_uring_stop_queues(struct fuse_ring *ring)
{
	int qid;

	for (qid = 0; qid < ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue = READ_ONCE(ring->queues[qid]);

		if (!queue)
			continue;

		fuse_uring_teardown_entries(queue);
	}

	if (atomic_read(&ring->queue_refs) > 0) {
		fuse_conn_get(ring->fc);
		ring->teardown_time = jiffies;
		INIT_DELAYED_WORK(&ring->async_teardown_work,
				  fuse_uring_async_stop_queues);
		schedule_delayed_work(&ring->async_teardown_work,
				      FUSE_URING_TEARDOWN_INTERVAL);
	} else {
		wake_up_all(&ring->stop_waitq);
	}
}

/*
 * Handle IO_URING_F_CANCEL, typically should come on daemon termination.
 *
 * Releasing the last entry should trigger fuse_dev_release() if
 * the daemon was terminated
 */
static void fuse_uring_cancel(struct io_uring_cmd *cmd,
			      unsigned int issue_flags)
{
	struct fuse_ring_ent *ent = uring_cmd_to_ring_ent(cmd);
	struct fuse_ring_queue *queue;
	bool need_cmd_done = false;

	/*
	 * direct access on ent - it must not be destructed as long as
	 * IO_URING_F_CANCEL might come up
	 */
	queue = ent->queue;
	spin_lock(&queue->lock);
	if (ent->state == FRRS_AVAILABLE) {
		list_del_init(&ent->list);
		fuse_uring_recycle_buffer(ent);
		need_cmd_done = true;
		ent->cmd = NULL;
	}
	spin_unlock(&queue->lock);

	if (need_cmd_done) {
		/* no queue lock to avoid lock order issues */
		io_uring_cmd_done(cmd, -ENOTCONN, issue_flags);
		kfree(ent);
		if (atomic_dec_and_test(&queue->ring->queue_refs))
			wake_up_all(&queue->ring->stop_waitq);
	}
}

static void fuse_uring_prepare_cancel(struct io_uring_cmd *cmd, int issue_flags,
				      struct fuse_ring_ent *ring_ent)
{
	uring_cmd_set_ring_ent(cmd, ring_ent);
	io_uring_cmd_mark_cancelable(cmd, issue_flags);
}

/*
 * Checks for errors and stores it into the request
 */
static int fuse_uring_out_header_has_err(struct fuse_out_header *oh,
					 struct fuse_req *req,
					 bool *valid_reply)
{
	int err;

	*valid_reply = false;
	err = -EINVAL;
	if (oh->unique == 0) {
		/* Not supported through io-uring yet */
		pr_warn_once("notify through fuse-io-uring not supported\n");
		goto err;
	}

	if (oh->error <= -ERESTARTSYS || oh->error > 0)
		goto err;

	err = -ENOENT;
	if ((oh->unique & ~FUSE_INT_REQ_BIT) != req->in.h.unique) {
		pr_warn_ratelimited("unique mismatch, expected: %llu got %llu\n",
				    req->in.h.unique,
				    oh->unique & ~FUSE_INT_REQ_BIT);
		goto err;
	}

	/*
	 * Is it an interrupt reply ID?
	 * XXX: Not supported through fuse-io-uring yet, it should not even
	 *      find the request - should not happen.
	 */
	if (WARN_ON_ONCE(oh->unique & FUSE_INT_REQ_BIT))
		goto err;

	*valid_reply = true;
	err = oh->error;
err:
	return err;
}

static int ring_header_type_offset(enum fuse_uring_header_type type)
{
	switch (type) {
	case FUSE_URING_HEADER_IN_OUT:
		return 0;
	case FUSE_URING_HEADER_OP:
		return offsetof(struct fuse_uring_req_header, op_in);
	case FUSE_URING_HEADER_RING_ENT:
		return offsetof(struct fuse_uring_req_header, ring_ent_in_out);
	default:
		WARN_ONCE(1, "Invalid header type: %d\n", type);
		return -EINVAL;
	}
}

static int copy_header_to_ring(struct fuse_ring_ent *ent,
			       enum fuse_uring_header_type type,
			       const void *header, size_t header_size)
{
	int offset = ring_header_type_offset(type);
	void __user *ring;

	if (offset < 0)
		return offset;

	ring = (void __user *)ent->headers + offset;
	if (copy_to_user(ring, header, header_size)) {
		pr_info_ratelimited("Copying header to ring failed.\n");
		return -EFAULT;
	}

	return 0;
}

static int copy_header_from_ring(struct fuse_ring_ent *ent,
				 enum fuse_uring_header_type type, void *header,
				 size_t header_size)
{
	int offset = ring_header_type_offset(type);
	const void __user *ring;

	if (offset < 0)
		return offset;

	ring = (const void __user *)ent->headers + offset;
	if (copy_from_user(header, ring, header_size)) {
		pr_info_ratelimited("Copying header from ring failed.\n");
		return -EFAULT;
	}

	return 0;
}

static int fuse_uring_import_payload(struct fuse_ring_ent *ent, int dir,
				     struct iov_iter *iter,
				     unsigned int issue_flags)
{
	void __user *base = ent->payload.iov_base;
	size_t len = ent->payload.iov_len;
	int err;

	if (!base) {
		memset(iter, 0, sizeof(*iter));
		return 0;
	}

	if (bufpool_registered(ent->queue))
		err = io_uring_cmd_import_fixed((u64)(uintptr_t)base, len, dir,
						iter, ent->cmd, issue_flags);
	else
		err = import_ubuf(dir, base, len, iter);

	if (err)
		pr_info_ratelimited("fuse: Import of user buffer failed\n");

	return err;
}

static int setup_fuse_copy_state(struct fuse_copy_state *cs,
				 struct fuse_req *req,
				 struct fuse_ring_ent *ent, int dir,
				 struct iov_iter *iter,
				 unsigned int issue_flags)
{
	int err;

	err = fuse_uring_import_payload(ent, dir, iter, issue_flags);
	if (err)
		return err;

	fuse_copy_init(cs, dir == ITER_DEST, iter);
	cs->skip_folio_copy = ent->zero_copied;
	cs->is_uring = true;
	cs->req = req;
	return 0;
}

static int fuse_uring_copy_from_ring(struct fuse_req *req,
				     struct fuse_ring_ent *ent,
				     unsigned int payload_sz,
				     unsigned int issue_flags)
{
	struct fuse_copy_state cs;
	struct fuse_args *args = req->args;
	struct iov_iter iter;
	int err;

	err = setup_fuse_copy_state(&cs, req, ent, ITER_SOURCE, &iter,
				    issue_flags);
	if (err)
		return err;

	err = fuse_copy_out_args(&cs, args, payload_sz);
	fuse_copy_finish(&cs);
	return err;
}

static void fuse_zero_copy_release(void *priv)
{
	struct fuse_zero_copy_bvs *zc_bvs = priv;
	unsigned int i;

	for (i = 0; i < zc_bvs->nr_bvs; i++)
		folio_put(page_folio(zc_bvs->bvs[i].bv_page));

	kvfree(zc_bvs);
}

static int fuse_uring_set_up_zero_copy(struct fuse_ring_ent *ent,
				       struct fuse_req *req,
				       unsigned int issue_flags)
{
	struct fuse_args_pages *ap;
	struct fuse_zero_copy_bvs *zc_bvs;
	struct bio_vec *bvs;
	unsigned int i;
	size_t page_bytes = 0;
	size_t expected_bytes;
	size_t remaining_bytes;
	u8 ddir = 0;
	int err;

	if (!ent->zero_copy_index || ent->zero_copied)
		return -EINVAL;

	/* Reject malformed page layouts instead of silently copying them. */
	if (req->args->opcode == FUSE_READ) {
		if (req->args->in_numargs != 1 ||
		    req->args->out_numargs != 1 || !req->args->out_argvar)
			return -EINVAL;
		expected_bytes = req->args->out_args[0].size;
		ddir |= IO_BUF_DEST;
	} else if (req->args->opcode == FUSE_WRITE) {
		if (req->args->in_numargs != 2 ||
		    req->args->out_numargs != 1 || req->args->out_argvar)
			return -EINVAL;
		expected_bytes = req->args->in_args[1].size;
		ddir |= IO_BUF_SOURCE;
	} else {
		return -EINVAL;
	}
	if (!expected_bytes || expected_bytes > ent->queue->ring->max_payload_sz)
		return -EINVAL;

	ap = container_of(req->args, typeof(*ap), args);
	if (!ap->folios || !ap->descs || !ap->num_folios ||
	    ap->num_folios > ent->queue->ring->fc->max_pages)
		return -EINVAL;

	zc_bvs = kvmalloc(struct_size(zc_bvs, bvs, ap->num_folios),
			     GFP_KERNEL_ACCOUNT);
	if (!zc_bvs)
		return -ENOMEM;

	zc_bvs->nr_bvs = 0;
	bvs = zc_bvs->bvs;
	/*
	 * Writeback may crop the logical request at i_size while retaining the
	 * covering folio descriptors.  Validate every descriptor, but expose only
	 * the logical request prefix through the registered buffer.
	 */
	remaining_bytes = expected_bytes;
	for (i = 0; i < ap->num_folios; i++) {
		struct folio *folio = ap->folios[i];
		size_t folio_bytes;
		size_t length;

		if (!folio || !ap->descs[i].length) {
			err = -EINVAL;
			goto err_release;
		}
		folio_bytes = folio_size(folio);
		if (ap->descs[i].offset >= folio_bytes ||
		    ap->descs[i].length > folio_bytes - ap->descs[i].offset) {
			err = -EINVAL;
			goto err_release;
		}
		if (check_add_overflow(page_bytes,
				       (size_t)ap->descs[i].length, &page_bytes) ||
		    page_bytes > MAX_RW_COUNT) {
			err = -EOVERFLOW;
			goto err_release;
		}

		if (!remaining_bytes)
			continue;

		length = min_t(size_t, remaining_bytes, ap->descs[i].length);
		bvec_set_folio(&bvs[zc_bvs->nr_bvs], folio, length,
			       ap->descs[i].offset);
		folio_get(folio);
		zc_bvs->nr_bvs++;
		remaining_bytes -= length;
	}
	if (remaining_bytes) {
		err = -EINVAL;
		goto err_release;
	}

	err = io_buffer_register_bvec_array(ent->cmd, bvs, zc_bvs->nr_bvs,
					    fuse_zero_copy_release, zc_bvs,
					    ddir, ent->zero_copy_index,
					    issue_flags);
	if (err)
		goto err_release;

	ent->zero_copied = true;
	return 0;

err_release:
	fuse_zero_copy_release(zc_bvs);
	return err;
}

/*
 * Copy data from the req to the ring buffer
 */
static int fuse_uring_args_to_ring(struct fuse_req *req,
				   struct fuse_ring_ent *ent,
				   unsigned int issue_flags)
{
	struct fuse_copy_state cs;
	struct fuse_args *args = req->args;
	struct fuse_in_arg *in_args = args->in_args;
	int num_args = args->in_numargs;
	int err;
	struct iov_iter iter;
	struct fuse_uring_ent_in_out ent_in_out = {
		.flags = 0,
		.commit_id = req->in.h.unique,
	};

	if (can_zero_copy_req(ent, req)) {
		ent_in_out.flags |= FUSE_URING_ENT_ZERO_COPY;
		err = fuse_uring_set_up_zero_copy(ent, req, issue_flags);
		if (err)
			return err;
	}

	if (num_args > 0) {
		/*
		 * Expectation is that the first argument is the per op header.
		 * Some op code have that as zero size.
		 */
		if (args->in_args[0].size > 0) {
			err = copy_header_to_ring(ent, FUSE_URING_HEADER_OP,
						  in_args->value, in_args->size);
			if (err)
				return err;
		}
		in_args++;
		num_args--;
	}

	err = setup_fuse_copy_state(&cs, req, ent, ITER_DEST, &iter,
				    issue_flags);
	if (err)
		return err;

	/* copy the payload */
	err = fuse_copy_args(&cs, num_args, args->in_pages,
			     (struct fuse_arg *)in_args, 0);
	fuse_copy_finish(&cs);
	if (err) {
		pr_info_ratelimited("%s fuse_copy_args failed\n", __func__);
		return err;
	}

	ent_in_out.payload_sz = cs.ring.copied_sz;
	/*
	 * A zero-copy WRITE exposes its page argument through the registered
	 * entry slot, so it is absent from copied_sz but remains part of the
	 * logical request payload reported to the server.
	 */
	if (cs.skip_folio_copy && args->in_pages)
		ent_in_out.payload_sz +=
			args->in_args[args->in_numargs - 1].size;

	if (bufpool_enabled(ent->queue) && ent->payload.iov_base)
		ent_in_out.offset =
			(uintptr_t)ent->payload.iov_base -
			ent->queue->bufpool->base_uaddr;

	return copy_header_to_ring(ent, FUSE_URING_HEADER_RING_ENT,
				   &ent_in_out, sizeof(ent_in_out));
}

static int fuse_uring_copy_to_ring(struct fuse_ring_ent *ent,
				   struct fuse_req *req,
				   unsigned int issue_flags)
{
	struct fuse_ring_queue *queue = ent->queue;
	struct fuse_in_header in_header;
	int err;

	err = -EIO;
	if (WARN_ON(ent->state != FRRS_FUSE_REQ)) {
		pr_err("qid=%d ring-req=%p invalid state %d on send\n",
		       queue->qid, ent, ent->state);
		return err;
	}

	err = -EINVAL;
	if (WARN_ON(req->in.h.unique == 0))
		return err;

	/* copy the request */
	err = fuse_uring_args_to_ring(req, ent, issue_flags);
	if (unlikely(err)) {
		pr_info_ratelimited("Copy to ring failed: %d\n", err);
		return err;
	}

	/* Bounce the slab-resident header through the stack for usercopy. */
	in_header = req->in.h;
	return copy_header_to_ring(ent, FUSE_URING_HEADER_IN_OUT, &in_header,
				   sizeof(in_header));
}

static bool fuse_uring_req_has_copyable_payload(struct fuse_ring_ent *ent,
						struct fuse_req *req)
{
	struct fuse_args *args = req->args;

	if (!can_zero_copy_req(ent, req))
		return args->in_numargs > 1 || args->out_numargs;

	/*
	 * The per-op input header is copied separately.  Page arguments use the
	 * registered entry slot; any remaining arguments still need the pool.
	 */
	if (args->in_numargs > 1 &&
	    (!args->in_pages || args->in_numargs > 2))
		return true;
	if (args->out_numargs &&
	    (!args->out_pages || args->out_numargs > 1))
		return true;

	return false;
}

static int fuse_uring_select_buffer(struct fuse_ring_ent *ent)
{
	struct fuse_ring_queue *queue = ent->queue;
	struct fuse_bufpool *pool = queue->bufpool;
	unsigned int id;

	lockdep_assert_held(&queue->lock);

	id = find_first_bit(pool->free_map, pool->nr_bufs);
	if (id >= pool->nr_bufs)
		return -ENOBUFS;

	WARN_ON_ONCE(ent->payload.iov_base);
	__clear_bit(id, pool->free_map);
	ent->buf_id = id;
	ent->payload.iov_base =
		(void __user *)(pool->base_uaddr + id * pool->buf_size);
	ent->payload.iov_len = pool->buf_size;
	return 0;
}

static void fuse_uring_recycle_buffer(struct fuse_ring_ent *ent)
{
	struct fuse_ring_queue *queue = ent->queue;
	struct fuse_bufpool *pool;

	lockdep_assert_held(&queue->lock);

	if (!bufpool_enabled(queue) || !ent->payload.iov_base)
		return;

	pool = queue->bufpool;
	WARN_ON_ONCE(test_bit(ent->buf_id, pool->free_map));
	__set_bit(ent->buf_id, pool->free_map);
	memset(&ent->payload, 0, sizeof(ent->payload));
	ent->buf_id = 0;
}

static int fuse_uring_next_req_update_buffer(struct fuse_ring_ent *ent,
					     struct fuse_req *req)
{
	bool buffer_selected;
	bool has_payload;

	if (!bufpool_enabled(ent->queue))
		return 0;

	buffer_selected = !!ent->payload.iov_base;
	has_payload = fuse_uring_req_has_copyable_payload(ent, req);
	if (has_payload && !buffer_selected)
		return fuse_uring_select_buffer(ent);
	if (!has_payload && buffer_selected)
		fuse_uring_recycle_buffer(ent);

	return 0;
}

static int fuse_uring_prep_buffer(struct fuse_ring_ent *ent,
				  struct fuse_req *req)
{
	if (!bufpool_enabled(ent->queue) ||
	    !fuse_uring_req_has_copyable_payload(ent, req))
		return 0;

	return fuse_uring_select_buffer(ent);
}

static int fuse_uring_prepare_send(struct fuse_ring_ent *ent,
				   struct fuse_req *req,
				   unsigned int issue_flags)
{
	int err;

	err = fuse_uring_copy_to_ring(ent, req, issue_flags);
	if (!err) {
		set_bit(FR_SENT, &req->flags);
	} else {
		/*
		 * Copying the request failed. Remove the entry from the
		 * ent_w_req_queue list and terminate the request
		 */
		spin_lock(&ent->queue->lock);
		list_del_init(&ent->list);
		ent->state = FRRS_INVALID;
		spin_unlock(&ent->queue->lock);

		fuse_uring_req_end(ent, req, err, issue_flags);
	}

	return err;
}

/* Used to find the request on SQE commit */
static void fuse_uring_add_to_pq(struct fuse_ring_ent *ent)
{
	struct fuse_ring_queue *queue = ent->queue;
	struct fuse_pqueue *fpq = &queue->fpq;
	unsigned int hash;
	struct fuse_req *req = ent->fuse_req;

	req->ring_entry = ent;
	hash = fuse_req_hash(req->in.h.unique);
	list_move_tail(&req->list, &fpq->processing[hash]);
}

/*
 * Write data to the ring buffer and send the request to userspace,
 * userspace will read it
 * This is comparable with classical read(/dev/fuse)
 */
static int fuse_uring_send_next_to_ring(struct fuse_ring_ent *ent,
					struct fuse_req *req,
					unsigned int issue_flags)
{
	struct fuse_ring_queue *queue = ent->queue;
	int err;
	struct io_uring_cmd *cmd;

	err = fuse_uring_prepare_send(ent, req, issue_flags);
	if (err)
		return err;

	spin_lock(&queue->lock);
	cmd = ent->cmd;
	ent->cmd = NULL;
	ent->state = FRRS_USERSPACE;
	list_move_tail(&ent->list, &queue->ent_in_userspace);
	fuse_uring_add_to_pq(ent);
	spin_unlock(&queue->lock);

	io_uring_cmd_done(cmd, 0, issue_flags);
	return 0;
}

/*
 * Make a ring entry available for fuse_req assignment
 */
static void fuse_uring_ent_avail(struct fuse_ring_ent *ent,
				 struct fuse_ring_queue *queue)
{
	WARN_ON_ONCE(!ent->cmd);
	list_move(&ent->list, &queue->ent_avail_queue);
	ent->state = FRRS_AVAILABLE;
}

/*
 * Assign a fuse queue entry to the given entry
 */
static void fuse_uring_add_req_to_ring_ent(struct fuse_ring_ent *ent,
					   struct fuse_req *req)
{
	struct fuse_ring_queue *queue = ent->queue;

	lockdep_assert_held(&queue->lock);

	if (WARN_ON_ONCE(ent->state != FRRS_AVAILABLE &&
			 ent->state != FRRS_COMMIT)) {
		pr_warn("%s qid=%d state=%d\n", __func__, ent->queue->qid,
			ent->state);
	}

	clear_bit(FR_PENDING, &req->flags);

	/* Until fuse_uring_add_to_pq() the req is not attached to any list */
	list_del_init(&req->list);

	ent->fuse_req = req;
	ent->state = FRRS_FUSE_REQ;
	list_move_tail(&ent->list, &queue->ent_w_req_queue);
}

/* Fetch the next fuse request if available */
static struct fuse_req *fuse_uring_ent_assign_req(struct fuse_ring_ent *ent)
	__must_hold(&queue->lock)
{
	struct fuse_req *req;
	struct fuse_ring_queue *queue = ent->queue;
	struct list_head *req_queue = &queue->fuse_req_queue;

	lockdep_assert_held(&queue->lock);

	/* get and assign the next entry while it is still holding the lock */
	req = list_first_entry_or_null(req_queue, struct fuse_req, list);
	if (!req || fuse_uring_next_req_update_buffer(ent, req)) {
		fuse_uring_recycle_buffer(ent);
		return NULL;
	}

	fuse_uring_add_req_to_ring_ent(ent, req);
	return req;
}

/*
 * Read data from the ring buffer, which user space has written to
 * This is comparible with handling of classical write(/dev/fuse).
 * Also make the ring request available again for new fuse requests.
 */
static void fuse_uring_commit(struct fuse_ring_ent *ent, struct fuse_req *req,
			      unsigned int issue_flags)
{
	struct fuse_ring *ring = ent->queue->ring;
	struct fuse_uring_ent_in_out ring_in_out;
	struct fuse_out_header out_header;
	bool valid_reply;
	ssize_t err = -EFAULT;

	if (copy_header_from_ring(ent, FUSE_URING_HEADER_IN_OUT, &out_header,
				  sizeof(out_header)))
		goto out;
	req->out.h = out_header;
	if (copy_header_from_ring(ent, FUSE_URING_HEADER_RING_ENT,
				  &ring_in_out, sizeof(ring_in_out)))
		goto out;
	if (ring_in_out.payload_sz > ring->max_payload_sz ||
	    req->out.h.len < sizeof(req->out.h) ||
	    req->out.h.len - sizeof(req->out.h) != ring_in_out.payload_sz) {
		err = -EINVAL;
		goto out;
	}

	err = fuse_uring_out_header_has_err(&req->out.h, req, &valid_reply);
	if (err) {
		/* req->out.h.error already set */
		if (valid_reply && !ring_in_out.payload_sz)
			req->extfuse_reply_received = true;
		else if (valid_reply && req->args->out_arg_optional) {
			req->args->out_arg_optional_invalid = true;
			req->extfuse_reply_received = true;
		} else if (valid_reply) {
			err = -EINVAL;
		}
		goto out;
	}

	err = fuse_uring_copy_from_ring(req, ent, ring_in_out.payload_sz,
					 issue_flags);
	if (!err)
		req->extfuse_reply_received = true;
out:
	fuse_uring_req_end(ent, req, err, issue_flags);
}

/*
 * Get the next fuse req and send it
 */
static void fuse_uring_next_fuse_req(struct fuse_ring_ent *ent,
				     struct fuse_ring_queue *queue,
				     unsigned int issue_flags)
{
	int err;
	struct fuse_req *req;

retry:
	spin_lock(&queue->lock);
	fuse_uring_ent_avail(ent, queue);
	req = fuse_uring_ent_assign_req(ent);
	spin_unlock(&queue->lock);

	if (req) {
		err = fuse_uring_send_next_to_ring(ent, req, issue_flags);
		if (err)
			goto retry;
	}
}

static int fuse_ring_ent_set_commit(struct fuse_ring_ent *ent)
{
	struct fuse_ring_queue *queue = ent->queue;

	lockdep_assert_held(&queue->lock);

	if (WARN_ON_ONCE(ent->state != FRRS_USERSPACE))
		return -EIO;

	ent->state = FRRS_COMMIT;
	list_move(&ent->list, &queue->ent_commit_queue);

	return 0;
}

/* FUSE_URING_CMD_COMMIT_AND_FETCH handler */
static int fuse_uring_commit_fetch(struct io_uring_cmd *cmd, int issue_flags,
				   struct fuse_conn *fc)
{
	const struct fuse_uring_cmd_req *cmd_req =
		io_uring_sqe128_cmd(cmd->sqe, struct fuse_uring_cmd_req);
	struct fuse_ring_ent *ent;
	int err;
	struct fuse_ring *ring = fc->ring;
	struct fuse_ring_queue *queue;
	uint64_t commit_id = READ_ONCE(cmd_req->commit_id);
	unsigned int qid = READ_ONCE(cmd_req->qid);
	struct fuse_pqueue *fpq;
	struct fuse_req *req;

	err = -ENOTCONN;
	if (!ring)
		return err;

	if (qid >= ring->nr_queues)
		return -EINVAL;

	/* Pairs with smp_store_release() in fuse_uring_create_queue(). */
	queue = smp_load_acquire(&ring->queues[qid]);
	if (!queue)
		return err;
	fpq = &queue->fpq;

	if (!READ_ONCE(fc->connected))
		return err;

	spin_lock(&queue->lock);
	if (unlikely(queue->stopped)) {
		spin_unlock(&queue->lock);
		return err;
	}
	if (!fuse_uring_cmd_index_ok(cmd, queue)) {
		spin_unlock(&queue->lock);
		return -EINVAL;
	}

	/* Find a request based on the unique ID of the fuse request
	 * This should get revised, as it needs a hash calculation and list
	 * search. And full struct fuse_pqueue is needed (memory overhead).
	 * As well as the link from req to ring_ent.
	 */
	req = fuse_request_find(fpq, commit_id);
	err = -ENOENT;
	if (!req) {
		pr_info("qid=%d commit_id %llu not found\n", queue->qid,
			commit_id);
		spin_unlock(&queue->lock);
		return err;
	}
	list_del_init(&req->list);
	ent = req->ring_entry;
	req->ring_entry = NULL;

	err = fuse_ring_ent_set_commit(ent);
	if (err != 0) {
		pr_info_ratelimited("qid=%d commit_id %llu state %d",
				    queue->qid, commit_id, ent->state);
		fuse_uring_recycle_buffer(ent);
		spin_unlock(&queue->lock);
		/* ent->cmd is NULL here, so use the incoming command directly. */
		zero_copy_unregister(cmd, ent, issue_flags);
		fuse_uring_req_end(ent, req, err, issue_flags);
		return err;
	}

	ent->cmd = cmd;
	spin_unlock(&queue->lock);

	/* without the queue lock, as other locks are taken */
	fuse_uring_prepare_cancel(cmd, issue_flags, ent);
	fuse_uring_commit(ent, req, issue_flags);

	/*
	 * Fetching the next request is absolutely required as queued
	 * fuse requests would otherwise not get processed - committing
	 * and fetching is done in one step vs legacy fuse, which has separated
	 * read (fetch request) and write (commit result).
	 */
	fuse_uring_next_fuse_req(ent, queue, issue_flags);
	return 0;
}

static bool is_ring_ready(struct fuse_ring *ring, int current_qid)
{
	int qid;
	struct fuse_ring_queue *queue;
	bool ready = true;

	for (qid = 0; qid < ring->nr_queues && ready; qid++) {
		if (current_qid == qid)
			continue;

		queue = READ_ONCE(ring->queues[qid]);
		if (!queue) {
			ready = false;
			break;
		}

		spin_lock(&queue->lock);
		if (list_empty(&queue->ent_avail_queue))
			ready = false;
		spin_unlock(&queue->lock);
	}

	return ready;
}

/*
 * fuse_uring_req_fetch command handling
 */
static int fuse_uring_do_register(struct fuse_ring_ent *ent,
				  struct io_uring_cmd *cmd,
				  unsigned int issue_flags)
{
	struct fuse_ring_queue *queue = ent->queue;
	struct fuse_ring *ring = queue->ring;
	struct fuse_conn *fc = ring->fc;
	struct fuse_iqueue *fiq = &fc->iq;

	spin_lock(&fc->lock);
	/* abort teardown path is running or has run */
	if (!fc->connected) {
		spin_unlock(&fc->lock);
		if (atomic_dec_and_test(&ring->queue_refs))
			wake_up_all(&ring->stop_waitq);
		kfree(ent);
		return -ECONNABORTED;
	}
	spin_unlock(&fc->lock);

	fuse_uring_prepare_cancel(cmd, issue_flags, ent);

	spin_lock(&queue->lock);
	ent->cmd = cmd;
	fuse_uring_ent_avail(ent, queue);
	spin_unlock(&queue->lock);

	if (!READ_ONCE(ring->ready)) {
		bool ready = is_ring_ready(ring, queue->qid);

		if (ready) {
			WRITE_ONCE(fiq->ops, &fuse_io_uring_ops);
			smp_store_release(&ring->ready, true);
			wake_up_all(&fc->blocked_waitq);
		}
	}
	return 0;
}

/*
 * sqe->addr is a ptr to an iovec array, iov[0] has the headers, iov[1]
 * the payload
 */
static int fuse_uring_get_iovec_from_sqe(const struct io_uring_sqe *sqe,
					 struct iovec iov[FUSE_URING_IOV_SEGS])
{
	struct iovec __user *uiov = u64_to_user_ptr(READ_ONCE(sqe->addr));
	struct iov_iter iter;
	ssize_t ret;

	if (sqe->len != FUSE_URING_IOV_SEGS)
		return -EINVAL;

	/*
	 * Direction for buffer access will actually be READ and WRITE,
	 * using write for the import should include READ access as well.
	 */
	ret = import_iovec(WRITE, uiov, FUSE_URING_IOV_SEGS,
			   FUSE_URING_IOV_SEGS, &iov, &iter);
	if (ret < 0)
		return ret;

	return 0;
}

static struct fuse_ring_ent *
fuse_uring_create_ring_ent(struct io_uring_cmd *cmd,
			   struct fuse_ring_queue *queue)
{
	const struct fuse_uring_cmd_req *cmd_req =
		io_uring_sqe128_cmd(cmd->sqe, struct fuse_uring_cmd_req);
	struct fuse_ring *ring = queue->ring;
	struct fuse_ring_ent *ent;
	struct iovec iov[FUSE_URING_IOV_SEGS];
	struct iovec *headers, *payload;
	unsigned int zero_copy_index;
	int err;

	err = fuse_uring_get_iovec_from_sqe(cmd->sqe, iov);
	if (err) {
		pr_info_ratelimited("Failed to get iovec from sqe, err=%d\n",
				    err);
		return ERR_PTR(err);
	}

	zero_copy_index = READ_ONCE(cmd_req->ent_zero_copy_buf_index);
	if ((zero_copy_index && !queue->zero_copy) ||
	    (queue->zero_copy && !zero_copy_index))
		return ERR_PTR(-EINVAL);

	err = -EINVAL;
	headers = &iov[FUSE_URING_IOV_HEADERS];
	if (!headers->iov_base ||
	    headers->iov_len < sizeof(struct fuse_uring_req_header)) {
		pr_info_ratelimited("Invalid header len %zu\n",
				    headers->iov_len);
		return ERR_PTR(err);
	}

	payload = &iov[FUSE_URING_IOV_PAYLOAD];
	spin_lock(&queue->lock);
	if (bufpool_enabled(queue)) {
		if (payload->iov_base || payload->iov_len ||
		    !fuse_uring_cmd_index_ok(cmd, queue) ||
		    (queue->zero_copy && !bufpool_registered(queue))) {
			spin_unlock(&queue->lock);
			return ERR_PTR(err);
		}
	} else {
		if (payload->iov_len < ring->max_payload_sz) {
			spin_unlock(&queue->lock);
			pr_info_ratelimited("Invalid req payload len %zu\n",
					    payload->iov_len);
			return ERR_PTR(err);
		}
		if (queue->zero_copy) {
			spin_unlock(&queue->lock);
			pr_info_ratelimited(
				"Zero-copy queue requires a registered buffer pool\n");
			return ERR_PTR(err);
		}
		queue->payload_mode = FUSE_PAYLOAD_PER_ENT;
	}
	spin_unlock(&queue->lock);

	err = -ENOMEM;
	ent = kzalloc(sizeof(*ent), GFP_KERNEL_ACCOUNT);
	if (!ent)
		return ERR_PTR(err);

	INIT_LIST_HEAD(&ent->list);

	ent->queue = queue;
	ent->headers = headers->iov_base;
	if (queue->payload_mode == FUSE_PAYLOAD_PER_ENT)
		ent->payload = *payload;
	ent->zero_copy_index = zero_copy_index;

	atomic_inc(&ring->queue_refs);
	return ent;
}

/*
 * Register header and payload buffer with the kernel and puts the
 * entry as "ready to get fuse requests" on the queue
 */
static int fuse_uring_register(struct io_uring_cmd *cmd,
			       unsigned int issue_flags, struct fuse_conn *fc)
{
	const struct fuse_uring_cmd_req *cmd_req =
		io_uring_sqe128_cmd(cmd->sqe, struct fuse_uring_cmd_req);
	struct fuse_ring *ring = smp_load_acquire(&fc->ring);
	struct fuse_ring_queue *queue;
	struct fuse_ring_ent *ent;
	int err;
	unsigned int qid = READ_ONCE(cmd_req->qid);

	err = -ENOMEM;
	if (!ring) {
		ring = fuse_uring_create(fc);
		if (!ring)
			return err;
	}

	if (qid >= ring->nr_queues) {
		pr_info_ratelimited("fuse: Invalid ring qid %u\n", qid);
		return -EINVAL;
	}

	/* Pairs with smp_store_release() in fuse_uring_create_queue(). */
	queue = smp_load_acquire(&ring->queues[qid]);
	if (!queue) {
		queue = fuse_uring_create_queue(ring, qid, false, false,
						io_uring_cmd_ctx_handle(cmd));
		if (IS_ERR(queue))
			return PTR_ERR(queue);
	}
	if (!fuse_uring_same_ctx(cmd, queue))
		return -EXDEV;

	/*
	 * The created queue above does not need to be destructed in
	 * case of entry errors below, will be done at ring destruction time.
	 */

	ent = fuse_uring_create_ring_ent(cmd, queue);
	if (IS_ERR(ent))
		return PTR_ERR(ent);

	return fuse_uring_do_register(ent, cmd, issue_flags);
}

static int fuse_uring_add_queue(struct io_uring_cmd *cmd,
				struct fuse_conn *fc)
{
	const struct fuse_uring_cmd_req *cmd_req =
		io_uring_sqe128_cmd(cmd->sqe, struct fuse_uring_cmd_req);
	struct fuse_ring *ring;
	unsigned int qid = READ_ONCE(cmd_req->qid);
	u64 flags = READ_ONCE(cmd_req->flags);
	struct fuse_ring_queue *queue;
	bool zero_copy = flags & FUSE_URING_ZERO_COPY;

	/* Pairs with smp_store_release() in fuse_uring_create(). */
	ring = smp_load_acquire(&fc->ring);
	if (!READ_ONCE(fc->io_uring_bufpool))
		return -EOPNOTSUPP;

	if (!ring) {
		ring = fuse_uring_create(fc);
		if (!ring)
			return -ENOMEM;
	}
	if (qid >= ring->nr_queues) {
		pr_info_ratelimited("fuse: Invalid ring qid %u\n", qid);
		return -EINVAL;
	}
	if (flags & ~FUSE_URING_ADD_QUEUE_FLAGS)
		return -EINVAL;
	if (zero_copy && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	queue = fuse_uring_create_queue(ring, qid, zero_copy, true,
					io_uring_cmd_ctx_handle(cmd));
	return IS_ERR(queue) ? PTR_ERR(queue) : 0;
}

static int fuse_uring_add_bufpool(struct io_uring_cmd *cmd,
				  unsigned int issue_flags,
				  struct fuse_conn *fc)
{
	const struct fuse_uring_cmd_req *cmd_req =
		io_uring_sqe128_cmd(cmd->sqe, struct fuse_uring_cmd_req);
	struct fuse_ring *ring;
	unsigned int qid = READ_ONCE(cmd_req->qid);
	u64 flags = READ_ONCE(cmd_req->flags);
	struct fuse_ring_queue *queue;
	struct fuse_bufpool *pool;
	struct iov_iter iter;
	u64 pool_uaddr64, pool_end;
	uintptr_t pool_uaddr;
	unsigned int pool_len, nr_bufs;
	size_t pool_size, buf_size;
	bool registered = cmd->flags & IORING_URING_CMD_FIXED;
	unsigned int registered_index = READ_ONCE(cmd->sqe->buf_index);
	int err;

	/* Pairs with smp_store_release() in fuse_uring_create(). */
	ring = smp_load_acquire(&fc->ring);
	if (!READ_ONCE(fc->io_uring_bufpool))
		return -EOPNOTSUPP;
	if (!ring || qid >= ring->nr_queues || flags)
		return -EINVAL;
	if (READ_ONCE(cmd_req->bufpool.reserved))
		return -EINVAL;

	/* Pairs with smp_store_release() in fuse_uring_create_queue(). */
	queue = smp_load_acquire(&ring->queues[qid]);
	if (!queue)
		return -EINVAL;
	if (!fuse_uring_same_ctx(cmd, queue))
		return -EXDEV;

	pool_uaddr64 = READ_ONCE(cmd_req->bufpool.uaddr);
	pool_len = READ_ONCE(cmd_req->bufpool.len);
	pool_uaddr = (uintptr_t)pool_uaddr64;
	buf_size = ring->max_payload_sz;
	if (!pool_uaddr64 || (u64)pool_uaddr != pool_uaddr64 || !pool_len ||
	    !buf_size || buf_size > UINT_MAX || pool_len % buf_size ||
	    check_add_overflow(pool_uaddr64, (u64)pool_len, &pool_end) ||
	    pool_end <= pool_uaddr64)
		return -EINVAL;

	/* Slot zero is reserved for the queue pool in the sparse table. */
	if (registered_index || (queue->zero_copy && !registered))
		return -EINVAL;

	/* Validate that slot zero actually covers the advertised pool range. */
	if (registered) {
		err = io_uring_cmd_import_fixed(pool_uaddr64, pool_len, ITER_DEST,
						&iter, cmd, issue_flags);
		if (err)
			return err;
	}

	nr_bufs = pool_len / buf_size;
	if (!nr_bufs)
		return -EINVAL;
	pool_size = struct_size(pool, free_map, BITS_TO_LONGS(nr_bufs));
	if (pool_size == SIZE_MAX)
		return -EOVERFLOW;
	pool = kzalloc(pool_size, GFP_KERNEL_ACCOUNT);
	if (!pool)
		return -ENOMEM;

	pool->registered = registered;
	pool->registered_index = registered_index;
	pool->base_uaddr = pool_uaddr;
	pool->buf_size = buf_size;
	pool->nr_bufs = nr_bufs;
	bitmap_set(pool->free_map, 0, nr_bufs);

	spin_lock(&queue->lock);
	if (queue->payload_mode != FUSE_PAYLOAD_UNSET) {
		spin_unlock(&queue->lock);
		kfree(pool);
		return -EINVAL;
	}
	queue->bufpool = pool;
	queue->payload_mode = FUSE_PAYLOAD_BUFPOOL;
	spin_unlock(&queue->lock);
	return 0;
}

/*
 * Entry function from io_uring to handle the given passthrough command
 * (op code IORING_OP_URING_CMD)
 */
int fuse_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	struct fuse_dev *fud;
	struct fuse_conn *fc;
	u32 cmd_op = cmd->cmd_op;
	int err;

	if ((unlikely(issue_flags & IO_URING_F_CANCEL))) {
		fuse_uring_cancel(cmd, issue_flags);
		return 0;
	}

	/* This extra SQE size holds struct fuse_uring_cmd_req */
	if (!(issue_flags & IO_URING_F_SQE128))
		return -EINVAL;

	fud = fuse_get_dev(cmd->file);
	if (IS_ERR(fud)) {
		pr_info_ratelimited("No fuse device found\n");
		return PTR_ERR(fud);
	}
	fc = fud->fc;
	FUSE_CPU_SCOPE(fc);

	/* The ring is sized from values negotiated by FUSE_INIT. */
	if (!smp_load_acquire(&fc->initialized))
		return -EAGAIN;

	if (READ_ONCE(fc->aborted))
		return -ECONNABORTED;
	if (!READ_ONCE(fc->connected))
		return -ENOTCONN;

	/* Once a connection has io-uring enabled on it, it can't be disabled */
	if (!enable_uring && !fc->io_uring) {
		pr_info_ratelimited(
			"fuse-io-uring is disabled by module parameter\n");
		return -EOPNOTSUPP;
	}

	if (!READ_ONCE(fc->io_uring)) {
		pr_info_ratelimited(
			"fuse-io-uring not enabled on this connection\n");
		return -EOPNOTSUPP;
	}

	switch (cmd_op) {
	case FUSE_IO_URING_CMD_REGISTER:
		err = fuse_uring_register(cmd, issue_flags, fc);
		if (err) {
			pr_info_once("FUSE_IO_URING_CMD_REGISTER failed err=%d\n",
				     err);
			fc->io_uring = 0;
			fc->io_uring_bufpool = 0;
			wake_up_all(&fc->blocked_waitq);
			return err;
		}
		break;
	case FUSE_IO_URING_CMD_COMMIT_AND_FETCH:
		err = fuse_uring_commit_fetch(cmd, issue_flags, fc);
		if (err) {
			pr_info_once("FUSE_IO_URING_COMMIT_AND_FETCH failed err=%d\n",
				     err);
			return err;
		}
		break;
	case FUSE_IO_URING_CMD_ADD_QUEUE:
		err = fuse_uring_add_queue(cmd, fc);
		if (err)
			pr_info_once(
				"FUSE_IO_URING_CMD_ADD_QUEUE failed err=%d\n", err);
		return err;
	case FUSE_IO_URING_CMD_ADD_BUFPOOL:
		err = fuse_uring_add_bufpool(cmd, issue_flags, fc);
		if (err)
			pr_info_once(
				"FUSE_IO_URING_CMD_ADD_BUFPOOL failed err=%d\n",
				err);
		return err;
	default:
		return -EINVAL;
	}

	return -EIOCBQUEUED;
}

static void fuse_uring_send(struct fuse_ring_ent *ent, struct io_uring_cmd *cmd,
			    ssize_t ret, unsigned int issue_flags)
{
	struct fuse_ring_queue *queue = ent->queue;

	spin_lock(&queue->lock);
	ent->state = FRRS_USERSPACE;
	list_move_tail(&ent->list, &queue->ent_in_userspace);
	ent->cmd = NULL;
	fuse_uring_add_to_pq(ent);
	spin_unlock(&queue->lock);

	io_uring_cmd_done(cmd, ret, issue_flags);
}

/*
 * This prepares and sends the ring request in fuse-uring task context.
 * User buffers are not mapped yet - the application does not have permission
 * to write to it - this has to be executed in ring task context.
 */
static void fuse_uring_send_in_task(struct io_tw_req tw_req, io_tw_token_t tw)
{
	unsigned int issue_flags = IO_URING_CMD_TASK_WORK_ISSUE_FLAGS;
	struct io_uring_cmd *cmd = io_uring_cmd_from_tw(tw_req);
	struct fuse_ring_ent *ent = uring_cmd_to_ring_ent(cmd);
	struct fuse_ring_queue *queue = ent->queue;
	int err;
	FUSE_CPU_SCOPE(queue->ring->fc);

	if (!tw.cancel) {
		err = fuse_uring_prepare_send(ent, ent->fuse_req, issue_flags);
		if (err) {
			fuse_uring_next_fuse_req(ent, queue, issue_flags);
			return;
		}
		fuse_uring_send(ent, cmd, err, issue_flags);
	} else {
		err = -ECANCELED;

		spin_lock(&queue->lock);
		list_del_init(&ent->list);
		fuse_uring_recycle_buffer(ent);
		spin_unlock(&queue->lock);

		io_uring_cmd_done(cmd, err, issue_flags);

		fuse_uring_req_end(ent, ent->fuse_req, err, issue_flags);
		kfree(ent);
		if (atomic_dec_and_test(&queue->ring->queue_refs))
			wake_up_all(&queue->ring->stop_waitq);
	}
}

static struct fuse_ring_queue *fuse_uring_task_to_queue(struct fuse_ring *ring)
{
	unsigned int qid;
	struct fuse_ring_queue *queue;

	qid = task_cpu(current);

	if (WARN_ONCE(qid >= ring->nr_queues,
		      "Core number (%u) exceeds nr queues (%zu)\n", qid,
		      ring->nr_queues))
		qid = 0;

	queue = READ_ONCE(ring->queues[qid]);
	WARN_ONCE(!queue, "Missing queue for qid %d\n", qid);

	return queue;
}

static struct fuse_ring_queue *
fuse_uring_next_background_queue(struct fuse_ring *ring)
{
	unsigned int seq;

	/*
	 * A writeback worker can submit requests generated by many application
	 * tasks.  CPU-local selection would serialize all of those requests on
	 * one userspace ring queue, so spread background traffic across queues.
	 * Foreground requests continue to use fuse_uring_task_to_queue().
	 */
	seq = (unsigned int)atomic_fetch_inc_relaxed(&ring->bg_queue_seq);

	return READ_ONCE(ring->queues[seq % ring->nr_queues]);
}

static void fuse_uring_dispatch_ent(struct fuse_ring_ent *ent)
{
	struct io_uring_cmd *cmd = ent->cmd;

	uring_cmd_set_ring_ent(cmd, ent);
	io_uring_cmd_complete_in_task(cmd, fuse_uring_send_in_task);
}

/* queue a fuse request and send it if a ring entry is available */
void fuse_uring_queue_fuse_req(struct fuse_iqueue *fiq, struct fuse_req *req)
{
	struct fuse_conn *fc = req->fm->fc;
	struct fuse_ring *ring = fc->ring;
	struct fuse_ring_queue *queue;
	struct fuse_ring_ent *ent = NULL;
	int err;

	err = -EINVAL;
	queue = fuse_uring_task_to_queue(ring);
	if (!queue)
		goto err;

	fuse_request_assign_unique(fiq, req);

	spin_lock(&queue->lock);
	err = -ENOTCONN;
	if (unlikely(queue->stopped))
		goto err_unlock;

	set_bit(FR_URING, &req->flags);
	req->ring_queue = queue;
	ent = list_first_entry_or_null(&queue->ent_avail_queue,
				       struct fuse_ring_ent, list);
	if (!ent || fuse_uring_prep_buffer(ent, req)) {
		list_add_tail(&req->list, &queue->fuse_req_queue);
		spin_unlock(&queue->lock);
		return;
	}

	fuse_uring_add_req_to_ring_ent(ent, req);
	spin_unlock(&queue->lock);
	fuse_uring_dispatch_ent(ent);
	return;

err_unlock:
	spin_unlock(&queue->lock);
err:
	req->out.h.error = err;
	clear_bit(FR_PENDING, &req->flags);
	fuse_request_end(req);
}

bool fuse_uring_queue_bq_req(struct fuse_req *req)
{
	struct fuse_conn *fc = req->fm->fc;
	struct fuse_ring *ring = fc->ring;
	struct fuse_ring_queue *queue;
	struct fuse_ring_ent *ent = NULL;

	queue = fuse_uring_next_background_queue(ring);
	if (!queue)
		return false;

	spin_lock(&queue->lock);
	if (unlikely(queue->stopped)) {
		spin_unlock(&queue->lock);
		return false;
	}

	set_bit(FR_URING, &req->flags);
	req->ring_queue = queue;
	list_add_tail(&req->list, &queue->fuse_req_bg_queue);

	ent = list_first_entry_or_null(&queue->ent_avail_queue,
				       struct fuse_ring_ent, list);
	spin_lock(&fc->bg_lock);
	fc->num_background++;
	if (fc->num_background == fc->max_background)
		fc->blocked = 1;
	fuse_uring_flush_bg(queue);
	spin_unlock(&fc->bg_lock);

	/*
	 * Due to bg_queue flush limits there might be other bg requests
	 * in the queue that need to be handled first. Or no further req
	 * might be available.
	 */
	req = list_first_entry_or_null(&queue->fuse_req_queue, struct fuse_req,
				       list);
	if (ent && req && !fuse_uring_prep_buffer(ent, req)) {
		fuse_uring_add_req_to_ring_ent(ent, req);
		spin_unlock(&queue->lock);

		fuse_uring_dispatch_ent(ent);
	} else {
		spin_unlock(&queue->lock);
	}

	return true;
}

bool fuse_uring_remove_pending_req(struct fuse_req *req)
{
	struct fuse_ring_queue *queue = req->ring_queue;

	return fuse_remove_pending_req(req, &queue->lock);
}

static const struct fuse_iqueue_ops fuse_io_uring_ops = {
	/* should be send over io-uring as enhancement */
	.send_forget = fuse_dev_queue_forget,

	/*
	 * could be send over io-uring, but interrupts should be rare,
	 * no need to make the code complex
	 */
	.send_interrupt = fuse_dev_queue_interrupt,
	.send_req = fuse_uring_queue_fuse_req,
};
