/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "event.h"
#include "event_impl.h"
#include "utils/slog.h"
#include "server.h"
#include "pktqueue.h"

#include <inttypes.h>
#include <stddef.h>

static void udp_reset(struct server *restrict s)
{
	if ((s->conf->mode & MODE_SERVER) != 0) {
		return;
	}
	LOG_RATELIMITED(
		LOG_LEVEL_WARNING, s->loop, 1.0,
		"udp connection refused (wrong port number?)");
}

#if HAVE_RECVMMSG || HAVE_SENDMMSG
#define MMSG_BATCH_SIZE 128
static struct mmsghdr mmsgs[MMSG_BATCH_SIZE];
#endif

#if HAVE_RECVMMSG

static size_t pkt_recv(const int fd, struct server *restrict s)
{
	struct pktqueue *restrict q = s->pkt.queue;
	size_t navail = q->mq_recv_cap - q->mq_recv_len;
	if (navail == 0) {
		return 0;
	}
	const ev_tstamp now = ev_now(s->loop);
	size_t nrecv = 0;
	size_t nbatch;
	struct msgframe *frames[MMSG_BATCH_SIZE];
	size_t num_frames = 0;
	do {
		nbatch = MIN(navail, MMSG_BATCH_SIZE);
		for (size_t i = num_frames; i < nbatch; i++) {
			struct msgframe *msg = msgframe_new(q, NULL);
			if (msg == NULL) {
				nbatch = i;
				break;
			}
			frames[num_frames++] = msg;
			mmsgs[i] = (struct mmsghdr){
				.msg_hdr = msg->hdr,
			};
		}
		if (nbatch == 0) {
			/* no frame could be allocated */
			break;
		}

		const int ret = recvmmsg(fd, mmsgs, nbatch, 0, NULL);
		if (ret < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			if (err == ECONNREFUSED || err == ECONNRESET) {
				udp_reset(s);
				break;
			}
			LOGE_F("recvmmsg: %s", strerror(err));
			break;
		} else if (ret == 0) {
			break;
		}
		const size_t n = (size_t)ret;
		for (size_t i = 0; i < n; i++) {
			struct msgframe *restrict msg = frames[i];
			msg->len = (size_t)mmsgs[i].msg_len;
			msg->ts = now;
			q->mq_recv[q->mq_recv_len++] = msg;
			if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
				const struct sockaddr *sa = msg->hdr.msg_name;
				char addr_str[64];
				format_sa(sa, addr_str, sizeof(addr_str));
				LOGV_F("kcp recv: %" PRIu16 " bytes from %s",
				       msg->len, addr_str);
			}
		}
		/* collect unused frames */
		num_frames = nbatch - n;
		for (size_t i = 0; i < num_frames; i++) {
			frames[i] = frames[i + n];
		}
		nrecv += n;
		navail -= n;
	} while (navail > 0);
	/* delete unused frames */
	for (size_t i = 0; i < num_frames; i++) {
		msgframe_delete(q, frames[i]);
	}
	return nrecv;
}

#else /* HAVE_RECVMMSG */

static size_t pkt_recv(const int fd, struct server *restrict s)
{
	struct pktqueue *restrict q = s->pkt.queue;
	size_t navail = q->mq_recv_cap - q->mq_recv_len;
	if (navail == 0) {
		return 0;
	}

	const ev_tstamp now = ev_now(s->loop);
	size_t nrecv = 0;
	do {
		struct msgframe *restrict msg = msgframe_new(q, NULL);
		if (msg == NULL) {
			return 0;
		}
		const ssize_t nbrecv = recvmsg(fd, &msg->hdr, 0);
		if (nbrecv < 0) {
			const int err = errno;
			msgframe_delete(q, msg);
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			if (err == ECONNREFUSED || err == ECONNRESET) {
				udp_reset(s);
				break;
			}
			LOGE_F("recvmsg: %s", strerror(err));
			break;
		}
		msg->len = (size_t)nbrecv;
		msg->ts = now;
		q->mq_recv[q->mq_recv_len++] = msg;
		if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
			const struct sockaddr *sa = msg->hdr.msg_name;
			char addr_str[64];
			format_sa(sa, addr_str, sizeof(addr_str));
			LOGV_F("kcp recv: %" PRIu16 " bytes from %s", msg->len,
			       addr_str);
		}
		s->stats.pkt_rx += nbrecv;
		nrecv++;
		navail--;
	} while (navail > 0);
	return nrecv;
}

#endif /* HAVE_RECVMMSG */

void pkt_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);
	struct server *restrict s = (struct server *)watcher->data;
	struct pktqueue *restrict q = s->pkt.queue;
	size_t nbrecv = 0;
	while (pkt_recv(watcher->fd, s) > 0) {
		nbrecv += queue_recv(q, s);
	}
	if (nbrecv > 0 && s->conf->kcp_flush >= 2) {
		kcp_notify_update(s);
	}
}

static size_t pkt_send_drop(struct pktqueue *restrict q)
{
	const size_t count = q->mq_send_len;
	for (size_t i = 0; i < count; i++) {
		msgframe_delete(q, q->mq_send[i]);
	}
	q->mq_send_len = 0;
	return count;
}

#if HAVE_SENDMMSG

static size_t pkt_send(const int fd, struct server *restrict s)
{
	struct pktqueue *restrict q = s->pkt.queue;
	size_t navail = q->mq_send_len;
	if (navail == 0) {
		return 0;
	}
	bool drop = false;
	size_t nsend = 0, nbsend = 0;
	size_t nbatch;
	do {
		nbatch = MIN(navail, MMSG_BATCH_SIZE);
		for (size_t i = 0; i < nbatch; i++) {
			struct msgframe *restrict msg = q->mq_send[nsend + i];
			mmsgs[i] = (struct mmsghdr){
				.msg_hdr = msg->hdr,
			};
		}
		const int ret = sendmmsg(fd, mmsgs, nbatch, 0);
		if (ret < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			LOGE_F("sendmmsg: %s", strerror(err));
			/* clear the send queue if the error is persistent */
			drop = true;
			break;
		} else if (ret == 0) {
			break;
		}
		const size_t n = (size_t)ret;
		/* delete sent messages */
		for (size_t i = 0; i < n; i++) {
			nbsend += mmsgs[i].msg_len;
			struct msgframe *restrict msg = q->mq_send[nsend + i];
			if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
				const struct sockaddr *sa = msg->hdr.msg_name;
				char addr_str[64];
				format_sa(sa, addr_str, sizeof(addr_str));
				LOGV_F("kcp send: %" PRIu16 " bytes to %s",
				       msg->len, addr_str);
			}
			msgframe_delete(q, msg);
		}
		nsend += n;
		navail -= n;
	} while (navail > 0);

	/* move remaining messages */
	for (size_t i = 0; i < navail; i++) {
		q->mq_send[i] = q->mq_send[nsend + i];
	}
	q->mq_send_len = navail;
	s->stats.pkt_tx += nbsend;
	s->pkt.last_send_time = ev_now(s->loop);
	if (drop) {
		nsend += pkt_send_drop(q);
	}
	return nsend;
}

#else /* HAVE_SENDMMSG */

static size_t pkt_send(const int fd, struct server *restrict s)
{
	struct pktqueue *restrict q = s->pkt.queue;
	const size_t count = q->mq_send_len;
	if (count == 0) {
		return 0;
	}
	bool drop = false;
	size_t nsend = 0, nbsend = 0;
	for (size_t i = 0; i < count; i++) {
		struct msgframe *msg = q->mq_send[i];
		const ssize_t ret = sendmsg(fd, &msg->hdr, 0);
		if (ret < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			LOGE_F("sendmsg: %s", strerror(err));
			/* clear the send queue if the error is persistent */
			drop = true;
			break;
		}
		nsend++, nbsend += ret;
	}
	if (nsend == 0) {
		return 0;
	}
	for (size_t i = 0; i < nsend; i++) {
		struct msgframe *restrict msg = q->mq_send[i];
		if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
			const struct sockaddr *sa = msg->hdr.msg_name;
			char addr_str[64];
			format_sa(sa, addr_str, sizeof(addr_str));
			LOGV_F("kcp send: %" PRIu16 " bytes to %s", msg->len,
			       addr_str);
		}
		msgframe_delete(q, msg);
	}
	const size_t remain = count - nsend;
	for (size_t i = 0; i < remain; i++) {
		q->mq_send[i] = q->mq_send[nsend + i];
	}
	q->mq_send_len = remain;
	s->stats.pkt_tx += nbsend;
	s->pkt.last_send_time = ev_now(s->loop);
	if (drop) {
		nsend += pkt_send_drop(q);
	}
	return nsend;
}

#endif /* HAVE_SENDMMSG */

void pkt_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);
	struct server *restrict s = (struct server *)watcher->data;
	struct pktqueue *restrict q = s->pkt.queue;
	while (pkt_send(watcher->fd, s) > 0) {
		if (q->mq_send_len == 0) {
			kcp_notify_update(s);
		}
	}
	if (q->mq_send_len == 0) {
		ev_io_stop(loop, watcher);
	}
}

void pkt_flush(struct server *restrict s)
{
	struct pktqueue *restrict q = s->pkt.queue;
	struct ev_io *restrict w_write = &s->pkt.w_write;
	(void)pkt_send(w_write->fd, s);
	if (q->mq_send_len > 0 && !ev_is_active(w_write)) {
		ev_io_start(s->loop, w_write);
	}
}
