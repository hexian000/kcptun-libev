/* kcptun-libev (c) 2019-2022 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "event.h"
#include "event_impl.h"
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
	size_t nrecv = 0, nbrecv = 0;
	size_t nbatch;
	do {
		nbatch = navail > MMSG_BATCH_SIZE ? MMSG_BATCH_SIZE : navail;
		static struct mmsghdr msgs[MMSG_BATCH_SIZE];
		static struct msgframe *frames[MMSG_BATCH_SIZE] = { NULL };
		for (size_t i = 0; i < nbatch; i++) {
			if (frames[i] == NULL) {
				struct msgframe *msg = msgframe_new(q, NULL);
				if (msg == NULL) {
					nbatch = i;
					break;
				}
				frames[i] = msg;
			}
			msgs[i] = (struct mmsghdr){
				.msg_hdr = frames[i]->hdr,
			};
		}

		const int ret = recvmmsg(fd, msgs, nbatch, 0, NULL);
		if (ret < 0) {
			const int err = errno;
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == EINTR || err == ENOMEM) {
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
		for (int i = 0; i < ret; i++) {
			struct msgframe *restrict msg = frames[i];
			msg->len = (size_t)msgs[i].msg_len;
			msg->ts = now;
			q->mq_recv[q->mq_recv_len++] = msg;
			nbrecv += msg->len;
			frames[i] = NULL;
			if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
				const struct sockaddr *sa = msg->hdr.msg_name;
				char addr_str[64];
				format_sa(sa, addr_str, sizeof(addr_str));
				LOGV_F("kcp recv: %" PRIu16 " bytes from %s",
				       msg->len, addr_str);
			}
		}
		nrecv += (size_t)ret;
		navail -= (size_t)ret;
	} while (navail > 0);
	if (nrecv > 0) {
		s->stats.pkt_rx += nbrecv;
		s->pkt.last_recv_time = ev_now(s->loop);
	}
	return nrecv;
}

#else /* HAVE_RECVMMSG */

static size_t pkt_recv(const int fd, struct server *restrict s)
{
	struct pktqueue *restrict q = s->pkt.queue;

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
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == EINTR || err == ENOMEM) {
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
	} while (true);
	if (nrecv > 0) {
		s->pkt.last_recv_time = ev_now(s->loop);
	}
	return nrecv;
}

#endif /* HAVE_RECVMMSG */

void pkt_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);
	struct server *restrict s = (struct server *)watcher->data;
	struct pktqueue *restrict q = s->pkt.queue;
	while (pkt_recv(watcher->fd, s) > 0) {
		(void)queue_recv(q, s);
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
		nbatch = navail > MMSG_BATCH_SIZE ? MMSG_BATCH_SIZE : navail;
		static struct mmsghdr msgs[MMSG_BATCH_SIZE];
		for (size_t i = 0; i < nbatch; i++) {
			struct msgframe *restrict msg = q->mq_send[nsend + i];
			msgs[i] = (struct mmsghdr){
				.msg_hdr = msg->hdr,
			};
		}
		const int ret = sendmmsg(fd, msgs, nbatch, 0);
		if (ret < 0) {
			const int err = errno;
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == EINTR || err == ENOMEM) {
				break;
			}
			LOGE_F("sendmmsg: %s", strerror(err));
			/* drop packets to prevent infinite error loop */
			drop = true;
			break;
		} else if (ret == 0) {
			break;
		}
		/* delete sent messages */
		for (int i = 0; i < ret; i++) {
			nbsend += msgs[i].msg_len;
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
		nsend += (size_t)ret;
		navail -= (size_t)ret;
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
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == EINTR || err == ENOMEM) {
				break;
			}
			LOGE_F("sendmsg: %s", strerror(err));
			/* drop packets to prevent infinite error loop */
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
