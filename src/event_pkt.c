/* kcptun-libev (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"
#include "event.h"
#include "pktqueue.h"
#include "server.h"
#include "sockutil.h"
#include "util.h"

#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/minmax.h"
#include "utils/slog.h"

#include <ev.h>

#include <sys/socket.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define PKT_LOGV(what, msg)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(VERBOSE)) {                                      \
			break;                                                 \
		}                                                              \
		char addr[64];                                                 \
		format_sa(addr, sizeof(addr), &(msg)->addr.sa);                \
		LOG_F(VERYVERBOSE, what ": %" PRIu16 " bytes, addr=%s",        \
		      (msg)->len, addr);                                       \
	} while (0)

static void udp_reset(struct server *restrict s)
{
	if ((s->conf->mode & MODE_SERVER) != 0) {
		return;
	}
	LOG_RATELIMITED(
		WARNING, ev_now(s->loop), 1.0,
		"udp connection refused (wrong port number?)");
}

#if HAVE_RECVMMSG || HAVE_SENDMMSG
static struct iovec iovecs[MMSG_BATCH_SIZE];
static struct mmsghdr mmsgs[MMSG_BATCH_SIZE];
#endif

#define RECVMSG_HDR(msg, iov)                                                  \
	((struct msghdr){                                                      \
		.msg_name = &(msg)->addr,                                      \
		.msg_namelen = sizeof((msg)->addr),                            \
		.msg_iov = (iov),                                              \
		.msg_iovlen = 1,                                               \
		.msg_control = NULL,                                           \
		.msg_controllen = 0,                                           \
		.msg_flags = 0,                                                \
	})

#define RECVMSG_IOV(msg)                                                       \
	((struct iovec){                                                       \
		.iov_base = (msg)->buf,                                        \
		.iov_len = sizeof((msg)->buf),                                 \
	})

#if HAVE_RECVMMSG

static size_t pkt_recv(struct server *restrict s, const int fd)
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
		nbatch = MIN(navail, MMSG_BATCH_SIZE);
		struct msgframe *frames[nbatch];
		for (size_t i = 0; i < nbatch; i++) {
			struct msgframe *restrict msg = msgframe_new(q);
			if (msg == NULL) {
				LOGOOM();
				if (i == 0) {
					/* no frame could be allocated */
					return nrecv;
				}
				nbatch = i;
				break;
			}
			frames[i] = msg;
			iovecs[i] = RECVMSG_IOV(msg);
			mmsgs[i] = (struct mmsghdr){
				.msg_hdr = RECVMSG_HDR(msg, &iovecs[i]),
				.msg_len = 0,
			};
		}

		const int ret = recvmmsg(fd, mmsgs, nbatch, 0, NULL);
		if (ret < 0) {
			for (size_t i = 0; i < nbatch; i++) {
				msgframe_delete(q, frames[i]);
			}
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
		}
		if (ret == 0) {
			for (size_t i = 0; i < nbatch; i++) {
				msgframe_delete(q, frames[i]);
			}
			break;
		}
		const size_t n = (size_t)ret;
		for (size_t i = 0; i < n; i++) {
			struct msgframe *restrict msg = frames[i];
			const size_t len = (size_t)mmsgs[i].msg_len;
			msg->len = len;
			msg->ts = now;
			q->mq_recv[q->mq_recv_len++] = msg;
			nbrecv += len;
			PKT_LOGV("pkt recv", msg);
		}
		/* collect unused frames */
		for (size_t i = n; i < nbatch; i++) {
			msgframe_delete(q, frames[i]);
		}
		nrecv += n;
		navail -= n;
	} while (navail > 0);
	s->stats.pkt_rx += nbrecv;
	return nrecv;
}

#else /* HAVE_RECVMMSG */

static size_t pkt_recv(struct server *restrict s, const int fd)
{
	struct pktqueue *restrict q = s->pkt.queue;
	size_t navail = q->mq_recv_cap - q->mq_recv_len;
	if (navail == 0) {
		return 0;
	}

	const ev_tstamp now = ev_now(s->loop);
	size_t nrecv = 0;
	do {
		struct msgframe *restrict msg = msgframe_new(q);
		if (msg == NULL) {
			LOGOOM();
			return 0;
		}
		struct iovec iov = RECVMSG_IOV(msg);
		struct msghdr hdr = RECVMSG_HDR(msg, &iov);
		const ssize_t nbrecv = recvmsg(fd, &hdr, 0);
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
		PKT_LOGV("pkt recv", msg);
		s->stats.pkt_rx += nbrecv;
		nrecv++;
		navail--;
	} while (navail > 0);
	return nrecv;
}

#endif /* HAVE_RECVMMSG */

void pkt_read_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	UNUSED(loop);
	CHECK_REVENTS(revents, EV_READ);
	struct server *restrict s = watcher->data;
	while (pkt_recv(s, watcher->fd) > 0) {
		(void)queue_dispatch(s);
	}
}

static size_t pkt_send_drop(struct pktqueue *restrict q)
{
	const size_t count = q->mq_send_len;
	for (size_t i = 0; i < count; i++) {
		msgframe_delete(q, q->mq_send[i]);
	}
	q->mq_send_len = 0;
	LOGV_F("pkt send: dropping %zu packets", count);
	return count;
}

#define SENDMSG_IOV(msg)                                                       \
	((struct iovec){                                                       \
		.iov_base = (msg)->buf,                                        \
		.iov_len = (msg)->len,                                         \
	})

#define SENDMSG_HDR(msg, iov)                                                  \
	((struct msghdr){                                                      \
		.msg_name = &(msg)->addr,                                      \
		.msg_namelen = getsocklen(&(msg)->addr.sa),                    \
		.msg_iov = (iov),                                              \
		.msg_iovlen = 1,                                               \
		.msg_control = NULL,                                           \
		.msg_controllen = 0,                                           \
		.msg_flags = 0,                                                \
	})

#if HAVE_SENDMMSG

static size_t pkt_send(struct server *restrict s, const int fd)
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
			iovecs[i] = SENDMSG_IOV(msg);
			mmsgs[i] = (struct mmsghdr){
				.msg_hdr = SENDMSG_HDR(msg, &iovecs[i]),
				.msg_len = msg->len,
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
		}
		if (ret == 0) {
			break;
		}
		const size_t n = (size_t)ret;
		/* delete sent messages */
		for (size_t i = 0; i < n; i++) {
			struct msgframe *restrict msg = q->mq_send[nsend + i];
			nbsend += msg->len;
			PKT_LOGV("pkt send", msg);
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

static size_t pkt_send(struct server *restrict s, const int fd)
{
	struct pktqueue *restrict q = s->pkt.queue;
	const size_t count = q->mq_send_len;
	if (count == 0) {
		return 0;
	}
	bool drop = false;
	size_t nsend = 0, nbsend = 0;
	for (size_t i = 0; i < count; i++) {
		struct msgframe *restrict msg = q->mq_send[i];
		struct iovec iov = SENDMSG_IOV(msg);
		struct msghdr hdr = SENDMSG_HDR(msg, &iov);
		const ssize_t ret = sendmsg(fd, &hdr, 0);
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
		PKT_LOGV("pkt send", msg);
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

static void pkt_flush(struct server *restrict s)
{
	const int fd = s->pkt.w_write.fd;
	while (pkt_send(s, fd) > 0) {
		;
	}
}

void pkt_write_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct server *restrict s = watcher->data;
	if (s->pkt.queue->mq_send_len == 0) {
		LOGD_F("pkt send fd=%d stop", watcher->fd);
		ev_io_stop(loop, watcher);
		return;
	}
	pkt_flush(s);
}

void pkt_notify_send(struct server *restrict s)
{
	const struct pktqueue *restrict q = s->pkt.queue;
	pkt_flush(s);
	ev_io *restrict w_write = &s->pkt.w_write;
	if (q->mq_send_len > 0 && !ev_is_active(w_write)) {
		LOGD_F("pkt send fd=%d start", w_write->fd);
		ev_io_start(s->loop, w_write);
	}
}
