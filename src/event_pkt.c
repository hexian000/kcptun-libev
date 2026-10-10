/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"
#include "event.h"
#include "pktqueue.h"
#include "server.h"
#include "util.h"

#include "meta/minmax.h"
#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#define PKT_LOGVV(what, msg)                                                   \
	do {                                                                   \
		if (!LOGLEVEL(VERYVERBOSE)) {                                  \
			break;                                                 \
		}                                                              \
		char addr[64] = "<unknown>";                                   \
		(void)sa_format(addr, sizeof(addr), &(msg)->addr.sa);          \
		LOG_F(VERYVERBOSE, what ": %" PRIu16 " bytes, addr=%s",        \
		      (msg)->len, addr);                                       \
	} while (0)

static void udp_log_refused(const struct server *restrict s)
{
	if ((s->conf->mode & MODE_SERVER) != 0) {
		return;
	}
	LOG_RATELIMITED(
		WARNING, ev_now(s->loop), 1.0,
		"udp connection refused (wrong port number?)");
}

#if HAVE_RECVMMSG || HAVE_SENDMMSG
/* shared scratch space between pkt_recv and pkt_send; safe only because
 * the two are never active on the call stack at the same time (single
 * event loop, neither calls the other) */
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

static size_t
pkt_recv(struct server *restrict s, const int fd, const size_t limit)
{
	struct pktqueue *restrict q = s->pkt.queue;
	size_t navail = MIN(q->mq_recv_cap - q->mq_recv_len, limit);
	if (navail == 0) {
		return 0;
	}
	const ev_tstamp now = ev_now(s->loop);
	size_t nrecv = 0, nbrecv = 0;
	size_t nbatch;
	do {
		nbatch = MIN(navail, MMSG_BATCH_SIZE);
		struct msgframe *frames[nbatch];
		size_t populated = nbatch;
		for (size_t i = 0; i < nbatch; i++) {
			struct msgframe *restrict msg = msgframe_new(q);
			if (msg == NULL) {
				LOGOOM();
				if (i == 0) {
					/* no frame could be allocated */
					s->stats.pkt_rx +=
						(uint_least64_t)nbrecv;
					return nrecv;
				}
				populated = i;
				break;
			}
			frames[i] = msg;
			iovecs[i] = RECVMSG_IOV(msg);
			mmsgs[i] = (struct mmsghdr){
				.msg_hdr = RECVMSG_HDR(msg, &iovecs[i]),
				.msg_len = 0,
			};
		}

		const int ret = recvmmsg(fd, mmsgs, populated, 0, NULL);
		if (ret < 0) {
			const int err = errno;
			for (size_t i = 0; i < populated; i++) {
				msgframe_delete(q, frames[i]);
			}
			if (err == EINTR) {
				continue;
			}
			if (err == EAGAIN || err == EWOULDBLOCK) {
				break;
			}
			if (err == ECONNREFUSED || err == ECONNRESET) {
				udp_log_refused(s);
				break;
			}
			LOGE_F("recvmmsg: (%d) %s", err, strerror(err));
			break;
		}
		if (ret == 0) {
			for (size_t i = 0; i < populated; i++) {
				msgframe_delete(q, frames[i]);
			}
			break;
		}
		const size_t n = (size_t)ret;
		ASSERT(n <= populated);
		for (size_t i = 0; i < n; i++) {
			struct msgframe *restrict msg = frames[i];
			if ((mmsgs[i].msg_hdr.msg_flags & MSG_TRUNC) != 0) {
				LOG_RATELIMITED_F(
					WARNING, now, 1.0,
					"pkt_recv: dropped truncated datagram (%zu bytes)",
					(size_t)mmsgs[i].msg_len);
				msgframe_delete(q, msg);
				continue;
			}
			const size_t len = (size_t)mmsgs[i].msg_len;
			msg->len = (uint16_t)len;
			msg->ts = now;
			q->mq_recv[q->mq_recv_len++] = msg;
			nbrecv += len;
			PKT_LOGVV("pkt recv", msg);
		}
		/* collect unused frames */
		for (size_t i = n; i < populated; i++) {
			msgframe_delete(q, frames[i]);
		}
		nrecv += n;
		navail -= n;
		if (n < populated) {
			break;
		}
	} while (navail > 0);
	s->stats.pkt_rx += (uint_least64_t)nbrecv;
	return nrecv;
}

#else /* HAVE_RECVMMSG */

static size_t
pkt_recv(struct server *restrict s, const int fd, const size_t limit)
{
	struct pktqueue *restrict q = s->pkt.queue;
	size_t navail = MIN(q->mq_recv_cap - q->mq_recv_len, limit);
	if (navail == 0) {
		return 0;
	}

	const ev_tstamp now = ev_now(s->loop);
	size_t nrecv = 0;
	do {
		struct msgframe *restrict msg = msgframe_new(q);
		if (msg == NULL) {
			LOGOOM();
			return nrecv;
		}
		struct iovec iov = RECVMSG_IOV(msg);
		struct msghdr hdr = RECVMSG_HDR(msg, &iov);
		const ssize_t nbrecv = recvmsg(fd, &hdr, 0);
		if (nbrecv < 0) {
			const int err = errno;
			msgframe_delete(q, msg);
			if (err == EINTR) {
				continue;
			}
			if (err == EAGAIN || err == EWOULDBLOCK) {
				break;
			}
			if (err == ECONNREFUSED || err == ECONNRESET) {
				udp_log_refused(s);
				break;
			}
			LOGE_F("recvmsg: (%d) %s", err, strerror(err));
			break;
		}
		if ((hdr.msg_flags & MSG_TRUNC) != 0) {
			LOG_RATELIMITED_F(
				WARNING, now, 1.0,
				"pkt_recv: dropped truncated datagram (%zu bytes)",
				(size_t)nbrecv);
			msgframe_delete(q, msg);
			nrecv++;
			navail--;
			continue;
		}
		msg->len = (uint16_t)nbrecv;
		msg->ts = now;
		q->mq_recv[q->mq_recv_len++] = msg;
		PKT_LOGVV("pkt recv", msg);
		s->stats.pkt_rx += (uint_least64_t)nbrecv;
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
	/* Yield to timers and other watchers even under continuous UDP traffic.
	 * Level-triggered EV_READ will resume any datagrams left on the socket. */
	size_t remaining = (size_t)MMSG_BATCH_SIZE * 4;
	while (remaining > 0) {
		const size_t limit = MIN(s->pkt.queue->mq_recv_cap, remaining);
		const size_t nrecv = pkt_recv(s, watcher->fd, limit);
		queue_dispatch(s);
		if (nrecv == 0 || nrecv < limit) {
			break;
		}
		remaining -= nrecv;
	}
}

static void udp_log_send_error(
	const struct server *restrict s, const char *operation, const int err)
{
	if (err == ECONNREFUSED || err == ECONNRESET) {
		udp_log_refused(s);
		return;
	}
	LOG_RATELIMITED_F(
		ERROR, ev_now(s->loop), 1.0, "%s: (%d) %s", operation, err,
		strerror(err));
}

#define SENDMSG_IOV(msg)                                                       \
	((struct iovec){                                                       \
		.iov_base = (msg)->buf,                                        \
		.iov_len = (msg)->len,                                         \
	})

#define SENDMSG_HDR(msg, iov)                                                  \
	((struct msghdr){                                                      \
		.msg_name = &(msg)->addr,                                      \
		.msg_namelen = sa_len(&(msg)->addr.sa),                        \
		.msg_iov = (iov),                                              \
		.msg_iovlen = 1,                                               \
		.msg_control = NULL,                                           \
		.msg_controllen = 0,                                           \
		.msg_flags = 0,                                                \
	})

#if HAVE_SENDMMSG

static size_t
pkt_send(struct server *restrict s, const int fd, bool *restrict eagain)
{
	struct pktqueue *restrict q = s->pkt.queue;
	size_t navail = q->mq_send_len;
	*eagain = false;
	if (navail == 0) {
		return 0;
	}
	size_t nprocessed = 0, nsend = 0, nbsend = 0;
	size_t nbatch;
	do {
		nbatch = MIN(navail, MMSG_BATCH_SIZE);
		for (size_t i = 0; i < nbatch; i++) {
			struct msgframe *restrict msg =
				q->mq_send[nprocessed + i];
			iovecs[i] = SENDMSG_IOV(msg);
			mmsgs[i] = (struct mmsghdr){
				.msg_hdr = SENDMSG_HDR(msg, &iovecs[i]),
				.msg_len = msg->len,
			};
		}

		const int ret = sendmmsg(fd, mmsgs, nbatch, 0);
		if (ret < 0) {
			const int err = errno;
			if (err == EINTR) {
				continue;
			}
			if (err == EAGAIN || err == EWOULDBLOCK) {
				*eagain = true;
				break;
			}
			udp_log_send_error(s, "sendmmsg", err);
			msgframe_delete(q, q->mq_send[nprocessed++]);
			navail--;
			continue;
		}
		if (ret == 0) {
			break;
		}
		const size_t n = (size_t)ret;
		/* delete sent messages */
		for (size_t i = 0; i < n; i++) {
			struct msgframe *restrict msg =
				q->mq_send[nprocessed + i];
			nbsend += msg->len;
			PKT_LOGVV("pkt send", msg);
			msgframe_delete(q, msg);
		}
		nprocessed += n;
		nsend += n;
		navail -= n;
	} while (navail > 0);

	/* move remaining messages */
	for (size_t i = 0; i < navail; i++) {
		q->mq_send[i] = q->mq_send[nprocessed + i];
	}
	q->mq_send_len = navail;
	if (nsend > 0) {
		/* only stamp last_send_time when something was actually sent;
		   stamping under sustained EAGAIN would keep deferring keepalive */
		s->stats.pkt_tx += (uint_least64_t)nbsend;
		s->pkt.last_send_time = ev_now(s->loop);
	}
	return nprocessed;
}

#else /* HAVE_SENDMMSG */

static size_t
pkt_send(struct server *restrict s, const int fd, bool *restrict eagain)
{
	struct pktqueue *restrict q = s->pkt.queue;
	const size_t count = q->mq_send_len;
	*eagain = false;
	if (count == 0) {
		return 0;
	}
	size_t nprocessed = 0, nsend = 0, nbsend = 0;
	for (size_t i = 0; i < count; i++) {
		struct msgframe *restrict msg = q->mq_send[i];
		struct iovec iov = SENDMSG_IOV(msg);
		struct msghdr hdr = SENDMSG_HDR(msg, &iov);
		ssize_t ret;
		int err;
		do {
			ret = sendmsg(fd, &hdr, 0);
			err = errno;
		} while (ret < 0 && err == EINTR);
		if (ret < 0) {
			if (err == EAGAIN || err == EWOULDBLOCK) {
				*eagain = true;
				break;
			}
			udp_log_send_error(s, "sendmsg", err);
			msgframe_delete(q, msg);
			nprocessed++;
			continue;
		}
		nprocessed++;
		nsend++, nbsend += ret;
		PKT_LOGVV("pkt send", msg);
		msgframe_delete(q, msg);
	}
	const size_t remain = count - nprocessed;
	for (size_t i = 0; i < remain; i++) {
		q->mq_send[i] = q->mq_send[nprocessed + i];
	}
	q->mq_send_len = remain;
	if (nsend > 0) {
		/* only stamp last_send_time when something was actually sent */
		s->stats.pkt_tx += (uint_least64_t)nbsend;
		s->pkt.last_send_time = ev_now(s->loop);
	}
	return nprocessed;
}

#endif /* HAVE_SENDMMSG */

static void pkt_flush(struct server *restrict s)
{
	const int fd = s->pkt.w_write.fd;
	if (fd == -1) {
		return;
	}
	bool eagain = false;
	while (!eagain && pkt_send(s, fd, &eagain) > 0) {
		;
	}
}

void pkt_write_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct server *restrict s = watcher->data;
	if (s->pkt.queue->mq_send_len == 0) {
		LOGD_F("[fd:%d] pkt send stop", watcher->fd);
		ev_io_stop(loop, watcher);
		return;
	}
	pkt_flush(s);
}

void pkt_notify_send(struct server *restrict s)
{
	if (s->pkt.w_write.fd == -1) {
		return;
	}
	const struct pktqueue *q = s->pkt.queue;
	pkt_flush(s);
	ev_io *restrict w_write = &s->pkt.w_write;
	if (q->mq_send_len > 0 && !ev_is_active(w_write)) {
		LOGD_F("[fd:%d] pkt send start", w_write->fd);
		ev_io_start(s->loop, w_write);
	}
}
