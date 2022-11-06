#include "event.h"
#include "event_impl.h"
#include "server.h"
#include "pktqueue.h"

#include <inttypes.h>

static void udp_reset(struct server *restrict s)
{
	if ((s->conf->mode & MODE_SERVER) != 0) {
		return;
	}
	struct pktqueue *restrict q = s->pkt.queue;
	LOGW("udp connection refused, closing all sessions");
	session_close_all(s->sessions);
	for (size_t i = 0; i < q->mq_send_len; i++) {
		struct msgframe *restrict msg = q->mq_send[i];
		msgframe_delete(q, msg);
	}
	q->mq_send_len = 0;
}

#if HAVE_RECVMMSG || HAVE_SENDMMSG
#define MMSG_BATCH_SIZE 128
#endif

#if HAVE_RECVMMSG

static size_t pkt_recv(const int fd, struct server *restrict s)
{
	struct pktqueue *restrict q = s->pkt.queue;
	size_t navail = MQ_RECV_SIZE - q->mq_recv_len;
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

		const int ret = recvmmsg(fd, msgs, nbatch, MSG_DONTWAIT, NULL);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == EINTR || errno == ENOMEM) {
				break;
			}
			if ((errno == ECONNREFUSED) || (errno == ECONNRESET)) {
				udp_reset(s);
				break;
			}
			LOGE_PERROR("recvmmsg");
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
	} while (nbatch == MMSG_BATCH_SIZE && navail > 0);
	if (nrecv > 0) {
		s->stats.pkt_in += nbrecv;
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
		const ssize_t nbrecv = recvmsg(fd, &msg->hdr, MSG_DONTWAIT);
		if (nbrecv < 0) {
			msgframe_delete(q, msg);
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == EINTR || errno == ENOMEM) {
				break;
			}
			if ((errno == ECONNREFUSED) || (errno == ECONNRESET)) {
				LOGW("udp connection refused, closing all sessions");
				udp_reset(s);
				break;
			}
			LOGE_PERROR("recvmsg");
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
		s->stats.pkt_in += nbrecv;
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
	const size_t nrecv = pkt_recv(watcher->fd, s);
	if (nrecv > 0) {
		packet_recv(q, s);
		kcp_notify_all(s);
	}
}

#if HAVE_SENDMMSG

static size_t pkt_send(const int fd, struct server *restrict s)
{
	struct pktqueue *restrict q = s->pkt.queue;
	size_t navail = q->mq_send_len;
	if (navail == 0) {
		return 0;
	}
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
		const int ret = sendmmsg(fd, msgs, nbatch, MSG_DONTWAIT);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == EINTR || errno == ENOMEM) {
				break;
			}
			LOGE_PERROR("sendmmsg");
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
	} while (nbatch == MMSG_BATCH_SIZE && navail > 0);

	/* move remaining messages */
	for (size_t i = 0; i < navail; i++) {
		q->mq_send[i] = q->mq_send[nsend + i];
	}
	q->mq_send_len = navail;
	s->stats.pkt_out += nbsend;
	s->pkt.last_send_time = ev_now(s->loop);
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
	size_t nsend = 0;
	for (size_t i = 0; i < count; i++) {
		struct msgframe *msg = q->mq_send[i];
		const ssize_t nbsend = sendmsg(fd, &msg->hdr, MSG_DONTWAIT);
		if (nbsend < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == EINTR || errno == ENOMEM) {
				break;
			}
			LOGE_PERROR("sendmsg");
			break;
		}
		nsend++;
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
	return nsend;
}

#endif /* HAVE_SENDMMSG */

void pkt_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);
	struct server *restrict s = (struct server *)watcher->data;
	(void)pkt_send(watcher->fd, s);
	struct pktqueue *restrict q = s->pkt.queue;
	if (q->mq_send_len == 0) {
		ev_io_stop(loop, watcher);
	}
}

void pkt_notify_write(struct server *restrict s)
{
	struct pktqueue *restrict q = s->pkt.queue;
	struct ev_io *restrict w_write = &s->pkt.w_write;
	(void)pkt_send(w_write->fd, s);
	if (q->mq_send_len > 0 && !ev_is_active(w_write)) {
		ev_io_start(s->loop, w_write);
	}
}
