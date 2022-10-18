#include "conf.h"
#include "event.h"
#include "event_impl.h"
#include "packet.h"
#include "session.h"
#include "slog.h"
#include "sockutil.h"
#include "util.h"

#include <ev.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>

static void udp_reset(struct server *restrict s)
{
	if ((s->conf->mode & MODE_SERVER) != 0) {
		return;
	}
	struct packet *restrict p = s->udp.packets;
	LOGW("udp connection refused, closing all sessions");
	session_close_all(s->sessions);
	for (size_t i = 0; i < p->mq_send_len; i++) {
		struct msgframe *restrict msg = p->mq_send[i];
		msgframe_delete(p, msg);
	}
	p->mq_send_len = 0;
}

#if HAVE_RECVMMSG || HAVE_SENDMMSG
#define MMSG_BATCH_SIZE 128
#endif

#if HAVE_RECVMMSG

static size_t udp_recv(struct server *restrict s)
{
	struct packet *restrict p = s->udp.packets;
	size_t navail = MQ_RECV_SIZE - p->mq_recv_len;
	if (navail == 0) {
		return 0;
	}
	size_t nrecv = 0, nbrecv = 0;
	size_t nbatch;
	do {
		nbatch = navail > MMSG_BATCH_SIZE ? MMSG_BATCH_SIZE : navail;
		static struct mmsghdr msgs[MMSG_BATCH_SIZE];
		static struct msgframe *frames[MMSG_BATCH_SIZE] = { NULL };
		for (size_t i = 0; i < nbatch; i++) {
			if (frames[i] == NULL) {
				struct msgframe *msg = msgframe_new(p, NULL);
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

		const int ret =
			recvmmsg(s->udp.fd, msgs, nbatch, MSG_DONTWAIT, NULL);
		if (ret < 0) {
			/* temporary errors */
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK) ||
			    (errno == EINTR) || (errno == ENOMEM)) {
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
			p->mq_recv[p->mq_recv_len++] = msg;
			nbrecv += msg->len;
			frames[i] = NULL;
			if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
				const struct sockaddr *sa = msg->hdr.msg_name;
				char addr_str[64];
				format_sa(sa, addr_str, sizeof(addr_str));
				LOGV_F("udp recv: %zu bytes from %s", msg->len,
				       addr_str);
			}
		}
		nrecv += (size_t)ret;
		navail -= (size_t)ret;
	} while (nbatch == MMSG_BATCH_SIZE && navail > 0);
	if (nrecv > 0) {
		s->stats.udp_in += nbrecv;
		s->udp.last_recv_time = ev_now(s->loop);
	}
	return nrecv;
}

#else /* HAVE_RECVMMSG */

static size_t udp_recv(struct server *restrict s)
{
	struct packet *restrict p = s->udp.packets;

	size_t nrecv = 0;
	do {
		struct msgframe *restrict msg = msgframe_new(p, NULL);
		if (msg == NULL) {
			return 0;
		}
		const ssize_t nbrecv =
			recvmsg(s->udp.fd, &msg->hdr, MSG_DONTWAIT);
		if (nbrecv < 0) {
			msgframe_delete(p, msg);
			/* temporary errors */
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK) ||
			    (errno == EINTR) || (errno == ENOMEM)) {
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
		p->mq_recv[p->mq_recv_len++] = msg;
		if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
			const struct sockaddr *sa = msg->hdr.msg_name;
			char addr_str[64];
			format_sa(sa, addr_str, sizeof(addr_str));
			LOGV_F("udp recv: %zu bytes from %s", msg->len,
			       addr_str);
		}
		s->stats.udp_in += nbrecv;
		nrecv++;
	} while (true);
	if (nrecv > 0) {
		s->udp.last_recv_time = ev_now(s->loop);
	}
	return nrecv;
}

#endif /* HAVE_RECVMMSG */

void udp_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);
	struct server *restrict s = (struct server *)watcher->data;
	struct packet *restrict p = s->udp.packets;
	const size_t nrecv = udp_recv(s);
	if (nrecv > 0) {
		packet_recv(p, s);
		kcp_notify_all(s);
	}
}

#if HAVE_SENDMMSG

static size_t udp_send(struct server *restrict s)
{
	struct packet *restrict p = s->udp.packets;
	size_t navail = p->mq_send_len;
	if (navail == 0) {
		return 0;
	}
	size_t nsend = 0, nbsend = 0;
	size_t nbatch;

	do {
		nbatch = navail > MMSG_BATCH_SIZE ? MMSG_BATCH_SIZE : navail;
		static struct mmsghdr msgs[MMSG_BATCH_SIZE];
		for (size_t i = 0; i < nbatch; i++) {
			struct msgframe *restrict msg = p->mq_send[nsend + i];
			msgs[i] = (struct mmsghdr){
				.msg_hdr = msg->hdr,
			};
		}
		const int ret = sendmmsg(s->udp.fd, msgs, nbatch, MSG_DONTWAIT);
		if (ret < 0) {
			/* temporary errors */
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK) ||
			    (errno == EINTR) || (errno == ENOMEM)) {
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
			struct msgframe *restrict msg = p->mq_send[nsend + i];
			if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
				const struct sockaddr *sa = msg->hdr.msg_name;
				char addr_str[64];
				format_sa(sa, addr_str, sizeof(addr_str));
				LOGV_F("udp send: %zu bytes to %s", msg->len,
				       addr_str);
			}
			msgframe_delete(p, msg);
		}
		nsend += (size_t)ret;
		navail -= (size_t)ret;
	} while (nbatch == MMSG_BATCH_SIZE && navail > 0);

	/* move remaining messages */
	for (size_t i = 0; i < navail; i++) {
		p->mq_send[i] = p->mq_send[nsend + i];
	}
	p->mq_send_len = navail;
	s->stats.udp_out += nbsend;
	s->udp.last_send_time = ev_now(s->loop);
	return nsend;
}

#else /* HAVE_SENDMMSG */

static size_t udp_send(struct server *restrict s)
{
	struct packet *restrict p = s->udp.packets;
	const size_t count = p->mq_send_len;
	if (count == 0) {
		return 0;
	}
	size_t nsend = 0, nbsend = 0;
	for (size_t i = 0; i < count; i++) {
		struct msgframe *msg = p->mq_send[i];
		const ssize_t nbsend =
			sendmsg(s->udp.fd, &msg->hdr, MSG_DONTWAIT);
		if (nbsend < 0) {
			/* temporary errors */
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK) ||
			    (errno == EINTR) || (errno == ENOMEM)) {
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
		struct msgframe *restrict msg = p->mq_send[i];
		nbsend += msg->len;
		if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
			const struct sockaddr *sa = msg->hdr.msg_name;
			char addr_str[64];
			format_sa(sa, addr_str, sizeof(addr_str));
			LOGV_F("udp send: %zu bytes to %s", msg->len, addr_str);
		}
		msgframe_delete(p, msg);
	}
	const size_t remain = count - nsend;
	for (size_t i = 0; i < remain; i++) {
		p->mq_send[i] = p->mq_send[nsend + i];
	}
	p->mq_send_len = remain;
	s->stats.udp_out += nbsend;
	s->udp.last_send_time = ev_now(s->loop);
	return nsend;
}

#endif /* HAVE_SENDMMSG */

void udp_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);
	struct server *restrict s = (struct server *)watcher->data;
	(void)udp_send(s);
	struct packet *restrict p = s->udp.packets;
	if (p->mq_send_len > 0) {
		return;
	}
	ev_io_stop(loop, watcher);
}

void udp_notify_write(struct server *restrict s)
{
	if (s->udp.packets->mq_send_len == 0) {
		return;
	}
	(void)udp_send(s);
	struct ev_io *restrict w_write = &s->udp.w_write;
	if (ev_is_active(w_write)) {
		return;
	}
	ev_io_start(s->loop, w_write);
}
