#include "event.h"
#include "event_impl.h"
#include "packet.h"
#include "sockutil.h"
#include "util.h"

#include <ev.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>

#if HAVE_RECVMMSG || HAVE_SENDMMSG
#define MMSG_BATCH_SIZE 128
#endif

#if HAVE_RECVMMSG

static size_t udp_recv(struct server *restrict s)
{
	struct packet *restrict p = s->udp.packets;
	const size_t navail = MQ_RECV_SIZE - p->mq_recv_len;
	size_t count = navail > MMSG_BATCH_SIZE ? MMSG_BATCH_SIZE : navail;

	static struct mmsghdr msgs[MMSG_BATCH_SIZE];
	static struct msgframe *frames[MMSG_BATCH_SIZE] = { NULL };
	for (size_t i = 0; i < count; i++) {
		if (frames[i] == NULL) {
			struct msgframe *msg = msgframe_new(p, NULL);
			if (msg == NULL) {
				count = i;
				break;
			}
			frames[i] = msg;
		}
		msgs[i] = (struct mmsghdr){
			.msg_hdr = frames[i]->hdr,
			.msg_len = MAX_PACKET_SIZE,
		};
	}
	if (count == 0) {
		return 0;
	}

	const int nrecv = recvmmsg(s->udp.fd, msgs, count, MSG_DONTWAIT, NULL);
	if (nrecv < 0) {
		/* temporary errors */
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK) ||
		    (errno == EINTR)) {
			return 0;
		}
		LOGE_PERROR("recvmmsg");
		return 0;
	} else if (nrecv == 0) {
		return 0;
	}
	s->udp.last_recv_time = ev_now(s->loop);

	size_t nbrecv = 0;
	for (int i = 0; i < nrecv; i++) {
		struct msgframe *restrict msg = frames[i];
		msg->len = (size_t)msgs[i].msg_len;
		p->mq_recv[p->mq_recv_len++] = msg;
		nbrecv += msg->len;
		frames[i] = NULL;
		if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
			struct sockaddr *sa = msg->hdr.msg_name;
			char addr_str[64];
			format_sa(sa, addr_str, sizeof(addr_str));
			LOGV_F("udp recv: %s %zu bytes", addr_str, msg->len);
		}
	}
	s->stats.udp_in += nbrecv;
	return nbrecv;
}

#else /* HAVE_RECVMMSG */

static size_t udp_recv(struct server *restrict s)
{
	struct packet *restrict p = s->udp.packets;

	struct msgframe *restrict msg = msgframe_new(p, NULL);
	if (msg == NULL) {
		break;
	}
	const ssize_t nbrecv = recvmsg(s->udp.fd, &msg->hdr, MSG_DONTWAIT);
	if (nbrecv < 0) {
		msgframe_delete(p, msg);
		/* temporary errors */
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK) ||
		    (errno == EINTR)) {
			break;
		}
		LOGE_PERROR("recvmsg");
		break;
	}
	s->udp.last_recv_time = ev_now(s->loop);

	msg->len = (size_t)nbrecv;
	p->mq_recv[p->mq_recv_len++] = msg;

	if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
		char addr_str[64];
		format_sa(
			(struct sockaddr *)&msg->addr, addr_str,
			sizeof(addr_str));
		LOGV_F("udp recv: %s %zu bytes", addr_str, msg->len);
	}
	s->stats.udp_in += nbrecv;
	return nbrecv;
}

#endif /* HAVE_RECVMMSG */

void udp_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);
	struct server *restrict s = (struct server *)watcher->data;
	struct packet *restrict p = s->udp.packets;
	size_t nrecv = 0;
	while (p->mq_recv_len < MQ_RECV_SIZE) {
		const size_t nbrecv = udp_recv(s);
		if (nbrecv == 0) {
			break;
		}
		nrecv++;
	}
	if (nrecv > 0) {
		packet_recv(p, s);
		kcp_notify_all(s);
	}
}

#if HAVE_SENDMMSG

static size_t udp_send(struct server *restrict s)
{
	struct packet *restrict p = s->udp.packets;
	const size_t count = p->mq_send_len;
	if (count < 1) {
		return 0;
	}

	size_t nsend = 0;
	size_t nbsend = 0;
	do {
		static struct mmsghdr msgs[MMSG_BATCH_SIZE];
		const size_t remain = count - nsend;
		const size_t nbatch =
			remain < MMSG_BATCH_SIZE ? remain : MMSG_BATCH_SIZE;
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
			    (errno == EINTR)) {
				return 0;
			}
			LOGE_PERROR("sendmmsg");
			break;
		} else if (ret == 0) {
			break;
		}
		for (int i = 0; i < ret; i++) {
			nbsend += msgs[i].msg_len;
		}
		nsend += (size_t)ret;
	} while (nsend < count);
	if (nsend == 0) {
		return 0;
	}

	/* move remaining messages */
	for (size_t i = 0; i < nsend; i++) {
		struct msgframe *restrict msg = p->mq_send[i];
		if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
			struct sockaddr *sa = (struct sockaddr *)&msg->addr;
			char addr_str[64];
			format_sa(sa, addr_str, sizeof(addr_str));
			LOGV_F("udp send: %s %zu bytes", addr_str, msg->len);
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
	return nbsend;
}

#else /* HAVE_SENDMMSG */

static size_t udp_send(struct server *restrict s)
{
	struct packet *restrict p = s->udp.packets;
	const size_t count = p->mq_send_len;
	if (count < 1) {
		return 0;
	}
	int nsend = 0;
	for (size_t i = 0; i < count; i++) {
		struct msgframe *msg = p->mq_send[i];
		const ssize_t nbsend =
			sendmsg(s->udp.fd, &msg->hdr, MSG_DONTWAIT);
		if (nbsend < 0) {
			/* temporary errors */
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK) ||
			    (errno == EINTR)) {
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
	size_t nbsend = 0;
	for (int i = 0; i < nsend; i++) {
		struct msgframe *restrict msg = p->mq_send[i];
		nbsend += msg->len;
		if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
			char addr_str[64];
			format_sa(
				(struct sockaddr *)&msg->addr, addr_str,
				sizeof(addr_str));
			LOGV_F("udp send: %s %zu bytes", addr_str, msg->len);
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
	return nbsend;
}

#endif /* HAVE_SENDMMSG */

void udp_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);
	struct server *restrict s = (struct server *)watcher->data;
	struct packet *restrict p = s->udp.packets;
	if (p->mq_send_len > 0) {
		(void)udp_send(s);
	}
	if (p->mq_send_len == 0) {
		ev_io_stop(s->loop, s->udp.w_write);
	}
}

void udp_notify_write(struct server *restrict s)
{
	if (s->udp.packets->mq_send_len == MQ_SEND_SIZE) {
		(void)udp_send(s);
	}
	if (s->udp.packets->mq_send_len == 0) {
		return;
	}
	if (ev_is_active(s->udp.w_write)) {
		return;
	}
	ev_io_start(s->loop, s->udp.w_write);
}
