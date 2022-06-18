#include "event_impl.h"
#include "packet.h"
#include "sockutil.h"
#include "util.h"

#include <ev.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>

#if HAVE_RECVMMSG

void udp_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);

	struct server *restrict s = (struct server *)watcher->data;
	struct packet *restrict p = s->udp.packets;
	size_t count = MSG_QUEUE_SIZE - p->mq_recv_len;

	static struct mmsghdr msgs[MSG_QUEUE_SIZE];
	static struct msgframe *frames[MSG_QUEUE_SIZE] = { NULL };
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
		return;
	}

	const int nrecv = recvmmsg(s->udp.fd, msgs, count, MSG_DONTWAIT, NULL);
	if (nrecv < 0) {
		/* temporary errors */
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK) ||
		    (errno == EINTR)) {
			return;
		}
		LOG_PERROR("recvmmsg");
		return;
	} else if (nrecv == 0) {
		return;
	}
	size_t len = 0;
	for (int i = 0; i < nrecv; i++) {
		struct msgframe *restrict msg = frames[i];
		msg->len = (size_t)msgs[i].msg_len;
		p->mq_recv[p->mq_recv_len++] = msg;
		len += msg->len;
		frames[i] = NULL;
		if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
			struct sockaddr *sa = msg->hdr.msg_name;
			char addr_str[64];
			format_sa(sa, addr_str, sizeof(addr_str));
			LOGV_F("udp recv: %s %zu bytes", addr_str, msg->len);
		}
	}
	s->stats.udp_in += len;
	packet_recv(p, s);
}

#else /* HAVE_RECVMMSG */

void udp_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);

	struct server *restrict s = (struct server *)watcher->data;
	struct packet *restrict p = s->udp.packets;
	size_t count = MSG_QUEUE_SIZE - p->mq_recv_len;

	int nrecv = 0;
	for (size_t i = 0; i < count; i++) {
		struct msgframe *restrict msg = msgframe_new(p, NULL);
		if (msg == NULL) {
			break;
		}
		const ssize_t nbrecv =
			recvmsg(s->udp.fd, &msg->hdr, MSG_DONTWAIT);
		if (nbrecv < 0) {
			msgframe_delete(p, msg);
			/* temporary errors */
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK) ||
			    (errno == EINTR)) {
				break;
			}
			LOG_PERROR("recvmsg");
			break;
		}
		msg->len = (size_t)nbrecv;
		p->mq_recv[p->mq_recv_len++] = msg;
		nrecv++;

		s->stats.udp_in += nbrecv;
		if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
			char addr_str[64];
			format_sa(
				(struct sockaddr *)&msg->addr, addr_str,
				sizeof(addr_str));
			LOGV_F("udp recv: %s %zu bytes", addr_str, msg->len);
		}
	}
	if (nrecv > 0) {
		packet_recv(p, s);
	}
}

#endif /* HAVE_RECVMMSG */

#if HAVE_SENDMMSG

static void udp_send(struct server *restrict s)
{
	struct packet *restrict p = s->udp.packets;
	const size_t count = p->mq_send_len;
	if (count < 1) {
		ev_io_stop(s->loop, s->udp.w_write);
		return;
	}

	static struct mmsghdr msgs[MSG_QUEUE_SIZE];
	for (size_t i = 0; i < count; i++) {
		struct msgframe *restrict msg = p->mq_send[i];
		msgs[i] = (struct mmsghdr){
			.msg_hdr = msg->hdr,
		};
	}

	int nsend = sendmmsg(s->udp.fd, msgs, count, MSG_DONTWAIT);
	if (nsend < 0) {
		/* temporary errors */
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK) ||
		    (errno == EINTR)) {
			ev_io_start(s->loop, s->udp.w_write);
			return;
		}
		LOG_PERROR("sendmmsg");
		return;
	}
	if ((size_t)nsend < count) {
		ev_io_start(s->loop, s->udp.w_write);
	}

	/* move remaining messages */
	if (nsend == 0) {
		return;
	}
	size_t len = 0;
	for (int i = 0; i < nsend; i++) {
		struct msgframe *restrict msg = p->mq_send[i];
		len += msgs[i].msg_len;
		if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
			struct sockaddr *sa = (struct sockaddr *)&msg->addr;
			char addr_str[64];
			format_sa(sa, addr_str, sizeof(addr_str));
			LOGV_F("udp send: %s %u bytes", addr_str,
			       msgs[i].msg_len);
		}
		msgframe_delete(p, msg);
	}
	const size_t remain = count - nsend;
	if (remain > 0) {
		memmove(p->mq_send, p->mq_send + nsend,
			sizeof(struct msgframe *) * remain);
		LOGV_F("udp send: remain %zu pkts", remain);
	}
	p->mq_send_len = remain;
	s->stats.udp_out += len;
	s->udp.last_send_time = ev_now(s->loop);
}

#else /* HAVE_SENDMMSG */

static void udp_send(struct server *restrict s)
{
	struct packet *restrict p = s->udp.packets;
	const size_t count = p->mq_send_len;
	if (count < 1) {
		ev_io_stop(s->loop, s->udp.w_write);
		return;
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
			LOG_PERROR("sendmsg");
			break;
		}
		nsend++;
	}
	if ((size_t)nsend < count) {
		ev_io_start(s->loop, s->udp.w_write);
	}
	if (nsend == 0) {
		return;
	}
	size_t len = 0;
	for (int i = 0; i < nsend; i++) {
		struct msgframe *restrict msg = p->mq_send[i];
		len += msg->len;
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
	if (remain > 0) {
		memmove(p->mq_send, p->mq_send + nsend,
			sizeof(struct msgframe *) * remain);
	}
	p->mq_send_len = remain;
	s->stats.udp_out += len;
	s->udp.last_send_time = ev_now(s->loop);
}

#endif /* HAVE_SENDMMSG */

void udp_notify_write(struct server *restrict s)
{
	if (ev_is_active(s->udp.w_write)) {
		return;
	}
	udp_send(s);
}

void udp_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);

	udp_send((struct server *)watcher->data);
}
