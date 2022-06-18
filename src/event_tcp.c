#include "event.h"
#include "event_impl.h"
#include "hashtable.h"
#include "kcp/ikcp.h"
#include "session.h"
#include "slog.h"
#include "sockutil.h"

#include "util.h"
#include <string.h>
#include <sys/socket.h>

static void accept_one(struct server *restrict s, const int fd)
{
	/* Initialize and start watcher to read client requests */
	uint32_t conv = conv_new(s);
	struct session *restrict ss;
	ss = session_new(s, fd, s->conf->addr_udp_connect, conv);
	if (ss == NULL) {
		LOGE("accept: out of memory");
		close(fd);
		return;
	}
	ss->is_accepted = true;
	ss->state = STATE_CONNECTED;
	ss->last_seen = ev_now(s->loop);
	hashkey_t key;
	conv_make_key(&key, s->conf->addr_udp_connect, conv);
	table_set(s->sessions, &key, ss);
	session_start(ss);
}

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);

	sockaddr_max_t m_sa;
	struct sockaddr *sa = (struct sockaddr *)&m_sa;
	socklen_t sa_len;
	int client_fd;

	while (true) {
		sa_len = sizeof(sa);
		// Accept client request
		client_fd = accept(watcher->fd, sa, &sa_len);
		if (client_fd < 0) {
			/* temporary errors */
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK) ||
			    (errno == EINTR)) {
				break;
			}
			LOG_PERROR("accept");
			return;
		}
		socket_set_nonblock(client_fd);

		if (LOGLEVEL(LOG_LEVEL_INFO)) {
			char addr_str[64];
			format_sa(sa, addr_str, sizeof(addr_str));
			LOGI_F("tcp accept from: %s", addr_str);
		}
		accept_one((struct server *)watcher->data, client_fd);
	};
}

#define TLV_MAX_LENGTH (SESSION_BUF_SIZE - MAX_PACKET_SIZE)

void tcp_recv(struct session *restrict ss)
{
	struct server *restrict s = ss->server;

	(void)kcp_send(ss);
	/* reserve some space to encode header in place */
	size_t cap = TLV_MAX_LENGTH - TLV_HEADER_SIZE - ss->rbuf_len;
	if (cap == 0) {
		/* KCP EAGAIN */
		ev_io_stop(s->loop, ss->w_read);
		return;
	}
	ev_io_start(s->loop, ss->w_read);

	unsigned char *buf = ss->rbuf + TLV_HEADER_SIZE + ss->rbuf_len;
	size_t len = 0;
	bool tcp_eof = false;
	while (cap > 0) {
		/* Receive message from client socket */
		const ssize_t nread =
			recv(ss->tcp_fd, buf, cap, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (nread < 0) {
			/* temporary errors */
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK) ||
			    (errno == EINTR)) {
				break;
			}
			LOG_PERROR("recv");
			kcp_close(ss);
			session_shutdown(ss);
			return;
		}
		if (nread == 0) {
			tcp_eof = true;
			break;
		}
		buf += nread, cap -= nread, len += nread;
	}
	ss->rbuf_len = len;

	if (len > 0) {
		ss->stats.tcp_in += len;
		ss->server->stats.tcp_in += len;
		LOGV_F("session [%08" PRIX32
		       "] tcp recv: %zu bytes, cap: %zu bytes",
		       ss->kcp->conv, len, cap);

		ss->last_seen = ev_now(s->loop);
		if (kcp_send(ss)) {
			kcp_notify(ss);
		}
	}

	if (tcp_eof) {
		LOGI_F("session [%08" PRIX32 "] tcp closing", ss->kcp->conv);
		// Stop and free session if client socket is closing
		kcp_close(ss);
		session_shutdown(ss);
		ss->state = STATE_LINGER;
	}
}

void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);

	tcp_recv((struct session *)watcher->data);
}

static void tcp_send(struct session *restrict ss)
{
	struct server *restrict s = ss->server;
	size_t navail = kcp_recv(ss);
	if (navail == 0) {
		/* no more data */
		if (ss->w_write != NULL) {
			ev_io_stop(s->loop, ss->w_write);
		}
		return;
	}

	unsigned char *raw = ss->wbuf + TLV_HEADER_SIZE;
	unsigned char *next = raw + navail;
	unsigned char *buf = raw + ss->wbuf_flush;
	size_t len = next - buf;

	ssize_t nsend = send(ss->tcp_fd, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (nsend < 0) {
		const int err = errno;
		if (err == EAGAIN || err == EWOULDBLOCK || err == EINPROGRESS) {
			/* ignore temporary errors */
			ev_io_start(s->loop, ss->w_write);
			return;
		}
		LOGE_F("session [%08" PRIu32 "] fd=%d tcp send error: [%d] %s",
		       ss->kcp->conv, ss->tcp_fd, err, strerror(err));
		session_shutdown(ss);
		kcp_close(ss);
		ss->state = STATE_LINGER;
		return;
	}
	if (nsend == 0) {
		return;
	}
	if ((size_t)nsend < len) {
		ss->wbuf_flush += nsend;
		ev_io_start(s->loop, ss->w_write);
	} else {
		const size_t msg_len = TLV_HEADER_SIZE + navail;
		ss->wbuf_len -= msg_len;
		memmove(ss->wbuf, next, ss->wbuf_len);
		ss->wbuf_flush = 0;
	}

	ss->stats.tcp_out += nsend;
	ss->server->stats.tcp_out += nsend;
	LOGV_F("session [%08" PRIX32 "] tcp send: %zd bytes, remain: %zu bytes",
	       ss->kcp->conv, nsend, len - (size_t)nsend + ss->wbuf_len);
}

void tcp_notify_write(struct session *restrict ss)
{
	if (ss->state != STATE_CONNECTED) {
		return;
	}
	if (ss->w_write == NULL) {
		return;
	}
	if (ev_is_active(ss->w_write)) {
		return;
	}
	tcp_send(ss);
}

void write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);

	struct session *restrict ss = (struct session *)watcher->data;
	if (ss->tcp_fd == -1) {
		return;
	}

	if (ss->state == STATE_CONNECT) {
		ss->state = STATE_CONNECTED;
		ss->last_seen = ev_now(ss->server->loop);
		LOGD_F("session [%08" PRIX32 "] tcp connected", ss->kcp->conv);
	}

	tcp_send(ss);
}
