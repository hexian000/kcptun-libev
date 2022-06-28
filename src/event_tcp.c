#include "event.h"
#include "event_impl.h"
#include "hashtable.h"
#include "kcp/ikcp.h"
#include "session.h"
#include "slog.h"
#include "sockutil.h"

#include "util.h"

#include <ev.h>
#include <string.h>
#include <sys/socket.h>

static void accept_one(struct server *restrict s, const int fd)
{
	/* Initialize and start watcher to read client requests */
	uint32_t conv = conv_new(s);
	struct session *restrict ss;
	ss = session_new(s, fd, s->conf->udp_connect.sa, conv);
	if (ss == NULL) {
		LOGE("accept: out of memory");
		close(fd);
		return;
	}
	ss->is_accepted = true;
	ss->state = STATE_CONNECTED;
	ss->last_seen = ev_now(s->loop);
	hashkey_t key;
	conv_make_key(&key, s->conf->udp_connect.sa, conv);
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
		if (socket_set_nonblock(client_fd)) {
			LOG_PERROR("fcntl");
			close(client_fd);
			return;
		}
		{
			struct server *restrict s = watcher->data;
			struct config *restrict cfg = s->conf;
			socket_set_tcp(
				client_fd, cfg->tcp_nodelay,
				cfg->tcp_lingertime, cfg->tcp_keepalive);
			socket_set_buffer(
				client_fd, cfg->tcp_sndbuf, cfg->tcp_rcvbuf);
		}

		if (LOGLEVEL(LOG_LEVEL_INFO)) {
			char addr_str[64];
			format_sa(sa, addr_str, sizeof(addr_str));
			LOGI_F("tcp accept from: %s", addr_str);
		}
		accept_one((struct server *)watcher->data, client_fd);
	};
}

#define TLV_MAX_LENGTH (SESSION_BUF_SIZE - MAX_PACKET_SIZE)

size_t tcp_recv(struct session *restrict ss)
{
	struct server *restrict s = ss->server;

	/* reserve some space to encode header in place */
	size_t cap = TLV_MAX_LENGTH - TLV_HEADER_SIZE - ss->rbuf_len;
	if (cap == 0) {
		/* KCP EAGAIN */
		return 0;
	}

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
			return 0;
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
	}

	if (tcp_eof) {
		LOGI_F("session [%08" PRIX32 "] tcp closing", ss->kcp->conv);
		// Stop and free session if client socket is closing
		kcp_close(ss);
		session_shutdown(ss);
		ss->state = STATE_LINGER;
	}
	return len;
}

void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);

	struct session *restrict ss = (struct session *)watcher->data;
	if (ss->rbuf_len == 0) {
		if (tcp_recv(ss) == 0) {
			if (ss->w_read != NULL) {
				ev_io_stop(loop, ss->w_read);
			}
		}
	}
	if (kcp_send(ss) > 0) {
		kcp_notify(ss);
	}
}

static size_t tcp_send(struct session *restrict ss)
{
	const size_t navail = ss->wbuf_navail;
	if (navail == 0) {
		return 0;
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
			return 0;
		}
		LOGE_F("session [%08" PRIu32 "] fd=%d tcp send error: [%d] %s",
		       ss->kcp->conv, ss->tcp_fd, err, strerror(err));
		session_shutdown(ss);
		kcp_close(ss);
		ss->state = STATE_LINGER;
		return 0;
	}
	if (nsend == 0) {
		return 0;
	}
	if ((size_t)nsend < len) {
		ss->wbuf_flush += nsend;
	} else {
		const size_t msg_len = TLV_HEADER_SIZE + navail;
		ss->wbuf_len -= msg_len;
		ss->wbuf_navail = 0;
		ss->wbuf_flush = 0;
		memmove(ss->wbuf, next, ss->wbuf_len);
	}

	ss->stats.tcp_out += nsend;
	ss->server->stats.tcp_out += nsend;
	LOGV_F("session [%08" PRIX32 "] tcp send: %zd bytes, remain: %zu bytes",
	       ss->kcp->conv, nsend, len - (size_t)nsend + ss->wbuf_len);
	return (size_t)nsend;
}

void tcp_notify_write(struct session *restrict ss)
{
	if (ss->state != STATE_CONNECTED) {
		return;
	}
	while (tcp_send(ss) > 0) {
		kcp_recv(ss);
	}
	if (ss->wbuf_navail == 0) {
		return;
	}
	if (ss->w_write != NULL && !ev_is_active(ss->w_write)) {
		ev_io_start(ss->server->loop, ss->w_write);
	}
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

	if (ss->wbuf_navail == 0) {
		kcp_recv(ss);
	}
	if (ss->wbuf_navail > 0) {
		tcp_send(ss);
	} else {
		/* no more data */
		if (ss->w_write != NULL && ev_is_active(ss->w_write)) {
			ev_io_stop(loop, ss->w_write);
		}
	}
}
