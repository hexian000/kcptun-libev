#include "event.h"
#include "event_impl.h"
#include "hashtable.h"
#include "server.h"
#include "pktqueue.h"
#include "slog.h"
#include "sockutil.h"

#include "util.h"
#include <ev.h>

#include <inttypes.h>

static void accept_one(
	struct server *restrict s, const int fd,
	const struct sockaddr *client_sa)
{
	/* Initialize and start watcher to read client requests */
	struct session *restrict ss;
	const struct sockaddr *sa = s->conf->pkt_connect.sa;
	uint32_t conv = conv_new(s, sa);
	ss = session_new(s, sa, conv);
	if (ss == NULL) {
		LOGE("accept: out of memory");
		close(fd);
		return;
	}
	if (!kcp_dial(ss)) {
		LOGE("kcp_dial: unexpected failure");
		close(fd);
		session_free(ss);
		return;
	}
	hashkey_t key;
	conv_make_key(&key, sa, conv);
	table_set(s->sessions, &key, ss);
	ss->state = STATE_CONNECTED;
	if (LOGLEVEL(LOG_LEVEL_INFO)) {
		char addr_str[64];
		format_sa(client_sa, addr_str, sizeof(addr_str));
		LOGI_F("session [%08" PRIX32 "] open: "
		       "tcp accepted from %s",
		       conv, addr_str);
	}
	session_start(ss, fd);
}

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct server *restrict s = watcher->data;
	struct config *restrict cfg = s->conf;
	sockaddr_max_t m_sa;
	socklen_t sa_len = sizeof(m_sa);
	int client_fd;

	while (true) {
		sa_len = sizeof(m_sa);
		// Accept client request
		client_fd = accept(watcher->fd, &m_sa.sa, &sa_len);
		if (client_fd < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == EINTR || errno == ENOMEM) {
				break;
			}
			LOGE_PERROR("accept");
			return;
		}
		if (table_size(s->sessions) >= MAX_SESSIONS) {
			close(client_fd);
			LOG_RATELIMITED(
				LOG_LEVEL_ERROR, loop, 1.0,
				"* max session count exceeded, new connections refused");
			return;
		}
		if (socket_setup(client_fd)) {
			LOGE_PERROR("fcntl");
			close(client_fd);
			return;
		}
		socket_set_tcp(client_fd, cfg->tcp_nodelay, cfg->tcp_keepalive);
		socket_set_buffer(client_fd, cfg->tcp_sndbuf, cfg->tcp_rcvbuf);

		accept_one((struct server *)watcher->data, client_fd, &m_sa.sa);
	}
}

#define TLV_MAX_LENGTH (SESSION_BUF_SIZE - MAX_PACKET_SIZE)

static size_t tcp_recv(struct session *restrict ss)
{
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
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == EINTR || errno == ENOMEM) {
				break;
			}
			const int err = errno;
			LOGE_F("session [%08" PRIX32 "] close: "
			       "tcp recv error on fd %d: [%d] %s",
			       ss->conv, ss->tcp_fd, err, strerror(err));
			session_shutdown(ss);
			kcp_reset(ss);
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
		       ss->conv, len, cap);
	}

	if (tcp_eof) {
		LOGI_F("session [%08" PRIX32 "] close: tcp closing", ss->conv);
		// Stop and free session if client socket is closing
		session_shutdown(ss);
		kcp_close(ss);
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
			ev_io_stop(loop, watcher);
		}
	}
	kcp_notify(ss);
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
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ||
		    errno == ENOMEM) {
			return 0;
		}
		const int err = errno;
		LOGE_F("session [%08" PRIX32 "] close: "
		       "tcp send error on fd %d: [%d] %s",
		       ss->conv, ss->tcp_fd, err, strerror(err));
		session_shutdown(ss);
		kcp_reset(ss);
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
	       ss->conv, nsend, len - (size_t)nsend + ss->wbuf_len);
	return (size_t)nsend;
}

void tcp_notify_write(struct session *restrict ss)
{
	if (ss->tcp_fd == -1) {
		return;
	}
	if (ss->state != STATE_CONNECTED) {
		return;
	}
	while (tcp_send(ss) > 0) {
		kcp_recv(ss);
	}
	if (ss->wbuf_navail == 0) {
		return;
	}
	struct ev_io *restrict w_write = &ss->w_write;
	if (!ev_is_active(w_write)) {
		ev_io_start(ss->server->loop, w_write);
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
		struct ev_io *restrict w_read = &ss->w_read;
		ev_io_start(loop, w_read);
		LOGD_F("session [%08" PRIX32 "] tcp connected", ss->conv);
	}

	if (ss->wbuf_navail == 0) {
		kcp_recv(ss);
	}
	if (ss->wbuf_navail > 0) {
		tcp_send(ss);
	} else {
		/* no more data */
		if (ss->tcp_fd != -1) {
			ev_io_stop(loop, watcher);
		}
	}
}
