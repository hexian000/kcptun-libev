/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "event.h"
#include "event_impl.h"
#include "utils/hashtable.h"
#include "utils/slog.h"
#include "server.h"
#include "pktqueue.h"
#include "session.h"
#include "util.h"
#include "sockutil.h"

#include <ev.h>

#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <limits.h>

static void accept_one(
	struct server *restrict s, const int fd,
	const struct sockaddr *client_sa)
{
	/* Initialize and start watcher to read client requests */
	struct session *restrict ss;
	const struct sockaddr *sa = s->conf->kcp_connect.sa;
	uint32_t conv = conv_new(s, sa);
	ss = session_new(s, sa, conv);
	if (ss == NULL) {
		LOGOOM();
		if (close(fd) != 0) {
			const int err = errno;
			LOGW_F("close: %s", strerror(err));
		}
		return;
	}
	ss->kcp_state = STATE_CONNECT;
	ss->tcp_state = STATE_CONNECTED;
	if (!kcp_sendmsg(ss, SMSG_DIAL)) {
		LOGOOM();
		if (close(fd) != 0) {
			const int err = errno;
			LOGW_F("close: %s", strerror(err));
		}
		session_free(ss);
		return;
	}
	hashkey_t key;
	conv_make_key(&key, sa, conv);
	table_set(s->sessions, &key, ss);
	if (LOGLEVEL(LOG_LEVEL_INFO)) {
		char addr_str[64];
		format_sa(client_sa, addr_str, sizeof(addr_str));
		LOGI_F("session [%08" PRIX32 "] tcp: accepted %s", conv,
		       addr_str);
	}
	session_start(ss, fd);
}

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct server *restrict s = watcher->data;
	struct config *restrict conf = s->conf;
	sockaddr_max_t m_sa;
	socklen_t sa_len = sizeof(m_sa);
	int client_fd;

	for (;;) {
		sa_len = sizeof(m_sa);
		/* accept client request */
		client_fd = accept(watcher->fd, &m_sa.sa, &sa_len);
		if (client_fd < 0) {
			const int err = errno;
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == EINTR || err == ENOMEM) {
				break;
			}
			LOGE_F("accept: %s", strerror(err));
			/* sleep until next timer, see timer_cb */
			ev_io_stop(loop, watcher);
			return;
		}
		if (table_size(s->sessions) >= MAX_SESSIONS) {
			if (close(client_fd) != 0) {
				const int err = errno;
				LOGW_F("close: %s", strerror(err));
			}
			LOG_RATELIMITED(
				LOG_LEVEL_ERROR, loop, 1.0,
				"* max session count exceeded, new connections refused");
			return;
		}
		if (!socket_set_nonblock(client_fd)) {
			const int err = errno;
			LOGE_F("fcntl: %s", strerror(err));
			(void)close(client_fd);
			return;
		}
		socket_set_tcp(
			client_fd, conf->tcp_nodelay, conf->tcp_keepalive);
		socket_set_buffer(
			client_fd, conf->tcp_sndbuf, conf->tcp_rcvbuf);

		accept_one((struct server *)watcher->data, client_fd, &m_sa.sa);
	}
}

enum tcp_recv_ret {
	TCPRECV_OK,
	TCPRECV_AGAIN,
	TCPRECV_EOF,
	TCPRECV_ERROR,
};

static int tcp_recv(struct session *restrict ss)
{
	/* reserve some space to encode header in place */
	size_t cap = TLV_MAX_LENGTH - TLV_HEADER_SIZE - ss->rbuf_len;
	if (cap == 0) {
		return TCPRECV_OK;
	}

	unsigned char *buf = ss->rbuf + TLV_HEADER_SIZE + ss->rbuf_len;
	size_t len = 0;
	/* Receive message from client socket */
	const ssize_t nread = recv(ss->tcp_fd, buf, cap, 0);
	if (nread < 0) {
		const int err = errno;
		if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR ||
		    err == ENOMEM) {
			return TCPRECV_AGAIN;
		}
		if (err == ECONNREFUSED || err == ECONNRESET) {
			LOGD_F("session [%08" PRIX32 "] tcp recv: %s", ss->conv,
			       strerror(err));
			return TCPRECV_ERROR;
		}
		LOGE_F("session [%08" PRIX32 "] tcp recv: %s", ss->conv,
		       strerror(err));
		return TCPRECV_ERROR;
	} else if (nread == 0) {
		return TCPRECV_EOF;
	} else {
		cap -= nread, len += nread;
		ss->rbuf_len += len;
	}

	if (len > 0) {
		ss->stats.tcp_rx += len;
		ss->server->stats.tcp_rx += len;
		LOGV_F("session [%08" PRIX32 "] "
		       "tcp recv: %zu bytes, cap: %zu bytes",
		       ss->conv, len, cap);
	}
	return TCPRECV_OK;
}

void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);
	struct session *restrict ss = (struct session *)watcher->data;
	assert(watcher == &ss->w_read);
	assert(watcher->fd == ss->tcp_fd);

	while (ss->tcp_fd != -1 && ikcp_waitsnd(ss->kcp) < ss->kcp->snd_wnd) {
		switch (tcp_recv(ss)) {
		case TCPRECV_OK:
			break;
		case TCPRECV_AGAIN:
			return;
		case TCPRECV_EOF:
			ss->tcp_state = STATE_LINGER;
			LOGI_F("session [%08" PRIX32 "] tcp: "
			       "connection closed by peer",
			       ss->conv);
			session_stop(ss);
			if (!session_send(ss)) {
				kcp_reset(ss);
			}
			return;
		case TCPRECV_ERROR:
			session_stop(ss);
			kcp_reset(ss);
			return;
		}
		if (!session_send(ss)) {
			session_stop(ss);
			kcp_reset(ss);
			return;
		}
	}
	ev_io_stop(loop, watcher);
}

static int tcp_flush(struct session *restrict ss)
{
	assert(ss->wbuf_next >= ss->wbuf_flush);
	unsigned char *payload = ss->wbuf;
	unsigned char *buf = payload + ss->wbuf_flush;
	const size_t len = ss->wbuf_next - ss->wbuf_flush;
	int nsend = -1;
	if (len > 0) {
		const ssize_t ret = send(ss->tcp_fd, buf, len, 0);
		if (ret < 0) {
			const int err = errno;
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == EINTR || err == ENOMEM) {
				return 0;
			}
			LOGE_F("session [%08" PRIX32 "] tcp send: %s", ss->conv,
			       strerror(err));
			return -1;
		}
		if (ret > 0) {
			ss->wbuf_flush += ret;
			ss->stats.tcp_tx += ret;
			ss->server->stats.tcp_tx += ret;
			LOGV_F("session [%08" PRIX32 "] tcp: "
			       "send %zd/%zu bytes",
			       ss->conv, ret, len);
		}
		assert(0 <= ret && ret <= INT_MAX);
		nsend = (int)ret;
	}
	return nsend;
}

int tcp_send(struct session *restrict ss)
{
	const int ret = tcp_flush(ss);
	if (ret < 0) {
		return ret;
	}
	if (ss->wbuf_next > ss->wbuf_flush || ss->tcp_state == STATE_LINGER) {
		/* has more data or eof, start write watcher */
		struct ev_io *restrict w_write = &ss->w_write;
		if (!ev_is_active(w_write)) {
			ev_io_start(ss->server->loop, w_write);
		}
	}
	return ret;
}

void write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct session *restrict ss = (struct session *)watcher->data;
	assert(watcher == &ss->w_write);
	assert(watcher->fd == ss->tcp_fd);

	while (ss->tcp_fd != -1 && ss->wbuf_next > ss->wbuf_flush) {
		const int ret = tcp_flush(ss);
		if (ret < 0) {
			session_stop(ss);
			kcp_reset(ss);
			return;
		} else if (ret == 0) {
			return;
		}
		if (ss->wbuf_flush == ss->wbuf_next) {
			session_read_cb(ss);
		}
	}

	/* stop write watcher */
	ev_io_stop(loop, watcher);

	if (ss->tcp_state == STATE_LINGER) {
		/* no more data, close */
		session_stop(ss);
		LOGD_F("session [%08" PRIX32 "] tcp: send eof", ss->conv);
		ss->tcp_state = STATE_TIME_WAIT;
	}
}
