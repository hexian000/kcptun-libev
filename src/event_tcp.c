/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "event.h"
#include "event_impl.h"
#include "algo/hashtable.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "server.h"
#include "pktqueue.h"
#include "session.h"
#include "util.h"
#include "sockutil.h"

#include <ev.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>

void modify_io_events(
	struct ev_loop *loop, struct ev_io *restrict watcher, const int events)
{
	assert(watcher->fd != -1);
	const int ioevents = events & (EV_READ | EV_WRITE);
	if (ioevents == EV_NONE) {
		if (ev_is_active(watcher)) {
			LOGD_F("io fd=%d stop", watcher->fd);
			ev_io_stop(loop, watcher);
		}
		return;
	}
	if (ioevents != (watcher->events & (EV_READ | EV_WRITE))) {
		LOGD_F("io fd=%d events=0x%x", watcher->fd, ioevents);
#ifdef ev_io_modify
		ev_io_modify(watcher, ioevents);
#else
		ev_io_set(watcher, watcher->fd, ioevents);
#endif
		ev_io_stop(loop, watcher);
	}
	if (!ev_is_active(watcher)) {
		LOGD_F("io fd=%d start", watcher->fd);
		ev_io_start(loop, watcher);
	}
}

static void accept_one(
	struct server *restrict s, const int fd,
	const struct sockaddr *client_sa)
{
	/* Initialize and start watcher to read client requests */
	struct session *restrict ss;
	const struct sockaddr *sa = &s->pkt.kcp_connect.sa;
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
	table_set(s->sessions, (hashkey_t *)&ss->key, ss);
	if (LOGLEVEL(LOG_LEVEL_INFO)) {
		char addr_str[64];
		format_sa(client_sa, addr_str, sizeof(addr_str));
		LOG_F(LOG_LEVEL_INFO,
		      "session [%08" PRIX32 "] tcp: accepted %s", conv,
		      addr_str);
	}
	session_start(ss, fd);
}

void tcp_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct server *restrict s = watcher->data;
	const struct config *restrict conf = s->conf;

	for (;;) {
		sockaddr_max_t addr;
		socklen_t addrlen = sizeof(addr);
		/* accept client request */
		const int fd = accept(watcher->fd, &addr.sa, &addrlen);
		if (fd < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			LOGE_F("accept: %s", strerror(err));
			/* sleep for a while, see listener_cb */
			ev_io_stop(loop, watcher);
			struct ev_timer *restrict w_timer =
				&s->listener.w_timer;
			if (!ev_is_active(w_timer)) {
				ev_timer_start(loop, w_timer);
			}
			return;
		}
		if (table_size(s->sessions) >= MAX_SESSIONS) {
			if (close(fd) != 0) {
				const int err = errno;
				LOGW_F("close: %s", strerror(err));
			}
			LOG_RATELIMITED(
				LOG_LEVEL_ERROR, ev_now(loop), 1.0,
				"* max session count exceeded, new connections refused");
			return;
		}
		if (!socket_set_nonblock(fd)) {
			const int err = errno;
			LOGE_F("fcntl: %s", strerror(err));
			(void)close(fd);
			return;
		}
		socket_set_tcp(fd, conf->tcp_nodelay, conf->tcp_keepalive);
		socket_set_buffer(fd, conf->tcp_sndbuf, conf->tcp_rcvbuf);

		accept_one(s, fd, &addr.sa);
	}
}

static void tcp_update(struct session *restrict ss)
{
	assert(ss->tcp_fd != -1);
	const bool is_linger = (ss->tcp_state == STATE_LINGER);
	const bool has_data = (ss->wbuf_flush < ss->wbuf_next);
	if (is_linger && !has_data) {
		/* finish this connection gracefully */
		session_tcp_stop(ss);
		LOGD_F("session [%08" PRIX32 "] tcp: send eof", ss->conv);
		return;
	}
	int events = 0;
	if (ss->kcp != NULL && ikcp_waitsnd(ss->kcp) < ss->kcp->snd_wnd) {
		events |= EV_READ;
	}
	if (is_linger || has_data) {
		events |= EV_WRITE;
	}
	modify_io_events(ss->server->loop, &ss->w_socket, events);
}

enum tcp_recv_ret {
	TCPRECV_OK,
	TCPRECV_AGAIN,
	TCPRECV_EOF,
	TCPRECV_ERROR,
};

static int tcp_recv(struct session *restrict ss)
{
	if (ikcp_waitsnd(ss->kcp) >= ss->kcp->snd_wnd) {
		return TCPRECV_AGAIN;
	}

	/* reserve some space to encode header in place */
	size_t cap = TLV_MAX_LENGTH - TLV_HEADER_SIZE - ss->rbuf->len;
	if (cap == 0) {
		return TCPRECV_AGAIN;
	}

	unsigned char *buf = ss->rbuf->data + TLV_HEADER_SIZE + ss->rbuf->len;
	size_t len = 0;
	/* Receive message from client socket */
	const ssize_t nread = recv(ss->tcp_fd, buf, cap, 0);
	if (nread < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return TCPRECV_AGAIN;
		}
		LOGE_F("session [%08" PRIX32 "] tcp recv: %s", ss->conv,
		       strerror(err));
		return TCPRECV_ERROR;
	}
	if (nread == 0) {
		return TCPRECV_EOF;
	}
	cap -= nread, len += nread;
	ss->rbuf->len += len;

	if (len > 0) {
		ss->stats.tcp_rx += len;
		ss->server->stats.tcp_rx += len;
		LOGV_F("session [%08" PRIX32 "] "
		       "tcp fd=%d: recv %zu bytes, cap: %zu bytes",
		       ss->conv, ss->tcp_fd, len, cap);
	}
	return TCPRECV_OK;
}

static void tcp_recv_all(struct session *restrict ss)
{
	int ret;
	for (;;) {
		ret = tcp_recv(ss);
		if (!session_kcp_send(ss)) {
			session_tcp_stop(ss);
			kcp_reset(ss);
			return;
		}
		if (ret != TCPRECV_OK) {
			break;
		}
	}

	switch (ret) {
	case TCPRECV_AGAIN:
		break;
	case TCPRECV_EOF:
		LOGI_F("session [%08" PRIX32 "] tcp: "
		       "connection closed by peer",
		       ss->conv);
		session_tcp_stop(ss);
		if (!session_kcp_send(ss)) {
			kcp_reset(ss);
			return;
		}
		session_kcp_close(ss);
		return;
	case TCPRECV_ERROR:
		session_tcp_stop(ss);
		kcp_reset(ss);
		return;
	default:
		FAIL();
	}
}

void tcp_notify_recv(struct session *restrict ss)
{
	if (ss->tcp_state != STATE_CONNECTED) {
		return;
	}
	tcp_update(ss);
}

static int tcp_send(struct session *restrict ss)
{
	assert(ss->wbuf_next >= ss->wbuf_flush);
	unsigned char *buf = ss->wbuf->data + ss->wbuf_flush;
	const size_t len = ss->wbuf_next - ss->wbuf_flush;
	if (len == 0) {
		return 0;
	}
	const ssize_t ret = send(ss->tcp_fd, buf, len, 0);
	if (ret < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return 0;
		}
		LOGE_F("session [%08" PRIX32 "] tcp send: %s", ss->conv,
		       strerror(err));
		return -1;
	} else if (ret == 0) {
		return 0;
	}
	assert(ret <= INT_MAX);
	ss->wbuf_flush += (size_t)ret;
	ss->stats.tcp_tx += (uintmax_t)ret;
	ss->server->stats.tcp_tx += (uintmax_t)ret;
	LOGV_F("session [%08" PRIX32 "] tcp fd=%d: "
	       "send %zd/%zu bytes",
	       ss->conv, ss->tcp_fd, ret, len);
	return 1;
}

static void tcp_flush(struct session *restrict ss)
{
	switch (ss->tcp_state) {
	case STATE_CONNECT:
	case STATE_CONNECTED:
	case STATE_LINGER:
		break;
	default:
		return;
	}
	for (;;) {
		const int ret = tcp_send(ss);
		if (ret < 0) {
			session_tcp_stop(ss);
			kcp_reset(ss);
			return;
		} else if (ret == 0) {
			/* wait next event */
			break;
		}
	}
}

void tcp_notify_send(struct session *restrict ss)
{
	tcp_flush(ss);
	if (ss->tcp_fd == -1) {
		return;
	}
	tcp_update(ss);
}

static void connected_cb(struct session *restrict ss)
{
	int sockerr = 0;
	if (getsockopt(
		    ss->tcp_fd, SOL_SOCKET, SO_ERROR, &sockerr,
		    &(socklen_t){ sizeof(sockerr) }) == 0) {
		if (sockerr != 0) {
			LOGE_F("SO_ERROR: %s", strerror(sockerr));
			session_tcp_stop(ss);
			kcp_reset(ss);
			return;
		}
	} else {
		const int err = errno;
		LOGD_F("SO_ERROR: %s", strerror(err));
	}

	ss->tcp_state = STATE_CONNECTED;
	LOGD_F("session [%08" PRIX32 "] tcp fd=%d: connected", ss->conv,
	       ss->tcp_fd);
	return;
}

void tcp_socket_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	UNUSED(loop);
	CHECK_EV_ERROR(revents);

	LOGD_F("io fd=%d revents=0x%x", watcher->fd, revents);
	struct session *restrict ss = watcher->data;
	if (ss->tcp_state == STATE_CONNECT) {
		connected_cb(ss);
		if (ss->tcp_fd == -1) {
			return;
		}
	}

	if (revents & EV_WRITE) {
		tcp_flush(ss);
		if (ss->tcp_fd == -1) {
			return;
		}
		if (ss->wbuf_flush == ss->wbuf_next) {
			session_read_cb(ss);
			if (ss->tcp_fd == -1) {
				return;
			}
		}
	}

	if (revents & EV_READ) {
		tcp_recv_all(ss);
		if (ss->tcp_fd == -1) {
			return;
		}
	}

	tcp_update(ss);
}
