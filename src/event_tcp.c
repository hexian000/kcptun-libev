/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"
#include "event.h"
#include "pktqueue.h"
#include "server.h"
#include "session.h"
#include "sockutil.h"
#include "util.h"

#include "algo/hashtable.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void modify_io_events(
	struct ev_loop *loop, ev_io *restrict watcher, const int events)
{
	const int fd = watcher->fd;
	ASSERT(fd != -1);
	const int ioevents = events & (EV_READ | EV_WRITE);
	if (ioevents == 0) {
		if (ev_is_active(watcher)) {
			LOGV_F("[fd:%d] io stop", fd);
			ev_io_stop(loop, watcher);
		}
		return;
	}
	if (ioevents != (watcher->events & (EV_READ | EV_WRITE))) {
		ev_io_stop(loop, watcher);
#ifdef ev_io_modify
		ev_io_modify(watcher, ioevents);
#else
		ev_io_set(watcher, fd, ioevents);
#endif
	}
	if (!ev_is_active(watcher)) {
		LOGV_F("[fd:%d] modified io events=0x%x", fd, ioevents);
		ev_io_start(loop, watcher);
	}
}

static void accept_one(
	struct server *restrict s, const int fd,
	const struct sockaddr *restrict client_sa)
{
	/* Initialize and start watcher to read client requests */
	const uint32_t conv = conv_new(s, &s->pkt.kcp_connect.sa);
	struct session *restrict ss = session_new(s, &s->pkt.kcp_connect, conv);
	if (ss == NULL) {
		LOGOOM();
		CLOSE_FD(fd);
		return;
	}
	ss->kcp_state = KCP_STATE_CONNECT;
	ss->tcp_state = TCP_STATE_ESTABLISHED;
	if (!kcp_sendmsg(ss, SMSG_DIAL)) {
		LOGOOM();
		CLOSE_FD(fd);
		session_free(ss);
		return;
	}
	void *elem = ss;
	s->sessions = table_set(s->sessions, SESSION_GETKEY(ss), &elem);
	ASSERT(elem == NULL);
	if (LOGLEVEL(INFO)) {
		char addr_str[64];
		format_sa(addr_str, sizeof(addr_str), client_sa);
		LOG_F(INFO, "[session:%08" PRIX32 "] tcp: accepted %s", conv,
		      addr_str);
	}
	session_tcp_start(ss, fd);
}

void tcp_accept_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);

	struct server *restrict s = watcher->data;
	const struct config *restrict conf = s->conf;

	for (;;) {
		union sockaddr_max addr;
		socklen_t addrlen = sizeof(addr);
		/* accept client request */
		const int fd = accept(watcher->fd, &addr.sa, &addrlen);
		if (fd < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			LOGE_F("accept: (%d) %s", err, strerror(err));
			/* sleep for a while, see listener_cb */
			ev_io_stop(loop, watcher);
			ev_timer *restrict w_timer = &s->listener.w_timer;
			if (!ev_is_active(w_timer)) {
				ev_timer_start(loop, w_timer);
			}
			return;
		}
		if (table_size(s->sessions) >= MAX_SESSIONS) {
			LOG_RATELIMITED(
				ERROR, ev_now(loop), 1.0,
				"* max session count exceeded, new connections refused");
			CLOSE_FD(fd);
			return;
		}
		if (!socket_set_nonblock(fd)) {
			LOG_PERROR("fcntl");
			CLOSE_FD(fd);
			return;
		}
		socket_set_tcp(fd, conf->tcp_nodelay, conf->tcp_keepalive);
		socket_set_buffer(fd, conf->tcp_sndbuf, conf->tcp_rcvbuf);

		if (!s->pkt.connected) {
			LOGE("packet connection is not ready, refusing");
			CLOSE_FD(fd);
			return;
		}
		accept_one(s, fd, &addr.sa);
	}
}

void tcp_notify(struct session *restrict ss)
{
	switch (ss->tcp_state) {
	case TCP_STATE_ESTABLISHED:
	case TCP_STATE_LINGER:
		break;
	default:
		return;
	}
	const bool has_data = (ss->wbuf_flush < ss->wbuf_next);
	if ((ss->tcp_state == TCP_STATE_LINGER) && !has_data) {
		/* TCP write direction finished */
		if (ss->kcp_eof_sent) {
			/* both directions closed, stop TCP */
			session_tcp_stop(ss);
			LOGD_F("[session:%08" PRIX32 "] tcp: close", ss->conv);
			return;
		}
		/* half-close: shutdown TCP write, but keep reading from TCP */
		if (!ss->tcp_eof_sent) {
			LOGD_F("[session:%08" PRIX32 "] tcp: shutdown write",
			       ss->conv);
			const int fd = ss->w_socket.fd;
			if (fd != -1) {
				if (shutdown(fd, SHUT_WR) != 0) {
					const int err = errno;
					LOGW_F("[fd:%d] shutdown: (%d) %s", fd,
					       err, strerror(err));
				}
			}
			ss->tcp_eof_sent = true;
		}
	}
	int events = 0;
	/* keep reading from TCP if:
	 * 1. TCP is ESTABLISHED (not LINGER - in LINGER we only flush wbuf)
	 * 2. we haven't sent EOF to KCP yet
	 * 3. KCP can accept more data */
	if (ss->tcp_state == TCP_STATE_ESTABLISHED && !ss->kcp_eof_sent &&
	    kcp_cansend(ss)) {
		events |= EV_READ;
	}
	if (has_data) {
		events |= EV_WRITE;
	}
	modify_io_events(ss->server->loop, &ss->w_socket, events);
}

/* returns: OK=0, wait=1, closed=-1 */
static int tcp_recv(struct session *restrict ss)
{
	if (!kcp_cansend(ss)) {
		return 1;
	}

	/* reserve some space to encode header in place */
	size_t cap = TLV_MAX_LENGTH - TLV_HEADER_SIZE - ss->rbuf->len;
	if (cap == 0) {
		return 1;
	}

	const int fd = ss->w_socket.fd;
	unsigned char *buf = ss->rbuf->data + TLV_HEADER_SIZE + ss->rbuf->len;
	size_t len = 0;
	/* Receive message from client socket */
	const ssize_t nread = recv(fd, buf, cap, 0);
	if (nread < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return 1;
		}
		LOGE_F("[session:%08" PRIX32 "] tcp recv: (%d) %s", ss->conv,
		       err, strerror(err));
		return -1;
	}
	if (nread == 0) {
		LOGI_F("[session:%08" PRIX32 "] tcp: "
		       "connection closed by peer",
		       ss->conv);
		return -1;
	}
	cap -= nread, len += nread;
	ss->rbuf->len += len;

	if (len > 0) {
		ss->stats.tcp_rx += len;
		ss->server->stats.tcp_rx += len;
		LOGV_F("[session:%08" PRIX32 "] "
		       "tcp fd=%d: recv %zu bytes, cap: %zu bytes",
		       ss->conv, fd, len, cap);
	}
	return 0;
}

static void tcp_recv_all(struct session *restrict ss)
{
	switch (ss->tcp_state) {
	case TCP_STATE_ESTABLISHED:
		break;
	default:
		return;
	}
	if (ss->kcp_eof_sent) {
		/* already sent EOF to KCP, stop reading from TCP */
		modify_io_events(
			ss->server->loop, &ss->w_socket,
			(ss->wbuf_flush < ss->wbuf_next) ? EV_WRITE : 0);
		return;
	}
	int ret;
	do {
		ret = tcp_recv(ss);
		if (!session_kcp_send(ss)) {
			session_tcp_stop(ss);
			session_kcp_close(ss);
			return;
		}
	} while (ret == 0);
	if (ret < 0) {
		/* TCP peer closed or error: send EOF to KCP (half-close) */
		session_kcp_close(ss);
		/* mark as sent even if kcp_close didn't send (e.g. KCP already closed)
		 * to prevent busy-loop on readable socket after peer close */
		ss->kcp_eof_sent = true;
		/* check if we should close TCP too */
		if (ss->kcp_eof_recv) {
			session_tcp_stop(ss);
		}
	}
}

/* returns: OK=0, wait=1, closed=-1 */
static int tcp_send(struct session *restrict ss)
{
	ASSERT(ss->wbuf_next >= ss->wbuf_flush);
	const size_t len = ss->wbuf_next - ss->wbuf_flush;
	if (len == 0) {
		return 1;
	}

	const int fd = ss->w_socket.fd;
	unsigned char *buf = ss->wbuf->data + ss->wbuf_flush;
	const ssize_t ret = send(fd, buf, len, 0);
	if (ret < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return 1;
		}
		LOGE_F("[session:%08" PRIX32 "] tcp send: (%d) %s", ss->conv,
		       err, strerror(err));
		return -1;
	}
	if (ret == 0) {
		return 1;
	}
	ASSERT(ret <= INT_MAX);
	ss->wbuf_flush += (size_t)ret;
	ss->stats.tcp_tx += (uintmax_t)ret;
	ss->server->stats.tcp_tx += (uintmax_t)ret;
	LOGV_F("[session:%08" PRIX32 "] tcp [fd:%d]: "
	       "send %zd/%zu bytes",
	       ss->conv, fd, ret, len);
	if ((size_t)ret < len) {
		return 0;
	}
	return 1;
}

static void connected_cb(struct session *restrict ss)
{
	const int fd = ss->w_socket.fd;
	const int sockerr = socket_get_error(fd);
	if (sockerr != 0) {
		LOGE_F("connect: (%d) %s", sockerr, strerror(sockerr));
		session_tcp_stop(ss);
		session_kcp_close(ss);
		return;
	}

	ss->tcp_state = TCP_STATE_ESTABLISHED;
	LOGD_F("[session:%08" PRIX32 "] tcp [fd:%d] connected", ss->conv, fd);
}

void tcp_flush(struct session *restrict ss)
{
	switch (ss->tcp_state) {
	case TCP_STATE_ESTABLISHED:
	case TCP_STATE_LINGER:
		break;
	default:
		return;
	}
	int ret;
	do {
		ret = tcp_send(ss);
	} while (ret == 0);
	if (ret < 0) {
		session_tcp_stop(ss);
		session_kcp_close(ss);
	}
}

void tcp_socket_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	UNUSED(loop);
	CHECK_REVENTS(revents, EV_READ | EV_WRITE);

	LOGVV_F("[fd:%d] io revents=0x%x", watcher->fd, revents);
	struct session *restrict ss = watcher->data;
	if (ss->tcp_state == TCP_STATE_CONNECT) {
		connected_cb(ss);
	}

	if (revents & EV_READ) {
		tcp_recv_all(ss);
	}

	if (revents & EV_WRITE) {
		tcp_flush(ss);
		if (ss->tcp_state == TCP_STATE_ESTABLISHED &&
		    ss->wbuf_flush == ss->wbuf_next) {
			session_read_cb(ss);
			return;
		}
	}

	tcp_notify(ss);
}
