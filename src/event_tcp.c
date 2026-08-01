/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"
#include "event.h"
#include "pktqueue.h"
#include "server.h"
#include "session.h"
#include "util.h"

#include "algo/hashtable.h"
#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

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
		socket_close(fd);
		return;
	}
	ss->kcp_state = KCP_STATE_CONNECT;
	ss->tcp_state = TCP_STATE_ESTABLISHED;
	if (!kcp_sendmsg(ss, SMSG_DIAL)) {
		/* kcp_send already logs the actual failure reason */
		socket_close(fd);
		session_free(ss);
		return;
	}
	void *elem = ss;
	s->sessions = table_set(s->sessions, SESSION_GETKEY(ss), &elem);
	if (elem != NULL) {
		/* table_set leaves the new element in place on allocation
		   failure; ss was not inserted */
		LOGOOM();
		socket_close(fd);
		session_free(ss);
		return;
	}
	if (LOGLEVEL(INFO)) {
		char addr_str[64];
		sa_format(addr_str, sizeof(addr_str), client_sa);
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
			if (err == EINTR) {
				continue;
			}
			if (err == EAGAIN || err == EWOULDBLOCK) {
				break;
			}
			accept_backoff(
				loop, watcher, &s->listener.w_timer, err);
			return;
		}
		if (table_size(s->sessions) >= MAX_SESSIONS) {
			LOG_RATELIMITED(
				ERROR, ev_now(loop), 1.0,
				"max sessions reached, refusing new connection");
			socket_close(fd);
			return;
		}
		if (!socket_nonblock_or_close(fd)) {
			return;
		}
		tcp_apply_conf(fd, conf);

		if (!s->pkt.connected) {
			LOGE("packet connection not ready, refusing");
			socket_close(fd);
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
	/* Receive message from client socket */
	ssize_t nread;
	int err;
	do {
		nread = recv(fd, buf, cap, 0);
		err = errno;
	} while (nread < 0 && err == EINTR);
	if (nread < 0) {
		if (err == EAGAIN || err == EWOULDBLOCK) {
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
	cap -= (size_t)nread;
	ss->rbuf->len += (size_t)nread;

	ss->stats.tcp_rx += (uint_least64_t)nread;
	ss->server->stats.tcp_rx += (uint_least64_t)nread;
	LOGV_F("[session:%08" PRIX32 "] tcp [fd:%d]: "
	       "recv %zu bytes, cap: %zu bytes",
	       ss->conv, fd, (size_t)nread, cap);
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
	ssize_t ret;
	int err;
	do {
		ret = send(fd, buf, len, 0);
		err = errno;
	} while (ret < 0 && err == EINTR);
	if (ret < 0) {
		if (err == EAGAIN || err == EWOULDBLOCK) {
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
	ss->stats.tcp_tx += (uint_least64_t)ret;
	ss->server->stats.tcp_tx += (uint_least64_t)ret;
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
		LOGE_F("[session:%08" PRIX32 "] tcp connect: (%d) %s", ss->conv,
		       sockerr, strerror(sockerr));
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
