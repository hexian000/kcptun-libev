/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "session.h"

#include "conf.h"
#include "event.h"
#include "pktqueue.h"
#include "server.h"
#include "util.h"

#include "algo/hashtable.h"
#include "ikcp.h"
#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

static bool fail_connect;
static ikcpcb *peer;
static unsigned char peerbuf[1024];
static size_t peerlen;

static int test_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	if (fail_connect) {
		fail_connect = false;
		errno = ENETUNREACH;
		return -1;
	}
	return connect(fd, addr, len);
}

#define connect(fd, addr, len) test_connect(fd, addr, len)
#include "session.c"
#undef connect

static const struct config conf = {
	.mode = MODE_SERVER,
	.kcp_mtu = 1400,
	.kcp_sndwnd = 128,
	.kcp_rcvwnd = 128,
	.kcp_nodelay = 1,
	.kcp_interval = 10,
	.kcp_nc = 1,
	.timeout = 60,
	.linger = 10,
	.keepalive = 20,
	.time_wait = 5,
};

static struct server *new_server(void)
{
	struct ev_loop *loop = ev_loop_new(0);
	CHECK(loop != NULL);
	struct server *s = server_new(loop, &conf);
	CHECK(s != NULL);
	/* No UDP transport is started in this fixture. */
	s->pkt.queue->mss = conf.kcp_mtu;
	return s;
}

static void free_server(struct server *s)
{
	struct ev_loop *loop = s->loop;
	server_free(s);
	ev_loop_destroy(loop);
}

static struct session *new_session(struct server *s)
{
	const union sockaddr_max addr = {
		.in = { .sin_family = AF_INET, .sin_port = 1234 },
	};
	struct session *ss = session_new(s, &addr, 123);
	CHECK(ss != NULL);
	ss->kcp_state = KCP_STATE_ESTABLISHED;
	void *element = ss;
	s->sessions = table_set(s->sessions, SESSION_GETKEY(ss), &element);
	CHECK(element == NULL);
	return ss;
}

static int to_peer(const char *buf, int len, ikcpcb *kcp, void *user)
{
	(void)kcp;
	(void)user;
	CHECK(ikcp_input(peer, buf, len) == 0);
	return len;
}

static int to_session(const char *buf, int len, ikcpcb *kcp, void *user)
{
	(void)kcp;
	struct session *ss = user;
	CHECK(ikcp_input(ss->kcp, buf, len) == 0);
	return len;
}

static void attach_peer(struct session *ss)
{
	CHECK(peer == NULL);
	peer = ikcp_create(ss->conv, ss);
	CHECK(peer != NULL);
	CHECK(ikcp_nodelay(peer, 1, 10, 2, 1) == 0);
	ikcp_setoutput(peer, to_session);
	ikcp_setoutput(ss->kcp, to_peer);
	ikcp_update(peer, 100);
	ikcp_update(ss->kcp, 100);
}

static void detach_peer(void)
{
	CHECK(peerlen == 0);
	CHECK(ikcp_peeksize(peer) < 0);
	ikcp_release(peer);
	peer = NULL;
}

static void enqueue_frame(uint16_t what, const char *payload)
{
	unsigned char buf[256];
	const size_t len = payload == NULL ? 0 : strlen(payload);
	CHECK(len + TLV_HEADER_SIZE <= sizeof(buf));
	tlv_header_write(
		buf, (struct tlv_header){
			     .msg = what,
			     .len = (uint16_t)(TLV_HEADER_SIZE + len),
		     });
	if (len > 0) {
		memcpy(buf + TLV_HEADER_SIZE, payload, len);
	}
	CHECK(ikcp_send(peer, (const char *)buf, (int)(TLV_HEADER_SIZE + len)) >=
	      0);
}

static void frame(struct session *ss, uint16_t what, const char *payload)
{
	enqueue_frame(what, payload);
	ikcp_flush(peer);
	session_read_cb(ss);
}

static void expect_frame(struct session *ss, uint16_t what, const char *payload)
{
	ikcp_flush(ss->kcp);
	const size_t len = payload == NULL ? 0 : strlen(payload);
	const size_t total = TLV_HEADER_SIZE + len;
	while (peerlen < total) {
		const int n = ikcp_recv(
			peer, (char *)peerbuf + peerlen,
			(int)(sizeof(peerbuf) - peerlen));
		CHECK(n > 0);
		peerlen += (size_t)n;
	}
	const struct tlv_header hdr = tlv_header_read(peerbuf);
	CHECK(hdr.msg == what && hdr.len == total);
	if (len > 0) {
		CHECK(memcmp(peerbuf + TLV_HEADER_SIZE, payload, len) == 0);
	}
	peerlen -= total;
	memmove(peerbuf, peerbuf + total, peerlen);
}

static int attach_socket(struct session *ss)
{
	int fd[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
	CHECK(socket_set_nonblock(fd[0]) == 0);
	CHECK(socket_set_nonblock(fd[1]) == 0);
	ss->tcp_state = TCP_STATE_ESTABLISHED;
	session_tcp_start(ss, fd[0]);
	return fd[1];
}

static void expect_socket(int fd, const char *payload)
{
	CHECK(fd >= 0);
	char buf[256];
	const size_t len = strlen(payload);
	CHECK(recv(fd, buf, sizeof(buf), 0) == (ssize_t)len);
	CHECK(memcmp(buf, payload, len) == 0);
}

static void expect_eof(int fd)
{
	CHECK(fd >= 0);
	char buf;
	CHECK(recv(fd, &buf, 1, 0) == 0);
}

static void send_bytes(struct session *ss, const unsigned char *buf, size_t len)
{
	CHECK(ikcp_send(peer, (const char *)buf, (int)len) >= 0);
	ikcp_flush(peer);
	CHECK(ikcp_peeksize(ss->kcp) > 0);
	session_read_cb(ss);
}

static void expect_no_socket_data(int fd)
{
	CHECK(fd >= 0);
	char byte;
	CHECK(recv(fd, &byte, 1, 0) == -1);
	CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
}

static void fragmented_push(void)
{
	const char payload[] = "split payload";
	unsigned char buf[TLV_HEADER_SIZE + sizeof(payload) - 1];
	tlv_header_write(
		buf,
		(struct tlv_header){ .msg = SMSG_PUSH, .len = sizeof(buf) });
	memcpy(buf + TLV_HEADER_SIZE, payload, sizeof(payload) - 1);
	for (size_t split = 1; split < sizeof(buf); split++) {
		struct server *s = new_server();
		struct session *ss = new_session(s);
		attach_peer(ss);
		const int fd = attach_socket(ss);
		send_bytes(ss, buf, split);
		/* A second read with no new bytes must preserve the partial frame. */
		session_read_cb(ss);
		CHECK(ss->wbuf->len == split && ss->wbuf_off == 0);
		CHECK(ss->wbuf_next == 0 && ss->wbuf_flush == 0);
		CHECK(ss->tcp_state == TCP_STATE_ESTABLISHED);
		CHECK(!ss->kcp_eof_sent && !ss->kcp_eof_recv);
		CHECK(ss->stats.tcp_tx == 0);
		expect_no_socket_data(fd);

		/* The completion and a subsequent frame arrive in the same read. */
		CHECK(ikcp_send(
			      peer, (const char *)buf + split,
			      (int)(sizeof(buf) - split)) >= 0);
		enqueue_frame(SMSG_PUSH, "next");
		ikcp_flush(peer);
		session_read_cb(ss);
		expect_socket(fd, "split payloadnext");
		session_read_cb(ss);
		expect_no_socket_data(fd);
		CHECK(ss->stats.tcp_tx == sizeof(payload) - 1 + strlen("next"));
		CHECK(ss->wbuf->len == 0 && ss->wbuf_off == 0);
		CHECK(ss->wbuf_next == 0 && ss->wbuf_flush == 0);
		CHECK(ikcp_peeksize(ss->kcp) < 0);
		socket_close(fd);
		detach_peer();
		free_server(s);
	}
}

static void fragmented_control(uint16_t what)
{
	unsigned char buf[TLV_HEADER_SIZE];
	tlv_header_write(
		buf, (struct tlv_header){ .msg = what, .len = sizeof(buf) });
	for (size_t split = 1; split < sizeof(buf); split++) {
		struct server *s = new_server();
		s->connect.in.sin_family = AF_INET;
		struct session *ss = new_session(s);
		attach_peer(ss);
		ss->is_accepted = true;
		const int fd = what == SMSG_DIAL ? -1 : attach_socket(ss);
		fail_connect = what == SMSG_DIAL;
		send_bytes(ss, buf, split);
		CHECK(ss->tcp_state == (what == SMSG_DIAL ?
						TCP_STATE_CLOSED :
						TCP_STATE_ESTABLISHED));
		CHECK(!ss->kcp_eof_recv && !ss->kcp_eof_sent);
		CHECK(fail_connect == (what == SMSG_DIAL));
		ikcp_flush(ss->kcp);
		CHECK(ikcp_peeksize(peer) < 0);
		if (fd >= 0) {
			expect_no_socket_data(fd);
		}
		send_bytes(ss, buf + split, sizeof(buf) - split);
		session_read_cb(ss);
		if (what == SMSG_DIAL) {
			CHECK(!fail_connect && ss->kcp_eof_sent);
			CHECK(ss->tcp_state == TCP_STATE_CLOSED);
			expect_frame(ss, SMSG_EOF, NULL);
		} else if (what == SMSG_EOF) {
			CHECK(ss->kcp_eof_recv && ss->tcp_eof_sent);
			CHECK(ss->tcp_state == TCP_STATE_LINGER);
			expect_eof(fd);
		} else {
			CHECK(ss->tcp_state == TCP_STATE_ESTABLISHED);
			CHECK(!ss->kcp_eof_sent && !ss->kcp_eof_recv);
			expect_frame(ss, SMSG_KEEPALIVE, NULL);
			expect_no_socket_data(fd);
		}
		CHECK(ss->wbuf->len == 0 && ss->wbuf_off == 0);
		CHECK(ss->wbuf_next == 0 && ss->wbuf_flush == 0);
		if (fd >= 0) {
			socket_close(fd);
		}
		detach_peer();
		free_server(s);
	}
}

static void push_length_boundaries(void)
{
	struct server *s = new_server();
	struct session *ss = new_session(s);
	attach_peer(ss);
	const int fd = attach_socket(ss);
	frame(ss, SMSG_PUSH, NULL);
	expect_no_socket_data(fd);
	CHECK(ss->tcp_state == TCP_STATE_ESTABLISHED);
	unsigned char buf[TLV_MAX_LENGTH];
	tlv_header_write(
		buf,
		(struct tlv_header){ .msg = SMSG_PUSH, .len = sizeof(buf) });
	for (size_t i = TLV_HEADER_SIZE; i < sizeof(buf); i++) {
		buf[i] = (unsigned char)i;
	}
	send_bytes(ss, buf, sizeof(buf));
	unsigned char received[TLV_MAX_LENGTH - TLV_HEADER_SIZE];
	for (size_t n = 0; n < sizeof(received);) {
		const ssize_t count =
			recv(fd, received + n, sizeof(received) - n, 0);
		CHECK(count > 0);
		n += (size_t)count;
	}
	CHECK(memcmp(received, buf + TLV_HEADER_SIZE, sizeof(received)) == 0);
	CHECK(ss->stats.tcp_tx == sizeof(received));
	frame(ss, SMSG_PUSH, "after maximum");
	expect_socket(fd, "after maximum");
	session_read_cb(ss);
	expect_no_socket_data(fd);
	CHECK(ss->wbuf->len == 0 && ss->wbuf_off == 0);
	socket_close(fd);
	detach_peer();
	free_server(s);
}

static void rejected_frame(uint16_t what, uint16_t length, bool body)
{
	struct server *s = new_server();
	s->connect.in.sin_family = AF_INET;
	struct session *ss = new_session(s);
	attach_peer(ss);
	ss->is_accepted = true;
	const int fd = what == SMSG_DIAL ? -1 : attach_socket(ss);
	fail_connect = what == SMSG_DIAL;
	unsigned char buf[TLV_HEADER_SIZE + 1];
	tlv_header_write(
		buf, (struct tlv_header){ .msg = what, .len = length });
	buf[TLV_HEADER_SIZE] = 'x';
	CHECK(ikcp_send(
		      peer, (const char *)buf,
		      (int)(TLV_HEADER_SIZE + (body ? 1 : 0))) >= 0);
	enqueue_frame(SMSG_KEEPALIVE, NULL);
	enqueue_frame(SMSG_PUSH, "must not be forwarded");
	ikcp_flush(peer);
	session_read_cb(ss);
	CHECK(ss->tcp_state == TCP_STATE_CLOSED && ss->w_socket.fd == -1);
	CHECK(ss->kcp_eof_sent && !ss->kcp_eof_recv);
	CHECK(ss->stats.tcp_tx == 0);
	CHECK(fail_connect == (what == SMSG_DIAL));
	fail_connect = false;
	expect_frame(ss, SMSG_EOF, NULL);
	CHECK(peerlen == 0 && ikcp_peeksize(peer) < 0);
	/* A later callback can consume the successor of a well-framed rejection,
	 * but the aborted local stream must never receive its payload. */
	session_read_cb(ss);
	if (length >= TLV_HEADER_SIZE && length <= TLV_MAX_LENGTH) {
		expect_frame(ss, SMSG_KEEPALIVE, NULL);
	}
	ikcp_flush(ss->kcp);
	CHECK(ikcp_peeksize(peer) < 0);
	CHECK(ss->stats.tcp_tx == 0);
	if (fd >= 0) {
		expect_eof(fd);
		socket_close(fd);
	}
	detach_peer();
	free_server(s);
}

static void malformed_frames(void)
{
	for (size_t length = 0; length < TLV_HEADER_SIZE; length++) {
		rejected_frame(SMSG_PUSH, (uint16_t)length, false);
	}
	rejected_frame(SMSG_PUSH, TLV_MAX_LENGTH + 1, false);
	rejected_frame(SMSG_PUSH, UINT16_MAX, false);
	rejected_frame(SMSG_DIAL, TLV_HEADER_SIZE + 1, true);
	rejected_frame(SMSG_EOF, TLV_HEADER_SIZE + 1, true);
	rejected_frame(SMSG_KEEPALIVE, TLV_HEADER_SIZE + 1, true);
	rejected_frame(SMSG_KEEPALIVE + 1, TLV_HEADER_SIZE, false);
	rejected_frame(UINT16_MAX, TLV_HEADER_SIZE, false);
}

static void half_close(bool remote_first)
{
	struct server *s = new_server();
	struct session *ss = new_session(s);
	attach_peer(ss);
	const int fd = attach_socket(ss);
	frame(ss, SMSG_PUSH, "request");
	expect_socket(fd, "request");
	if (remote_first) {
		frame(ss, SMSG_EOF, NULL);
		CHECK(ss->tcp_state == TCP_STATE_LINGER);
		CHECK(ss->tcp_eof_sent && !ss->kcp_eof_sent);
		CHECK(ss->w_socket.events & EV_READ);
		expect_eof(fd);
		/* Repeated EOF is idempotent and must preserve the read direction. */
		frame(ss, SMSG_EOF, NULL);
	}
	CHECK(send(fd, "response", 8, 0) == 8);
	CHECK(shutdown(fd, SHUT_WR) == 0);
	tcp_socket_cb(s->loop, &ss->w_socket, EV_READ);
	expect_frame(ss, SMSG_PUSH, "response");
	expect_frame(ss, SMSG_EOF, NULL);
	if (!remote_first) {
		CHECK(ss->tcp_state == TCP_STATE_ESTABLISHED);
		CHECK(ss->w_socket.fd >= 0);
		CHECK(!(ss->w_socket.events & EV_READ) ||
		      !ev_is_active(&ss->w_socket));
		frame(ss, SMSG_PUSH, "after local eof");
		expect_socket(fd, "after local eof");
		frame(ss, SMSG_EOF, NULL);
	}
	CHECK(ss->kcp_state == KCP_STATE_LINGER);
	CHECK(ss->tcp_state == TCP_STATE_CLOSED && ss->w_socket.fd == -1);
	expect_eof(fd);
	CHECK(ss->stats.tcp_rx == 8);
	CHECK(ss->last_payload_send == ev_now(s->loop));
	socket_close(fd);
	detach_peer();
	free_server(s);
}

static void pending_output(void)
{
	struct server *s = new_server();
	struct session *ss = new_session(s);
	attach_peer(ss);
	const int fd = attach_socket(ss);
	const int size = 1024;
	CHECK(setsockopt(
		      ss->w_socket.fd, SOL_SOCKET, SO_SNDBUF, &size,
		      sizeof(size)) == 0);
	char buf[1024];
	memset(buf, 'x', sizeof(buf));
	size_t filled = 0;
	for (;;) {
		const ssize_t n = send(ss->w_socket.fd, buf, sizeof(buf), 0);
		if (n < 0) {
			CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
			break;
		}
		CHECK(n > 0);
		filled += (size_t)n;
	}
	CHECK(filled > 0);
	frame(ss, SMSG_PUSH, "buffered response");
	CHECK(ss->wbuf_flush < ss->wbuf_next);
	CHECK(ss->w_socket.events & EV_WRITE);
	frame(ss, SMSG_EOF, NULL);
	CHECK(!ss->kcp_eof_recv);
	CHECK(shutdown(fd, SHUT_WR) == 0);
	tcp_socket_cb(s->loop, &ss->w_socket, EV_READ);
	CHECK(ss->kcp_eof_sent && ss->w_socket.fd >= 0);
	expect_frame(ss, SMSG_EOF, NULL);
	for (size_t consumed = 0; consumed < filled;) {
		const ssize_t n = recv(fd, buf, sizeof(buf), 0);
		CHECK(n > 0);
		for (ssize_t i = 0; i < n; i++) {
			CHECK(buf[i] == 'x');
		}
		consumed += (size_t)n;
		CHECK(consumed <= filled);
	}
	tcp_socket_cb(s->loop, &ss->w_socket, EV_WRITE);
	expect_socket(fd, "buffered response");
	expect_eof(fd);
	CHECK(ss->tcp_state == TCP_STATE_CLOSED);
	CHECK(ss->kcp_state == KCP_STATE_LINGER);
	CHECK(ss->stats.tcp_tx == strlen("buffered response"));
	socket_close(fd);
	detach_peer();
	free_server(s);
}

static void pending_connect(bool early_eof)
{
	struct server *s = new_server();
	const int listener = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(socket_set_nonblock(listener) == 0);
	s->connect.in = (struct sockaddr_in){
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	CHECK(bind(listener, &s->connect.sa, sizeof(s->connect.in)) == 0);
	socklen_t addrlen = sizeof(s->connect);
	CHECK(getsockname(listener, &s->connect.sa, &addrlen) == 0);
	CHECK(listen(listener, 1) == 0);
	struct session *ss = new_session(s);
	attach_peer(ss);
	frame(ss, SMSG_DIAL, NULL);
	CHECK(ss->tcp_state == TCP_STATE_CONNECT);
	if (early_eof) {
		frame(ss, SMSG_EOF, NULL);
	}
	CHECK(ss->tcp_state == TCP_STATE_CONNECT);
	CHECK(ss->kcp_eof_recv == early_eof);
	CHECK(!ss->tcp_eof_sent);
	CHECK(ev_is_active(&ss->w_socket) && (ss->w_socket.events & EV_WRITE));
	struct pollfd ready = { .fd = listener, .events = POLLIN };
	CHECK(poll(&ready, 1, 1000) == 1);
	const int fd = accept(listener, NULL, NULL);
	CHECK(fd >= 0);
	CHECK(socket_set_nonblock(fd) == 0);
	ready = (struct pollfd){ .fd = ss->w_socket.fd, .events = POLLOUT };
	CHECK(poll(&ready, 1, 1000) == 1);
	tcp_socket_cb(s->loop, &ss->w_socket, EV_WRITE);
	if (!early_eof) {
		CHECK(ss->tcp_state == TCP_STATE_ESTABLISHED);
		frame(ss, SMSG_PUSH, "connected request");
		expect_socket(fd, "connected request");
		frame(ss, SMSG_EOF, NULL);
	}
	CHECK(ss->tcp_state == TCP_STATE_LINGER && ss->tcp_eof_sent);
	expect_eof(fd);
	CHECK(send(fd, "late response", 13, 0) == 13);
	CHECK(shutdown(fd, SHUT_WR) == 0);
	tcp_socket_cb(s->loop, &ss->w_socket, EV_READ);
	expect_frame(ss, SMSG_PUSH, "late response");
	expect_frame(ss, SMSG_EOF, NULL);
	CHECK(ss->tcp_state == TCP_STATE_CLOSED);
	socket_close(fd);
	socket_close(listener);
	detach_peer();
	free_server(s);
}

static void failed_dial(bool coalesced)
{
	struct server *s = new_server();
	s->connect.in.sin_family = AF_INET;
	struct session *ss = new_session(s);
	attach_peer(ss);
	fail_connect = true;
	if (coalesced) {
		enqueue_frame(SMSG_DIAL, NULL);
		enqueue_frame(SMSG_PUSH, "discard after failed dial");
		enqueue_frame(SMSG_EOF, NULL);
		ikcp_flush(peer);
		session_read_cb(ss);
	} else {
		frame(ss, SMSG_DIAL, NULL);
		CHECK(ss->kcp_state == KCP_STATE_ESTABLISHED);
		frame(ss, SMSG_PUSH, "discard after failed dial");
		frame(ss, SMSG_EOF, NULL);
	}
	CHECK(!fail_connect);
	CHECK(ss->tcp_state == TCP_STATE_CLOSED && ss->kcp_eof_sent);
	expect_frame(ss, SMSG_EOF, NULL);
	CHECK(ss->kcp_eof_recv && ss->kcp_state == KCP_STATE_LINGER);
	CHECK(ss->wbuf->len == 0 && ss->wbuf_off == 0);
	CHECK(ss->wbuf_flush == ss->wbuf_next);
	CHECK(ikcp_peeksize(ss->kcp) < 0);
	detach_peer();
	free_server(s);
}

static void tick(struct server *s)
{
	timeout_cb(s->loop, &s->w_timeout, EV_TIMER);
}

static void dial_timeout(void)
{
	struct server *s = new_server();
	struct session *ss = new_session(s);
	const ev_tstamp now = ev_now(s->loop);
	ss->kcp_state = KCP_STATE_CONNECT;
	ss->created = now - s->dial_timeout;
	tick(s);
	CHECK(ss->kcp_state == KCP_STATE_CONNECT);
	ss->created -= 1;
	tick(s);
	CHECK(ss->kcp_state == KCP_STATE_TIME_WAIT && ss->kcp == NULL);
	CHECK(ss->time_wait_started == now);
	CHECK(ss->rbuf == NULL && ss->wbuf == NULL);
	free_server(s);
}

static void activity_timeout(void)
{
	/* Each source of established-session activity is tested independently. */
	for (int activity = 0; activity < 3; activity++) {
		struct server *s = new_server();
		struct session *ss = new_session(s);
		ss->created = ev_now(s->loop) - s->session_timeout - 1;
		if (activity == 0) {
			ss->last_recv = ev_now(s->loop);
		} else if (activity == 1) {
			memcpy(ss->rbuf->data + TLV_HEADER_SIZE, "x", 1);
			ss->rbuf->len = 1;
			CHECK(session_kcp_send(ss));
			CHECK(ss->last_payload_send == ev_now(s->loop));
		} else {
			CHECK(kcp_sendmsg(ss, SMSG_KEEPALIVE));
			CHECK(ss->last_payload_send == TSTAMP_NIL);
		}
		tick(s);
		CHECK(ss->kcp_state == (activity == 2 ? KCP_STATE_TIME_WAIT :
							KCP_STATE_ESTABLISHED));
		free_server(s);
	}
}

static void linger_timeout(void)
{
	for (int half = 0; half < 3; half++) {
		struct server *s = new_server();
		struct session *ss = new_session(s);
		if (half == 0) {
			ss->kcp_eof_sent = true;
		} else if (half == 1) {
			ss->kcp_eof_recv = true;
		} else {
			ss->kcp_state = KCP_STATE_LINGER;
		}
		ss->created = ev_now(s->loop) - s->session_timeout - 1;
		ss->last_send = ev_now(s->loop) - s->linger;
		tick(s);
		CHECK(kcp_is_connected(ss));
		ss->last_send -= 1;
		tick(s);
		CHECK(ss->kcp_state == KCP_STATE_TIME_WAIT);
		free_server(s);
	}
}

static void time_wait_timeout(void)
{
	struct server *s = new_server();
	struct session *ss = new_session(s);
	ss->created = ev_now(s->loop) - 1000;
	session_kcp_stop(ss);
	tick(s);
	CHECK(table_size(s->sessions) == 1);
	const ev_tstamp started = ss->time_wait_started;
	session_kcp_stop(ss);
	CHECK(ss->time_wait_started == started);
	ss->time_wait_started = ev_now(s->loop) - s->time_wait;
	tick(s);
	CHECK(table_size(s->sessions) == 1);
	ss->time_wait_started -= 1;
	ss->last_reset = ev_now(s->loop);
	tick(s);
	CHECK(table_size(s->sessions) == 1);
	ss->last_reset = ev_now(s->loop) - s->time_wait;
	tick(s);
	CHECK(table_size(s->sessions) == 1);
	ss->last_reset -= 1;
	tick(s);
	CHECK(table_size(s->sessions) == 0);
	free_server(s);
}

int main(int argc, char **argv)
{
	slog_setoutput(SLOG_OUTPUT_STREAM, log_filewriter(stderr));
	CHECK(argc == 2);
	CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
	loadlibs();
	slog_setlevel(LOG_LEVEL_ERROR);
	if (strcmp(argv[1], "lifecycle") == 0) {
		half_close(true);
		half_close(false);
		pending_output();
		pending_connect(true);
		pending_connect(false);
		failed_dial(false);
		failed_dial(true);
	} else if (strcmp(argv[1], "framing") == 0) {
		fragmented_push();
		fragmented_control(SMSG_DIAL);
		fragmented_control(SMSG_EOF);
		fragmented_control(SMSG_KEEPALIVE);
		push_length_boundaries();
		malformed_frames();
	} else {
		CHECK(strcmp(argv[1], "timeouts") == 0);
		dial_timeout();
		activity_timeout();
		linger_timeout();
		time_wait_timeout();
	}
	unloadlibs();
	puts("session assertions passed");
	return EXIT_SUCCESS;
}
