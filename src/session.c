/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "session.h"
#include "utils/buffer.h"
#include "utils/check.h"
#include "utils/formats.h"
#include "utils/serialize.h"
#include "utils/slog.h"
#include "algo/hashtable.h"
#include "crypto.h"
#include "conf.h"
#include "event.h"
#include "server.h"
#include "pktqueue.h"
#include "sockutil.h"
#include "util.h"
#include "kcp/ikcp.h"

#include <ev.h>
#include <sys/socket.h>
#include <unistd.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>

const char session_state_char[STATE_MAX] = {
	[STATE_INIT] = ' ',   [STATE_CONNECT] = '>',   [STATE_CONNECTED] = '-',
	[STATE_LINGER] = '.', [STATE_TIME_WAIT] = 'x',
};

static void kcp_log(const char *log, struct IKCPCB *kcp, void *user)
{
	UNUSED(kcp);
	struct session *restrict ss = user;
	LOGV_F("session [%08" PRIX32 "] kcp internal: %s", ss->conv, log);
}

static ikcpcb *
kcp_new(struct session *restrict ss, const struct config *restrict conf,
	uint32_t conv)
{
	ikcpcb *restrict kcp = ikcp_create(conv, ss);
	if (kcp == NULL) {
		return NULL;
	}
	ikcp_wndsize(kcp, conf->kcp_sndwnd, conf->kcp_rcvwnd);
	ikcp_setmtu(kcp, (int)ss->server->pkt.queue->mss);
	ikcp_nodelay(
		kcp, conf->kcp_nodelay, conf->kcp_interval, conf->kcp_resend,
		conf->kcp_nc);
	ikcp_setoutput(kcp, udp_output);
	if (LOGLEVEL(VERBOSE)) {
		kcp->logmask = -1;
		kcp->writelog = kcp_log;
	}
	return kcp;
}

static void
ss_flush_cb(struct ev_loop *loop, struct ev_idle *watcher, int revents)
{
	UNUSED(revents);
	ev_idle_stop(loop, watcher);
	struct session *restrict ss = watcher->data;
	switch (ss->kcp_state) {
	case STATE_CONNECT:
	case STATE_CONNECTED:
	case STATE_LINGER:
		break;
	default:
		return;
	}
	ikcp_flush(ss->kcp);
	tcp_notify_recv(ss);
}

struct session *session_new(
	struct server *restrict s, const struct sockaddr *addr,
	const uint32_t conv)
{
	struct session *restrict ss =
		(struct session *)malloc(sizeof(struct session));
	if (ss == NULL) {
		return NULL;
	}
	const ev_tstamp now = ev_now(s->loop);
	SESSION_MAKE_KEY(ss->key, addr, conv);
	ss->created = now;
	ss->last_send = TSTAMP_NIL;
	ss->last_recv = TSTAMP_NIL;
	ss->last_reset = TSTAMP_NIL;
	ss->tcp_state = STATE_INIT;
	ss->kcp_state = STATE_INIT;
	ev_io_init(&ss->w_socket, tcp_socket_cb, -1, EV_NONE);
	ss->w_socket.data = ss;
	ev_idle_init(&ss->w_flush, ss_flush_cb);
	ss->w_flush.data = ss;
	ss->server = s;
	memcpy(&ss->raddr, addr, getsocklen(addr));
	ss->conv = conv;
	ss->stats = (struct link_stats){ 0 };
	ss->kcp_flush = s->conf->kcp_flush;
	ss->is_accepted = false;
	ss->wbuf_next = ss->wbuf_flush = 0;
	ss->rbuf = VBUF_NEW(SESSION_BUF_SIZE);
	if (ss->rbuf == NULL) {
		session_free(ss);
		return NULL;
	}
	ss->wbuf = VBUF_NEW(SESSION_BUF_SIZE);
	if (ss->wbuf == NULL) {
		session_free(ss);
		return NULL;
	}
	ss->kcp = kcp_new(ss, s->conf, conv);
	if (ss->kcp == NULL) {
		session_free(ss);
		return NULL;
	}
	return ss;
}

void session_free(struct session *restrict ss)
{
	session_tcp_stop(ss);
	session_kcp_stop(ss);
	ev_idle_stop(ss->server->loop, &ss->w_flush);
	free(ss);
}

void session_start(struct session *restrict ss, const int fd)
{
	LOGD_F("session [%08" PRIX32 "] tcp: start, fd=%d", ss->conv, fd);
	/* Initialize and start watchers to transfer data */
	struct ev_loop *loop = ss->server->loop;
	struct ev_io *restrict w_socket = &ss->w_socket;
	ev_io_set(w_socket, fd, EV_READ | EV_WRITE);
	ev_io_start(loop, w_socket);

	const ev_tstamp now = ev_now(loop);
	const uint32_t now_ms = TSTAMP2MS(now);
	ikcp_update(ss->kcp, now_ms);
}

void session_tcp_stop(struct session *restrict ss)
{
	ss->tcp_state = STATE_TIME_WAIT;
	struct ev_io *restrict w_socket = &ss->w_socket;
	if (w_socket->fd == -1) {
		return;
	}
	LOGD_F("session [%08" PRIX32 "] tcp: stop, fd=%d", ss->conv,
	       w_socket->fd);
	ev_io_stop(ss->server->loop, w_socket);
	CLOSE_FD(ss->w_socket.fd);
	ev_io_set(w_socket, -1, EV_NONE);
}

void session_kcp_stop(struct session *restrict ss)
{
	ss->kcp_state = STATE_TIME_WAIT;
	if (ss->kcp != NULL) {
		ikcp_release(ss->kcp);
		ss->kcp = NULL;
	}
	ss->rbuf = VBUF_FREE(ss->rbuf);
	ss->wbuf = VBUF_FREE(ss->wbuf);
}

static void consume_wbuf(struct session *restrict ss, const size_t n)
{
	VBUF_CONSUME(ss->wbuf, n);
	ss->wbuf_flush = 0;
	ss->wbuf_next = 0;
}

static bool proxy_dial(struct session *restrict ss, const struct sockaddr *sa)
{
	/* Create client socket */
	int fd = socket(sa->sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		const int err = errno;
		LOGE_F("socket: %s", strerror(err));
		return false;
	}
	if (!socket_set_nonblock(fd)) {
		const int err = errno;
		LOGE_F("fcntl: %s", strerror(err));
		CLOSE_FD(fd);
		return false;
	}
	{
		const struct config *restrict conf = ss->server->conf;
		socket_set_tcp(fd, conf->tcp_nodelay, conf->tcp_keepalive);
		socket_set_buffer(fd, conf->tcp_sndbuf, conf->tcp_rcvbuf);
	}

	/* Connect to address */
	if (connect(fd, sa, getsocklen(sa)) != 0) {
		const int err = errno;
		if (err != EINTR && err != EINPROGRESS) {
			LOGE_F("connect: %s", strerror(err));
			return false;
		}
		ss->tcp_state = STATE_CONNECT;
	} else {
		ss->tcp_state = STATE_CONNECTED;
	}

	if (LOGLEVEL(INFO)) {
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOG_F(INFO, "session [%08" PRIX32 "] tcp: connect %s", ss->conv,
		      addr_str);
	}
	session_start(ss, fd);
	return true;
}

static bool session_on_msg(
	struct session *restrict ss, const struct tlv_header *restrict hdr)
{
	switch (hdr->msg) {
	case SMSG_DIAL: {
		if (hdr->len != TLV_HEADER_SIZE) {
			break;
		}
		LOGD_F("session [%08" PRIX32 "] msg: dial", ss->conv);
		if (ss->tcp_state != STATE_INIT) {
			break;
		}
		if (!proxy_dial(ss, &ss->server->connect.sa)) {
			break;
		}
		return true;
	}
	case SMSG_PUSH: {
		const size_t navail = (size_t)hdr->len - TLV_HEADER_SIZE;
		LOGV_F("session [%08" PRIX32 "] msg: push, %zu bytes", ss->conv,
		       navail);
		ss->wbuf_flush = TLV_HEADER_SIZE;
		tcp_notify_send(ss);
		return true;
	}
	case SMSG_EOF: {
		if (hdr->len != TLV_HEADER_SIZE) {
			break;
		}
		LOGI_F("session [%08" PRIX32 "] kcp: "
		       "connection closed by peer",
		       ss->conv);
		ss->kcp_state = STATE_LINGER;
		ss->tcp_state = STATE_LINGER;
		ss->wbuf_flush = ss->wbuf_next;
		tcp_notify_send(ss);
		return true;
	}
	case SMSG_KEEPALIVE: {
		if (hdr->len != TLV_HEADER_SIZE) {
			break;
		}
		LOGD_F("session [%08" PRIX32 "] msg: keepalive", ss->conv);
		if (ss->is_accepted) {
			if (!kcp_sendmsg(ss, SMSG_KEEPALIVE)) {
				return false;
			}
		}
		return true;
	}
	}
	LOGE_F("session [%08" PRIX32 "] msg: error "
	       "msg=%04" PRIX16 ", len=%04" PRIX16,
	       ss->conv, hdr->msg, hdr->len);
	return false;
}

static int ss_process(struct session *restrict ss)
{
	if (ss->wbuf_flush < ss->wbuf_next) {
		/* tcp flushing is in progress */
		return 0;
	}
	if (ss->wbuf->len < TLV_HEADER_SIZE) {
		/* no header available */
		return 0;
	}
	if (ss->wbuf_flush > 0) {
		/* tcp flushing is done */
		consume_wbuf(ss, ss->wbuf_flush);
	}
	const struct tlv_header hdr = tlv_header_read(ss->wbuf->data);
	if (hdr.len < TLV_HEADER_SIZE && hdr.len > TLV_MAX_LENGTH) {
		LOGE_F("unexpected message length: %" PRIu16, hdr.len);
		return -1;
	}
	if (hdr.msg < SMSG_MAX && ss->wbuf->len < hdr.len) {
		/* incomplete message */
		return 0;
	}
	ss->wbuf_next = hdr.len;
	if (!session_on_msg(ss, &hdr)) {
		/* malformed message */
		return -1;
	}
	if (ss->wbuf_flush == 0) {
		/* nothing to flush */
		consume_wbuf(ss, ss->wbuf_next);
	}
	return 1;
}

bool session_kcp_send(struct session *restrict ss)
{
	switch (ss->kcp_state) {
	case STATE_CONNECT:
	case STATE_CONNECTED:
		break;
	default:
		return false;
	}
	if (ss->rbuf->len == 0) {
		return true;
	}
	if (!kcp_push(ss)) {
		return false;
	}
	if (ss->kcp_flush >= 1) {
		session_kcp_flush(ss);
	}
	return true;
}

void session_kcp_close(struct session *restrict ss)
{
	switch (ss->kcp_state) {
	case STATE_CONNECT:
	case STATE_CONNECTED:
		break;
	default:
		kcp_reset(ss);
		return;
	}
	/* pass eof */
	if (!kcp_sendmsg(ss, SMSG_EOF)) {
		kcp_reset(ss);
		return;
	}
	LOGD_F("session [%08" PRIX32 "] kcp: close", ss->conv);
	ss->kcp_state = STATE_LINGER;
	if (ss->kcp_flush >= 1) {
		session_kcp_flush(ss);
	}
}

void session_read_cb(struct session *restrict ss)
{
	for (;;) {
		switch (ss->kcp_state) {
		case STATE_CONNECT:
		case STATE_CONNECTED:
			break;
		default:
			return;
		}
		switch (ss->tcp_state) {
		case STATE_INIT:
		case STATE_CONNECT:
		case STATE_CONNECTED:
			break;
		default:
			return;
		}
		kcp_recv(ss);
		const int ret = ss_process(ss);
		if (ret < 0) {
			session_tcp_stop(ss);
			session_kcp_close(ss);
			return;
		} else if (ret == 0) {
			return;
		}
	}
}

void session_kcp_flush(struct session *restrict ss)
{
	struct ev_idle *restrict w_flush = &ss->w_flush;
	if (ev_is_active(w_flush)) {
		return;
	}
	ev_idle_start(ss->server->loop, w_flush);
}

struct session0_header {
	uint32_t zero;
	uint16_t what;
};

#define SESSION0_HEADER_SIZE (sizeof(uint32_t) + sizeof(uint16_t))

static inline struct session0_header ss0_header_read(const unsigned char *d)
{
	return (struct session0_header){
		.zero = read_uint32(d),
		.what = read_uint16(d + sizeof(uint32_t)),
	};
}

static inline void
ss0_header_write(unsigned char *d, struct session0_header header)
{
	write_uint32(d, header.zero);
	write_uint16(d + sizeof(uint32_t), header.what);
}

void ss0_reset(struct server *s, const struct sockaddr *sa, uint32_t conv)
{
	unsigned char b[sizeof(uint32_t)];
	write_uint32(b, conv);
	ss0_send(s, sa, S0MSG_RESET, b, sizeof(b));
}

bool ss0_send(
	struct server *restrict s, const struct sockaddr *sa,
	const uint16_t what, const unsigned char *b, const size_t n)
{
	struct msgframe *restrict msg = msgframe_new(s->pkt.queue);
	if (msg == NULL) {
		LOGOOM();
		return false;
	}
	memcpy(&msg->addr.sa, sa, getsocklen(sa));
	unsigned char *packet = msg->buf + msg->off;
	ss0_header_write(
		packet, (struct session0_header){
				.zero = 0,
				.what = what,
			});
	memcpy(packet + SESSION0_HEADER_SIZE, b, n);
	msg->len = SESSION0_HEADER_SIZE + n;
	return queue_send(s, msg);
}

static void
ss0_on_ping(struct server *restrict s, struct msgframe *restrict msg)
{
	if (msg->len < SESSION0_HEADER_SIZE + sizeof(uint32_t)) {
		LOGW_F("short ping message: %" PRIu16 " bytes", msg->len);
		return;
	}
	const unsigned char *msgbuf =
		msg->buf + msg->off + SESSION0_HEADER_SIZE;
	const uint32_t tstamp = read_uint32(msgbuf);
	/* send echo message */
	unsigned char b[sizeof(uint32_t)];
	write_uint32(b, tstamp);
	ss0_send(s, &msg->addr.sa, S0MSG_PONG, b, sizeof(b));
}

static void
ss0_on_pong(struct server *restrict s, struct msgframe *restrict msg)
{
	UNUSED(s);
	if (msg->len < SESSION0_HEADER_SIZE + sizeof(uint32_t)) {
		LOGW_F("short pong message: %" PRIu16 " bytes", msg->len);
		return;
	}
	const unsigned char *msgbuf =
		msg->buf + msg->off + SESSION0_HEADER_SIZE;
	const uint32_t tstamp = read_uint32(msgbuf);
	/* calculate RTT & estimated bandwidth */
	const uint32_t now_ms = TSTAMP2MS(ev_time());
	const double rtt = (now_ms - tstamp) * 1e-3;
	const struct config *restrict conf = s->conf;
	const double rx = conf->kcp_rcvwnd * conf->kcp_mtu / rtt;
	const double tx = conf->kcp_sndwnd * conf->kcp_mtu / rtt;

	char bw_rx[16], bw_tx[16];
	format_iec_bytes(bw_rx, sizeof(bw_rx), rx);
	format_iec_bytes(bw_tx, sizeof(bw_tx), tx);

	LOGD_F("roundtrip finished, RTT: %" PRIu32 " ms, "
	       "bandwidth rx: %s/s, tx: %s/s",
	       now_ms - tstamp, bw_rx, bw_tx);
	s->pkt.inflight_ping = TSTAMP_NIL;
}

static void
ss0_on_reset(struct server *restrict s, struct msgframe *restrict msg)
{
	if (msg->len < SESSION0_HEADER_SIZE + sizeof(uint32_t)) {
		LOGW_F("short reset message: %" PRIu16 " bytes", msg->len);
		return;
	}
	const unsigned char *msgbuf =
		msg->buf + msg->off + SESSION0_HEADER_SIZE;
	const uint32_t conv = read_uint32(msgbuf);
	struct session_key key;
	SESSION_MAKE_KEY(key, &msg->addr.sa, conv);
	struct session *restrict ss =
		table_find(s->sessions, (hashkey_t *)&key);
	if (ss == NULL) {
		return;
	}
	if (ss->kcp_state == STATE_TIME_WAIT) {
		return;
	}
	LOGI_F("session [%08" PRIX32 "] kcp: reset by peer", conv);
	session_tcp_stop(ss);
	session_kcp_stop(ss);
}

void session0(struct server *restrict s, struct msgframe *restrict msg)
{
	if (msg->len < SESSION0_HEADER_SIZE) {
		LOGW_F("short session 0 message: %" PRIu16 " bytes", msg->len);
		return;
	}
	const unsigned char *packet = msg->buf + msg->off;
	struct session0_header header = ss0_header_read(packet);
	switch (header.what) {
	case S0MSG_PING:
		ss0_on_ping(s, msg);
		break;
	case S0MSG_PONG:
		ss0_on_pong(s, msg);
		break;
	case S0MSG_RESET:
		ss0_on_reset(s, msg);
		break;
	default:
		LOGW_F("unknown session 0 message: %04" PRIX16, header.what);
		break;
	}
}
