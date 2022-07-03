#include "event.h"
#include "event_impl.h"
#include "packet.h"
#include "proxy.h"
#include "server.h"
#include "session.h"
#include "util.h"

#include <ev.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

int udp_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
	UNUSED(kcp);
	UTIL_ASSERT(len > 0 && len < MAX_PACKET_SIZE);
	struct session *restrict ss = (struct session *)user;
	struct server *restrict s = ss->server;
	struct packet *p = s->udp.packets;
	struct sockaddr *sa = (struct sockaddr *)&ss->udp_remote;
	struct msgframe *restrict msg = msgframe_new(p, sa);
	if (msg == NULL) {
		return -1;
	}
	memcpy(msg->buf, buf, len);
	msg->len = len;
	ss->stats.udp_out += len;
	return packet_send(p, s, msg) ? len : -1;
}

bool kcp_send(
	struct session *restrict ss, const unsigned char *buf, const size_t len)
{
	int r = ikcp_send(ss->kcp, (char *)buf, len);
	if (r < 0) {
		return false;
	}
	ss->stats.kcp_out += len;
	ss->server->stats.kcp_out += len;
	LOGV_F("session [%08" PRIX32 "] kcp send: %zu bytes", ss->conv, len);
	ss->last_send = ev_now(ss->server->loop);
	return true;
}

static bool kcp_push(struct session *restrict ss)
{
	struct server *restrict s = ss->server;
	const size_t len = TLV_HEADER_SIZE + ss->rbuf_len;
	struct tlv_header header = (struct tlv_header){
		.msg = SMSG_PUSH,
		.len = (uint16_t)len,
	};
	tlv_header_write(ss->rbuf, header);
	if (!kcp_send(ss, ss->rbuf, len)) {
		return false;
	}
	ss->rbuf_len = 0;
	/* invalidate last ikcp_check */
	ss->kcp_checked = false;
	ss->last_send = ev_now(s->loop);
	return true;
}

bool kcp_dial(struct session *restrict ss)
{
	unsigned char buf[TLV_HEADER_SIZE];
	struct tlv_header header = (struct tlv_header){
		.msg = SMSG_DIAL,
		.len = TLV_HEADER_SIZE,
	};
	tlv_header_write(buf, header);
	LOGD_F("session [%08" PRIX32 "] send dial", ss->conv);
	return kcp_send(ss, buf, TLV_HEADER_SIZE);
}

void kcp_close(struct session *restrict ss)
{
	switch (ss->state) {
	case STATE_HALFOPEN:
	case STATE_CONNECT:
	case STATE_CONNECTED:
		break;
	default:
		return;
	}
	/* flush unsent push message */
	if (ss->rbuf_len > 0) {
		if (!kcp_push(ss)) {
			return;
		}
	}
	ss->state = STATE_LINGER;
	unsigned char buf[TLV_HEADER_SIZE];
	struct tlv_header header = (struct tlv_header){
		.msg = SMSG_EOF,
		.len = TLV_HEADER_SIZE,
	};
	tlv_header_write(buf, header);
	if (!kcp_send(ss, buf, TLV_HEADER_SIZE)) {
		return;
	}
	LOGD_F("session [%08" PRIX32 "] send: eof", ss->conv);
	ss->state = STATE_LINGER;
}

void kcp_reset(struct session *ss)
{
	const ev_tstamp now = ev_now(ss->server->loop);
	if (ss->state != STATE_CONNECT && ss->state != STATE_CONNECTED &&
	    now - ss->last_send < 1.0) {
		return;
	}
	struct sockaddr *sa = (struct sockaddr *)&ss->udp_remote;
	ss0_reset(ss->server, sa, ss->conv);
	ss->last_send = now;
	LOGD_F("session [%08" PRIX32 "] send: reset", ss->conv);
	ss->state = STATE_TIME_WAIT;
}

void kcp_recv(struct session *restrict ss)
{
	switch (ss->state) {
	case STATE_HALFOPEN:
	case STATE_CONNECT:
	case STATE_CONNECTED:
		break;
	default: {
		const int r =
			ikcp_recv(ss->kcp, (char *)ss->wbuf, SESSION_BUF_SIZE);
		if (r > 0) {
			kcp_reset(ss);
		}
		return;
	}
	}
	if (ss->wbuf_navail > 0) {
		return;
	}
	unsigned char *start = ss->wbuf + ss->wbuf_len;
	size_t cap = SESSION_BUF_SIZE - ss->wbuf_len;
	size_t nrecv = 0;
	while (cap > 0) {
		int r = ikcp_recv(ss->kcp, (char *)start, cap);
		if (r <= 0) {
			break;
		}
		nrecv += r;
		start += r;
		cap -= r;
	}
	if (nrecv > 0) {
		ss->wbuf_len += nrecv;
		ss->stats.kcp_in += nrecv;
		ss->server->stats.kcp_in += nrecv;
		LOGV_F("session [%08" PRIX32
		       "] kcp recv: %zu bytes, cap: %zu bytes",
		       ss->conv, nrecv, cap);
		ss->last_recv = ev_now(ss->server->loop);
	}

	if (ss->wbuf_len < TLV_HEADER_SIZE) {
		/* no data available */
		return;
	}
	struct tlv_header header = tlv_header_read(ss->wbuf);
	UTIL_ASSERT(
		header.len >= TLV_HEADER_SIZE &&
		header.len <= SESSION_BUF_SIZE);
	if (header.msg < SMSG_MAX && ss->wbuf_len < header.len) {
		/* incomplete data packet */
		return;
	}
	session_on_msg(ss, &header);
}

static void kcp_keepalive(struct session *restrict ss)
{
	unsigned char buf[TLV_HEADER_SIZE];
	struct tlv_header header = (struct tlv_header){
		.msg = SMSG_KEEPALIVE,
		.len = TLV_HEADER_SIZE,
	};
	tlv_header_write(buf, header);
	if (!kcp_send(ss, buf, TLV_HEADER_SIZE)) {
		return;
	}
	LOGD_F("session [%08" PRIX32 "] send: keepalive", ss->conv);
}

static void kcp_update(struct session *restrict ss)
{
	switch (ss->state) {
	case STATE_HALFOPEN:
	case STATE_CONNECT:
	case STATE_CONNECTED:
	case STATE_LINGER:
		break;
	default:
		return;
	}
	struct server *restrict s = ss->server;
	const ev_tstamp now = ev_now(s->loop);
	const uint32_t now_ms = tstamp2ms(now);
	if (!ss->kcp_checked || (int32_t)(now_ms - ss->kcp_next) >= 0) {
		ikcp_update(ss->kcp, now_ms);
		kcp_recv(ss);
		tcp_notify_write(ss);
		ss->kcp_next = ikcp_check(ss->kcp, now_ms);
		ss->kcp_checked = true;
	}
	const int waitsnd = ikcp_waitsnd(ss->kcp);
	if (ss->tcp_fd != -1 && !ev_is_active(ss->w_read)) {
		const int window_size = s->conf->kcp_sndwnd;
		if (waitsnd < window_size) {
			ev_io_start(s->loop, ss->w_read);
		}
	}
	if (!ss->is_accepted) {
		const double last_seen = ss->last_send > ss->last_recv ?
						 ss->last_send :
						 ss->last_recv;
		const double not_seen = now - last_seen;
		if (not_seen > s->session_keepalive) {
			kcp_keepalive(ss);
		}
	}
}

void kcp_notify(struct session *restrict ss)
{
	UTIL_ASSERT(ss->rbuf_len <= SESSION_BUF_SIZE - TLV_HEADER_SIZE);
	if (ss->rbuf_len == 0) {
		return;
	}
	struct server *restrict s = ss->server;
	const int waitsnd = ikcp_waitsnd(ss->kcp);
	const int window_size = s->conf->kcp_sndwnd;
	if (waitsnd >= window_size) {
		return;
	}
	if (!kcp_push(ss)) {
		return;
	}
	kcp_update(ss);
}

static bool kcp_update_iter(
	struct hashtable *t, const hashkey_t *key, void *value, void *user)
{
	UNUSED(t);
	UNUSED(key);
	kcp_update((struct session *)value);
	struct server *restrict s = user;
	struct packet *restrict p = s->udp.packets;
	return p->mq_send_len < MQ_SEND_SIZE;
}

void kcp_update_all(struct server *restrict s)
{
	table_iterate(s->sessions, kcp_update_iter, s);
}

void kcp_update_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);
	struct server *restrict s = watcher->data;
	struct packet *restrict p = s->udp.packets;
	if (p->mq_send_len < MQ_SEND_SIZE) {
		table_iterate(s->sessions, kcp_update_iter, s);
	}
}
