#include "event.h"
#include "event_impl.h"
#include "session.h"
#include "util.h"
#include "server.h"
#include "pktqueue.h"

#include "kcp/ikcp.h"

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>

int udp_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
	UNUSED(kcp);
	assert(len > 0 && len < MAX_PACKET_SIZE);
	struct session *restrict ss = (struct session *)user;
	struct server *restrict s = ss->server;
	struct pktqueue *q = s->pkt.queue;
	struct msgframe *restrict msg = msgframe_new(q, &ss->raddr.sa);
	if (msg == NULL) {
		return -1;
	}
	unsigned char *kcp_packet = msg->buf + msg->off;
	memcpy(kcp_packet, buf, len);
	msg->len = len;
	s->stats.kcp_tx += len;
	ss->stats.kcp_tx += len;
	return packet_send(q, s, msg) ? len : -1;
}

void kcp_reset(struct session *ss)
{
	const ev_tstamp now = ev_now(ss->server->loop);
	if (ss->state != STATE_CONNECT && ss->state != STATE_CONNECTED &&
	    now - ss->last_send < 1.0) {
		return;
	}
	ss0_reset(ss->server, &ss->raddr.sa, ss->conv);
	ss->last_send = now;
	LOGD_F("session [%08" PRIX32 "] send: reset", ss->conv);
	ss->state = STATE_TIME_WAIT;
}

bool kcp_send(
	struct session *restrict ss, const unsigned char *buf, const size_t len)
{
	const bool can_flush = ss->kcp_flush && ikcp_waitsnd(ss->kcp) == 0;
	int r = ikcp_send(ss->kcp, (char *)buf, (int)len);
	if (r < 0) {
		return false;
	}
	if (can_flush) {
		ikcp_flush(ss->kcp);
	}
	LOGV_F("session [%08" PRIX32 "] kcp send: %zu bytes", ss->conv, len);
	ss->last_send = ev_now(ss->server->loop);
	return true;
}

static bool kcp_sendmsg(struct session *restrict ss, const uint16_t msg)
{
	unsigned char buf[TLV_HEADER_SIZE];
	struct tlv_header header = (struct tlv_header){
		.msg = msg,
		.len = TLV_HEADER_SIZE,
	};
	tlv_header_write(buf, header);
	return kcp_send(ss, buf, TLV_HEADER_SIZE);
}

static bool kcp_push(struct session *restrict ss)
{
	if (ss->rbuf_len == 0) {
		return true;
	}
	const size_t len = TLV_HEADER_SIZE + ss->rbuf_len;
	struct tlv_header header = (struct tlv_header){
		.msg = SMSG_PUSH,
		.len = (uint16_t)len,
	};
	tlv_header_write(ss->rbuf, header);
	ss->rbuf_len = 0;
	return kcp_send(ss, ss->rbuf, len);
}

bool kcp_dial(struct session *restrict ss)
{
	LOGD_F("session [%08" PRIX32 "] send: dial", ss->conv);
	return kcp_sendmsg(ss, SMSG_DIAL);
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
	if (!kcp_push(ss) || !kcp_sendmsg(ss, SMSG_EOF)) {
		kcp_reset(ss);
		return;
	}
	LOGD_F("session [%08" PRIX32 "] send: eof", ss->conv);
	ss->state = STATE_LINGER;
}

static void kcp_recv(struct session *restrict ss)
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
		int r = ikcp_recv(ss->kcp, (char *)start, (int)cap);
		if (r <= 0) {
			break;
		}
		nrecv += r;
		start += r;
		cap -= r;
	}
	if (nrecv > 0) {
		ss->wbuf_len += nrecv;
		LOGV_F("session [%08" PRIX32 "] kcp recv: "
		       "%zu bytes, cap: %zu bytes",
		       ss->conv, nrecv, cap);
		ss->last_recv = ev_now(ss->server->loop);
	}

	if (ss->wbuf_len < TLV_HEADER_SIZE) {
		/* no data available */
		return;
	}
	struct tlv_header header = tlv_header_read(ss->wbuf);
	if (header.len < TLV_HEADER_SIZE && header.len > TLV_MAX_LENGTH) {
		LOGE_F("unexpected packet length: %" PRIu16, header.len);
		session_stop(ss);
		kcp_reset(ss);
		return;
	}
	if (header.msg < SMSG_MAX && ss->wbuf_len < header.len) {
		/* incomplete data packet */
		return;
	}
	session_on_msg(ss, &header);
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
	ikcp_update(ss->kcp, now_ms);
	kcp_recv(ss);
	if (ss->state != STATE_LINGER && ss->tcp_fd != -1) {
		struct ev_io *restrict w_read = &ss->w_read;
		const int waitsnd = ikcp_waitsnd(ss->kcp);
		const int window_size = (int)ss->kcp->snd_wnd;
		if (waitsnd < window_size && !ev_is_active(w_read)) {
			ev_io_start(s->loop, w_read);
		}
	}
}

void kcp_notify_write(struct session *restrict ss)
{
	assert(ss->rbuf_len <= SESSION_BUF_SIZE - TLV_HEADER_SIZE);
	if (!kcp_push(ss)) {
		kcp_reset(ss);
		session_stop(ss);
		return;
	}
	if (ss->state == STATE_LINGER) {
		session_stop(ss);
		return;
	}
	const int waitsnd = ikcp_waitsnd(ss->kcp);
	const int window_size = (int)ss->kcp->snd_wnd;
	if (waitsnd >= window_size) {
		struct ev_io *restrict w_read = &ss->w_read;
		if (ev_is_active(w_read)) {
			ev_io_stop(ss->server->loop, w_read);
		}
	}
}

static bool kcp_update_iter(
	struct hashtable *t, const hashkey_t *key, void *value, void *user)
{
	UNUSED(t);
	UNUSED(key);
	kcp_update((struct session *)value);
	struct server *restrict s = user;
	struct pktqueue *restrict q = s->pkt.queue;
	return q->mq_send_len < MQ_SEND_SIZE;
}

static void kcp_update_all(struct server *restrict s)
{
	struct pktqueue *restrict q = s->pkt.queue;
	if (q->mq_send_len == MQ_SEND_SIZE) {
		return;
	}
	table_iterate(s->sessions, kcp_update_iter, s);
	pkt_notify_write(s);
}

void kcp_notify_all(struct server *s)
{
	kcp_update_all(s);
}

void kcp_update_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);
	kcp_update_all(watcher->data);
}
