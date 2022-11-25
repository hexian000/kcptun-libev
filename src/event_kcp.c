#include "event.h"
#include "event_impl.h"
#include "session.h"
#include "slog.h"
#include "util.h"
#include "server.h"
#include "pktqueue.h"

#include "kcp/ikcp.h"

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
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
	if (!queue_send(q, s, msg)) {
		ss->need_flush = true;
		return -1;
	}
	return len;
}

void kcp_reset(struct session *ss)
{
	session_kcp_stop(ss);
	const ev_tstamp now = ev_now(ss->server->loop);
	if (ss->last_send != TSTAMP_NIL && now - ss->last_send < 1.0) {
		return;
	}
	ss0_reset(ss->server, &ss->raddr.sa, ss->conv);
	ss->last_send = now;
	LOGD_F("session [%08" PRIX32 "] send: reset", ss->conv);
}

static bool kcp_send(
	struct session *restrict ss, const unsigned char *buf, const size_t len)
{
	int r = ikcp_send(ss->kcp, (char *)buf, (int)len);
	if (r < 0) {
		return false;
	}
	LOGV_F("session [%08" PRIX32 "] kcp send: %zu bytes", ss->conv, len);
	ss->last_send = ev_now(ss->server->loop);
	return true;
}

bool kcp_sendmsg(struct session *restrict ss, const uint16_t msg)
{
	unsigned char buf[TLV_HEADER_SIZE];
	struct tlv_header header = (struct tlv_header){
		.msg = msg,
		.len = TLV_HEADER_SIZE,
	};
	tlv_header_write(buf, header);
	return kcp_send(ss, buf, TLV_HEADER_SIZE);
}

bool kcp_push(struct session *restrict ss)
{
	if (ss->rbuf_len == 0) {
		return true;
	}
	assert(ss->rbuf_len <= SESSION_BUF_SIZE - TLV_HEADER_SIZE);
	const size_t len = TLV_HEADER_SIZE + ss->rbuf_len;
	struct tlv_header header = (struct tlv_header){
		.msg = SMSG_PUSH,
		.len = (uint16_t)len,
	};
	tlv_header_write(ss->rbuf, header);
	ss->rbuf_len = 0;
	return kcp_send(ss, ss->rbuf, len);
}

void kcp_close(struct session *restrict ss)
{
	switch (ss->kcp_state) {
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
	if (ss->kcp_flush >= 1) {
		kcp_flush(ss);
	}
	LOGD_F("session [%08" PRIX32 "] send: eof", ss->conv);
	ss->kcp_state = STATE_LINGER;
}

void kcp_recv(struct session *restrict ss)
{
	switch (ss->kcp_state) {
	case STATE_CONNECT:
	case STATE_CONNECTED:
		break;
	default:
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
	}
}

void kcp_update(struct session *restrict ss)
{
	switch (ss->kcp_state) {
	case STATE_CONNECT:
	case STATE_CONNECTED:
	case STATE_LINGER:
		break;
	default:
		return;
	}
	struct server *restrict s = ss->server;
	if (ss->need_flush) {
		ikcp_flush(ss->kcp);
		ss->need_flush = false;
	} else {
		const ev_tstamp now = ev_now(s->loop);
		const uint32_t now_ms = tstamp2ms(now);
		ikcp_update(ss->kcp, now_ms);
	}
	session_recv(ss);
	if (ss->kcp_state == STATE_CONNECTED && ss->tcp_fd != -1) {
		struct ev_io *restrict w_read = &ss->w_read;
		const int waitsnd = ikcp_waitsnd(ss->kcp);
		const int window_size = (int)ss->kcp->snd_wnd;
		if (waitsnd < window_size && !ev_is_active(w_read)) {
			ev_io_start(s->loop, w_read);
		}
	}
}

void kcp_flush(struct session *ss)
{
	ss->need_flush = true;
	kcp_update(ss);
}

static bool kcp_update_iter(
	struct hashtable *t, const hashkey_t *key, void *value, void *user)
{
	UNUSED(t);
	UNUSED(key);
	struct session *restrict ss = value;
	kcp_update(ss);
	struct pktqueue *restrict q = user;
	return q->mq_send_len < q->mq_send_cap;
}

void kcp_update_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);
	struct server *restrict s = watcher->data;
	table_iterate(s->sessions, kcp_update_iter, s->pkt.queue);
}

void kcp_notify_update(struct server *restrict s)
{
	table_iterate(s->sessions, kcp_update_iter, s->pkt.queue);
}
