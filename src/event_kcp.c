/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "event.h"
#include "pktqueue.h"
#include "server.h"
#include "session.h"
#include "util.h"

#include "algo/hashtable.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include "ikcp.h"

#include <ev.h>

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int kcp_output(const char *buf, const int len, ikcpcb *kcp, void *user)
{
	UNUSED(kcp);
	struct session *restrict ss = user;
	struct server *restrict s = ss->server;
	struct msgframe *restrict msg = msgframe_new(s->pkt.queue);
	if (msg == NULL) {
		LOGOOM();
		return -1;
	}
	msg->addr = ss->raddr;
	ASSERT(len > 0 && len + msg->off <= MAX_PACKET_SIZE);
	unsigned char *dst = msg->buf + msg->off;
	memcpy(dst, buf, len);
	msg->len = len;
	s->stats.kcp_tx += len;
	ss->stats.kcp_tx += len;
	return queue_send(s, msg) ? len : -1;
}

bool kcp_cansend(const struct session *restrict ss)
{
	struct IKCPCB *restrict kcp = ss->kcp;
	return kcp != NULL && ikcp_waitsnd(kcp) < kcp->snd_wnd;
}

bool kcp_canrecv(const struct session *restrict ss)
{
	struct IKCPCB *restrict kcp = ss->kcp;
	return kcp != NULL && ikcp_peeksize(kcp) > 0;
}

static bool kcp_send(
	struct session *restrict ss, const unsigned char *buf, const size_t len)
{
	ASSERT(len <= INT_MAX);
	const int r = ikcp_send(ss->kcp, (char *)buf, (int)len);
	if (r < 0) {
		return false;
	}
	LOGV_F("session [%08" PRIX32 "] kcp: send %zu bytes", ss->conv, len);
	ss->last_send = ev_now(ss->server->loop);
	return true;
}

bool kcp_sendmsg(struct session *restrict ss, const uint16_t msg)
{
	unsigned char buf[TLV_HEADER_SIZE];
	struct tlv_header header = {
		.msg = msg,
		.len = TLV_HEADER_SIZE,
	};
	tlv_header_write(buf, header);
	return kcp_send(ss, buf, TLV_HEADER_SIZE);
}

bool kcp_push(struct session *restrict ss)
{
	ASSERT(ss->rbuf->len <= SESSION_BUF_SIZE - TLV_HEADER_SIZE);
	const size_t len = TLV_HEADER_SIZE + ss->rbuf->len;
	struct tlv_header header = {
		.msg = SMSG_PUSH,
		.len = (uint16_t)len,
	};
	tlv_header_write(ss->rbuf->data, header);
	ss->rbuf->len = 0;
	return kcp_send(ss, ss->rbuf->data, len);
}

void kcp_recv(struct session *restrict ss)
{
	unsigned char *start = ss->wbuf->data + ss->wbuf->len;
	size_t cap = SESSION_BUF_SIZE - ss->wbuf->len;
	size_t nrecv = 0;
	while (cap > 0) {
		const int r = ikcp_recv(ss->kcp, (char *)start, (int)cap);
		if (r <= 0) {
			break;
		}
		nrecv += r;
		start += r;
		cap -= r;
	}
	if (nrecv > 0) {
		ss->wbuf->len += nrecv;
		ss->last_recv = ev_now(ss->server->loop);
		LOGV_F("session [%08" PRIX32 "] kcp: "
		       "recv %zu bytes, cap: %zu bytes",
		       ss->conv, nrecv, cap);
	}
}

static void kcp_update(struct session *restrict ss)
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
	const ev_tstamp now = ev_now(s->loop);
	const uint32_t now_ms = tstamp2ms(now);
	ikcp_update(ss->kcp, now_ms);
	tcp_notify(ss);
}

static bool kcp_update_iter(
	const struct hashtable *t, const struct hashkey key, void *element,
	void *user)
{
	UNUSED(t);
	UNUSED(key);
	UNUSED(user);
	struct session *restrict ss = element;
	ASSERT(key.data == ss->key);
	kcp_update(ss);
	return true;
}

void kcp_update_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	UNUSED(loop);
	CHECK_REVENTS(revents, EV_TIMER);
	struct server *restrict s = watcher->data;
	table_iterate(s->sessions, kcp_update_iter, NULL);
}
