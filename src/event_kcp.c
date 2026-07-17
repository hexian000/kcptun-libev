/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "event.h"
#include "pktqueue.h"
#include "server.h"
#include "session.h"
#include "util.h"

#include "algo/hashtable.h"
#include "ikcp.h"
#include "utils/debug.h"
#include "utils/slog.h"

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
	msg->len = (uint16_t)len;
	s->stats.kcp_tx += (uint_least64_t)len;
	ss->stats.kcp_tx += (uint_least64_t)len;
	return queue_send(s, msg) ? len : -1;
}

bool kcp_cansend(const struct session *restrict ss)
{
	const struct IKCPCB *restrict kcp = ss->kcp;
	return kcp != NULL && ikcp_waitsnd(kcp) < kcp->snd_wnd;
}

bool kcp_canrecv(const struct session *restrict ss)
{
	const struct IKCPCB *restrict kcp = ss->kcp;
	return kcp != NULL && ikcp_peeksize(kcp) > 0;
}

static bool kcp_send(
	struct session *restrict ss, const unsigned char *buf, const size_t len)
{
	ASSERT(len <= INT_MAX);
	const int r = ikcp_send(ss->kcp, (const char *)buf, (int)len);
	if (r < 0) {
		LOGW_F("[session:%08" PRIX32 "] kcp: send %zu bytes failed: %d",
		       ss->conv, len, r);
		return false;
	}
	LOGV_F("[session:%08" PRIX32 "] kcp: send %zu bytes", ss->conv, len);
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
	if (!kcp_send(ss, ss->rbuf->data, len)) {
		return false;
	}
	ss->rbuf->len = 0;
	return true;
}

void kcp_recv(struct session *restrict ss)
{
	ASSERT(ss->wbuf->len <= SESSION_BUF_SIZE);
	unsigned char *start;
	size_t cap;
	VBUF_SPACE(start, cap, ss->wbuf);
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
		LOGV_F("[session:%08" PRIX32 "] kcp: "
		       "recv %zu bytes, cap: %zu bytes",
		       ss->conv, nrecv, cap);
	}
}

static void kcp_update(struct session *restrict ss, const uint32_t now_ms)
{
	switch (ss->kcp_state) {
	case KCP_STATE_CONNECT:
	case KCP_STATE_ESTABLISHED:
	case KCP_STATE_LINGER:
		break;
	default:
		return;
	}
	ikcp_update(ss->kcp, now_ms);
	tcp_notify(ss);
}

static bool kcp_update_iter(
	const struct hashtable *t, const void *key, void *element, void *user)
{
	UNUSED(t);
	UNUSED(key);
	struct session *restrict ss = element;
	ASSERT(((const struct hashkey *)key)->data == ss->key);
	const uint32_t now_ms = *(const uint32_t *)user;
	kcp_update(ss, now_ms);
	return true;
}

void kcp_update_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	UNUSED(loop);
	CHECK_REVENTS(revents, EV_TIMER);
	const struct server *restrict s = watcher->data;
	/* not const: &now_ms is passed as table_iterate's void *data */
	uint32_t now_ms = tstamp2ms(ev_now(s->loop));
	table_iterate(s->sessions, kcp_update_iter, &now_ms);
}
