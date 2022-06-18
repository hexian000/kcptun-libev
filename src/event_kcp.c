#include "event.h"
#include "event_impl.h"
#include "server.h"
#include "session.h"
#include "util.h"

#include <ev.h>
#include <stdint.h>

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

void kcp_close(struct session *restrict ss)
{
	if (ss->kcp_closed) {
		return;
	}
	ss->state = STATE_LINGER;
	unsigned char buf[TLV_HEADER_SIZE];
	struct tlv_header header = (struct tlv_header){
		.msg = SMSG_CLOSE,
		.len = TLV_HEADER_SIZE,
	};
	tlv_header_write(buf, header);
	int r = ikcp_send(ss->kcp, (char *)buf, TLV_HEADER_SIZE);
	LOGD_F("session [%08" PRIX32 "] kcp close: %d", ss->kcp->conv, r);
	if (r < 0) {
		/* TODO */
		UTIL_ASSERT(0);
		return;
	}
	ss->stats.kcp_out += TLV_HEADER_SIZE;
	ss->server->stats.kcp_out += TLV_HEADER_SIZE;
	ss->kcp_closed = true;
	ss->last_seen = ev_now(ss->server->loop);
}

bool kcp_send(struct session *restrict ss)
{
	UTIL_ASSERT(ss->rbuf_len <= SESSION_BUF_SIZE - TLV_HEADER_SIZE);
	if (ss->rbuf_len == 0) {
		return true;
	}
	struct server *restrict s = ss->server;
	const int waitsnd = ikcp_waitsnd(ss->kcp);
	const int window_size = s->conf->kcp_sndwnd;
	if (waitsnd >= window_size) {
		return false;
	}

	const size_t len = TLV_HEADER_SIZE + ss->rbuf_len;
	struct tlv_header header = (struct tlv_header){
		.msg = SMSG_DATA,
		.len = (uint16_t)len,
	};
	tlv_header_write(ss->rbuf, header);
	int r = ikcp_send(ss->kcp, (char *)ss->rbuf, len);
	if (r < 0) {
		return false;
	}
	ss->rbuf_len = 0;
	/* invalidate last ikcp_check */
	ss->kcp_checked = false;

	ss->stats.kcp_out += len;
	s->stats.kcp_out += len;
	LOGV_F("session [%08" PRIX32 "] kcp send: %zu bytes", ss->kcp->conv,
	       len);
	return true;
}

size_t kcp_recv(struct session *restrict ss)
{
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
		       ss->kcp->conv, nrecv, cap);
		ss->last_seen = ev_now(ss->server->loop);
	}

	if (ss->wbuf_len < TLV_HEADER_SIZE) {
		/* no data available */
		return 0;
	}
	struct tlv_header header = tlv_header_read(ss->wbuf);
	UTIL_ASSERT(
		header.len >= TLV_HEADER_SIZE &&
		header.len <= SESSION_BUF_SIZE);
	if (ss->wbuf_len < header.len) {
		/* incomplete data packet */
		return 0;
	}
	switch (header.msg) {
	case SMSG_DATA: {
		/* tcp connection is lost, discard packet */
		if (ss->tcp_fd == -1) {
			ss->wbuf_len = 0;
			return 0;
		}
		return (size_t)header.len - TLV_HEADER_SIZE;
	} break;
	case SMSG_CLOSE: {
		UTIL_ASSERT(header.len == TLV_HEADER_SIZE);
		LOGD_F("session [%08" PRIX32 "] kcp eof", ss->kcp->conv);
		ss->kcp_closed = true;
		session_shutdown(ss);
		ss->state = STATE_LINGER;
		return 0;
	} break;
	}
	LOGE_F("unknown msg: %04" PRIX16 ", %04" PRIX16, header.msg,
	       header.len);
	kcp_close(ss);
	return 0;
}

static void kcp_update(struct session *restrict ss)
{
	if (ss->state != STATE_CONNECTED && ss->state != STATE_LINGER) {
		return;
	}
	struct server *restrict s = ss->server;
	const uint32_t now_ms = tstamp2ms(ev_now(s->loop));
	if (!ss->kcp_checked || (int32_t)(now_ms - ss->kcp_next) >= 0) {
		ikcp_update(ss->kcp, now_ms);
		tcp_notify_write(ss);
		ss->kcp_next = ikcp_check(ss->kcp, now_ms);
		UTIL_ASSERT((int32_t)(ss->kcp_next - now_ms) < 5000);
		ss->kcp_checked = true;
	}
	if (ss->w_read != NULL && !ev_is_active(ss->w_read)) {
		const int waitsnd = ikcp_waitsnd(ss->kcp);
		const int window_size = s->conf->kcp_sndwnd;
		if (waitsnd < window_size) {
			tcp_recv(ss);
		}
	}
	if (ss->state == STATE_LINGER && !ss->kcp_closed) {
		kcp_close(ss);
	}
}

void kcp_notify(struct session *restrict ss)
{
	kcp_update(ss);
}

bool kcp_update_iter(
	struct hashtable *t, const hashkey_t *key, void *value, void *user)
{
	UNUSED(t);
	UNUSED(key);
	UNUSED(user);
	kcp_update((struct session *)value);
	return true;
}

void kcp_notify_all(struct server *restrict s)
{
	table_iterate(s->sessions, kcp_update_iter, NULL);
}

void kcp_update_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);
	kcp_notify_all((struct server *)watcher->data);
}
