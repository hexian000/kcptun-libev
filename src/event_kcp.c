#include "event.h"
#include "event_impl.h"
#include "packet.h"
#include "server.h"
#include "session.h"
#include "util.h"

#include <ev.h>
#include <stdint.h>
#include <string.h>

static inline struct tlv_header tlv_header_read(const unsigned char *d)
{
	return (struct tlv_header){
		.msg = read_uint16(d),
		.len = read_uint16(d + sizeof(uint16_t)),
	};
}

static inline void tlv_header_write(unsigned char *d, struct tlv_header header)
{
	write_uint16(d, header.msg);
	write_uint16(d + sizeof(uint16_t), header.len);
}

/* session messages */
#define SMSG_DATA (UINT16_C(0x0000))
#define SMSG_CLOSE (UINT16_C(0x0001))
#define SMSG_KEEPALIVE (UINT16_C(0x0002))

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
	(void)kcp_send(ss);
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
}

size_t kcp_send(struct session *restrict ss)
{
	UTIL_ASSERT(ss->rbuf_len <= SESSION_BUF_SIZE - TLV_HEADER_SIZE);
	if (ss->rbuf_len == 0) {
		return 0;
	}
	struct server *restrict s = ss->server;
	const int waitsnd = ikcp_waitsnd(ss->kcp);
	const int window_size = s->conf->kcp_sndwnd;
	if (waitsnd >= window_size) {
		return 0;
	}

	const size_t len = TLV_HEADER_SIZE + ss->rbuf_len;
	struct tlv_header header = (struct tlv_header){
		.msg = SMSG_DATA,
		.len = (uint16_t)len,
	};
	tlv_header_write(ss->rbuf, header);
	int r = ikcp_send(ss->kcp, (char *)ss->rbuf, len);
	if (r < 0) {
		return 0;
	}
	ss->rbuf_len = 0;
	/* invalidate last ikcp_check */
	ss->kcp_checked = false;

	ss->last_send = ev_now(ss->server->loop);
	ss->stats.kcp_out += len;
	s->stats.kcp_out += len;
	LOGV_F("session [%08" PRIX32 "] kcp send: %zu bytes", ss->kcp->conv,
	       len);
	return len;
}

static void consume_wbuf(struct session *restrict ss, size_t len)
{
	ss->wbuf_len -= len;
	if (ss->wbuf_len > 0) {
		memmove(ss->wbuf, ss->wbuf + len, ss->wbuf_len);
	}
}

void kcp_recv(struct session *restrict ss)
{
	if (ss->kcp_closed) {
		ikcp_recv(ss->kcp, (char *)ss->wbuf, SESSION_BUF_SIZE);
		return;
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
		       ss->kcp->conv, nrecv, cap);
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
	if (ss->wbuf_len < header.len) {
		/* incomplete data packet */
		return;
	}
	switch (header.msg) {
	case SMSG_DATA: {
		/* tcp connection is lost, discard packet */
		if (ss->tcp_fd == -1) {
			consume_wbuf(ss, header.len);
			return;
		}
		ss->wbuf_navail = (size_t)header.len - TLV_HEADER_SIZE;
		return;
	} break;
	case SMSG_CLOSE: {
		UTIL_ASSERT(header.len == TLV_HEADER_SIZE);
		LOGD_F("session [%08" PRIX32 "] kcp eof", ss->kcp->conv);
		ss->wbuf_len = 0;
		ss->kcp_closed = true;
		session_shutdown(ss);
		ss->state = STATE_LINGER;
		return;
	} break;
	case SMSG_KEEPALIVE: {
		UTIL_ASSERT(header.len == TLV_HEADER_SIZE);
		consume_wbuf(ss, header.len);
		return;
	} break;
	}
	LOGE_F("unknown msg: %04" PRIX16 ", %04" PRIX16, header.msg,
	       header.len);
	kcp_close(ss);
	return;
}

static void kcp_update(struct session *restrict ss)
{
	if (ss->state != STATE_CONNECTED && ss->state != STATE_LINGER) {
		return;
	}
	struct server *restrict s = ss->server;
	if (s->udp.packets->mq_send_len == MQ_SEND_SIZE) {
		return;
	}
	const uint32_t now_ms = tstamp2ms(ev_now(s->loop));
	if (!ss->kcp_checked || (int32_t)(now_ms - ss->kcp_next) >= 0) {
		ikcp_update(ss->kcp, now_ms);
		kcp_recv(ss);
		tcp_notify_write(ss);
		ss->kcp_next = ikcp_check(ss->kcp, now_ms);
		UTIL_ASSERT((int32_t)(ss->kcp_next - now_ms) < 5000);
		ss->kcp_checked = true;
	}
	if (ss->w_read != NULL && !ev_is_active(ss->w_read)) {
		const int waitsnd = ikcp_waitsnd(ss->kcp);
		const int window_size = s->conf->kcp_sndwnd;
		if (waitsnd < window_size) {
			ev_io_start(s->loop, ss->w_read);
		}
	}
	if (ss->state == STATE_LINGER && !ss->kcp_closed) {
		kcp_close(ss);
	}
}

void kcp_notify(struct session *restrict ss)
{
	ss->kcp_checked = false;
	kcp_update(ss);
}

static bool kcp_notify_iter(
	struct hashtable *t, const hashkey_t *key, void *value, void *user)
{
	UNUSED(t);
	UNUSED(key);
	UNUSED(user);
	kcp_notify((struct session *)value);
	return true;
}

void kcp_notify_all(struct server *s)
{
	table_iterate(s->sessions, kcp_notify_iter, NULL);
}

static bool kcp_update_iter(
	struct hashtable *t, const hashkey_t *key, void *value, void *user)
{
	UNUSED(t);
	UNUSED(key);
	UNUSED(user);
	kcp_update((struct session *)value);
	return true;
}

void kcp_update_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);
	struct server *restrict s = (struct server *)watcher->data;
	table_iterate(s->sessions, kcp_update_iter, NULL);
}
