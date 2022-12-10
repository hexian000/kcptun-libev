/* kcptun-libev (c) 2019-2022 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "event.h"
#include "event_impl.h"
#include "utils/serialize.h"
#include "utils/strbuilder.h"
#include "session.h"
#include "util.h"
#include "server.h"
#include "pktqueue.h"
#include "nonce.h"

#include "kcp/ikcp.h"
#include <ev.h>

#include <inttypes.h>
#include <math.h>

static bool
timeout_filt(struct hashtable *t, const hashkey_t *key, void *value, void *user)
{
	UNUSED(t);
	UNUSED(key);
	struct server *restrict s = user;
	const ev_tstamp now = ev_now(s->loop);
	struct session *restrict ss = value;
	ev_tstamp not_seen = now - ss->created;
	switch (ss->kcp_state) {
	case STATE_INIT:
	case STATE_CONNECT:
		if (not_seen > s->dial_timeout) {
			LOGW_F("session [%08" PRIX32 "] timeout: kcp connect",
			       ss->conv);
			session_stop(ss);
			kcp_reset(ss);
			break;
		}
		break;
	case STATE_CONNECTED:
		if (ss->last_recv != TSTAMP_NIL) {
			not_seen = now - ss->last_recv;
		}
		if (not_seen > s->session_timeout) {
			LOGW_F("session [%08" PRIX32 "] timeout: keepalive",
			       ss->conv);
			session_stop(ss);
			session_kcp_stop(ss);
			break;
		}
		if (!ss->is_accepted && not_seen > s->session_keepalive) {
			LOGD_F("session [%08" PRIX32 "] kcp: send keepalive",
			       ss->conv);
			kcp_sendmsg(ss, SMSG_KEEPALIVE);
		}
		break;
	case STATE_LINGER:
		if (ss->last_send != TSTAMP_NIL) {
			not_seen = now - ss->last_send;
		}
		if (not_seen > s->linger) {
			LOGD_F("session [%08" PRIX32 "] timeout: linger",
			       ss->conv);
			session_kcp_stop(ss);
		}
		break;
	case STATE_TIME_WAIT:
		if (ss->last_reset != TSTAMP_NIL) {
			not_seen = now - ss->last_reset;
		}
		if (not_seen > s->time_wait) {
			session_free(ss);
			return false;
		}
		break;
	}
	return true;
}

void timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct server *restrict s = (struct server *)watcher->data;

	/* check & restart accept watchers */
	struct ev_io *restrict w_accept = &s->listener.w_accept;
	if (s->listener.fd != -1 && !ev_is_active(w_accept)) {
		ev_io_start(loop, w_accept);
	}

	/* timeout check */
	table_filter(s->sessions, timeout_filt, s);

	/* ping */
	if ((s->conf->mode & MODE_CLIENT) == 0) {
		return;
	}
	if (!(s->keepalive > 0.0)) {
		return;
	}
	const ev_tstamp now = ev_now(loop);
	if (s->pkt.inflight_ping != TSTAMP_NIL) {
		if (now - s->pkt.inflight_ping < 4.0) {
			return;
		}
		LOGD("ping timeout");
		s->pkt.inflight_ping = TSTAMP_NIL;
	}
	const double timeout = fmax(s->keepalive * 3.0, 60.0);
	if (now - s->last_resolve_time > timeout &&
	    (s->pkt.last_recv_time == TSTAMP_NIL ||
	     now - s->pkt.last_recv_time > timeout)) {
		LOGD("peer is not responding, try resolve addresses");
		(void)server_resolve(s);
#if WITH_CRYPTO
		noncegen_init(s->pkt.queue->noncegen);
#endif
		s->last_resolve_time = now;
	}
	if (s->pkt.last_send_time != TSTAMP_NIL &&
	    now - s->pkt.last_send_time < s->keepalive) {
		return;
	}
	const uint32_t tstamp = tstamp2ms(now);
	unsigned char b[sizeof(uint32_t)];
	write_uint32(b, tstamp);
	ss0_send(s, s->conf->kcp_connect.sa, S0MSG_PING, b, sizeof(b));
	s->pkt.inflight_ping = now;
}
