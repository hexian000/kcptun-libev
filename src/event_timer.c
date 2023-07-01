/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "event.h"
#include "event_impl.h"
#include "algo/hashtable.h"
#include "utils/mcache.h"
#include "utils/slog.h"
#include "session.h"
#include "util.h"
#include "server.h"
#include "pktqueue.h"
#include "nonce.h"

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
			LOGW_F("session [%08" PRIX32 "] "
			       "timeout: not seen in %.01fs",
			       ss->conv, not_seen);
			session_stop(ss);
			session_kcp_stop(ss);
			break;
		}
		if (!ss->is_accepted && not_seen > s->session_keepalive) {
			LOGD_F("session [%08" PRIX32 "] kcp: send keepalive",
			       ss->conv);
			(void)kcp_sendmsg(ss, SMSG_KEEPALIVE);
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

static void tick_keepalive(struct server *restrict s)
{
	if ((s->conf->mode & MODE_CLIENT) == 0) {
		return;
	}
	if (!isnormal(s->keepalive) || signbit(s->keepalive)) {
		return;
	}
	const ev_tstamp now = ev_now(s->loop);
	if (s->pkt.inflight_ping != TSTAMP_NIL) {
		if (now - s->pkt.inflight_ping < 4.0) {
			return;
		}
		LOGD("ping timeout");
		s->pkt.inflight_ping = TSTAMP_NIL;
	}
	if (now - s->last_resolve_time > s->timeout &&
	    (s->pkt.last_recv_time == TSTAMP_NIL ||
	     now - s->pkt.last_recv_time > s->timeout)) {
		LOGW("peer is not responding, try resolve addresses");
		(void)server_resolve(s);
#if WITH_CRYPTO
		struct noncegen *restrict noncegen = s->pkt.queue->noncegen;
		if (noncegen != NULL) {
			noncegen_init(noncegen);
		}
#endif
		s->last_resolve_time = now;
	}
	if (s->pkt.last_send_time != TSTAMP_NIL &&
	    now - s->pkt.last_send_time < s->keepalive) {
		return;
	}
	server_ping(s);
}

static void tick_listener(struct server *restrict s)
{
	/* check & restart accept watchers */
	struct ev_io *restrict w_accept = &s->listener.w_accept;
	if (s->listener.fd != -1 && !ev_is_active(w_accept)) {
		ev_io_start(s->loop, w_accept);
	}
}

static void tick_timeout(struct server *restrict s)
{
	/* session timeout */
	table_filter(s->sessions, timeout_filt, s);

	/* mcache maintenance */
	mcache_shrink(msgpool, 1);
}

void ticker_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	const ev_tstamp now = ev_now(loop);
	struct server *restrict s = (struct server *)watcher->data;
	TICK_INTERVAL(now, 1.0, tick_keepalive(s));
	TICK_INTERVAL(now, 5.0, tick_listener(s));
	TICK_INTERVAL(now, 10.0, tick_timeout(s));
}
