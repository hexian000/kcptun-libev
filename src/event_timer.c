/* kcptun-libev (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"
#include "event.h"
#include "nonce.h"
#include "pktqueue.h"
#include "server.h"
#include "session.h"
#include "util.h"

#include "algo/hashtable.h"
#include "utils/mcache.h"
#include "utils/slog.h"

#include <ev.h>

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

static bool timeout_filt(
	const struct hashtable *t, const struct hashkey key, void *element,
	void *user)
{
	UNUSED(t);
	struct server *restrict s = user;
	const ev_tstamp now = ev_now(s->loop);
	struct session *restrict ss = element;
	(void)key, assert(key.data == ss->key);
	ev_tstamp not_seen = now - ss->created;
	switch (ss->kcp_state) {
	case STATE_INIT:
	case STATE_CONNECT:
		if (not_seen > s->dial_timeout) {
			LOGW_F("session [%08" PRIX32 "] timeout: kcp connect",
			       ss->conv);
			session_tcp_stop(ss);
			session_kcp_close(ss);
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
			session_tcp_stop(ss);
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

void listener_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct listener *restrict l = watcher->data;
	/* check & restart accept watchers */
	struct ev_io *restrict w_accept = &l->w_accept;
	if (l->fd != -1 && !ev_is_active(w_accept)) {
		ev_io_start(loop, w_accept);
	}
	struct ev_io *restrict w_accept_http = &l->w_accept_http;
	if (l->fd_http != -1 && !ev_is_active(w_accept_http)) {
		ev_io_start(loop, w_accept_http);
	}
}

void keepalive_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct server *restrict s = watcher->data;
	const int mode = s->conf->mode;
	if ((mode & MODE_RENDEZVOUS) != 0) {
		if ((mode & MODE_SERVER) != 0) {
			udp_rendezvous(s, S0MSG_LISTEN);
		}
		if ((mode & MODE_CLIENT) != 0 && !s->pkt.connected) {
			udp_rendezvous(s, S0MSG_CONNECT);
			watcher->repeat = s->ping_timeout;
			ev_timer_again(loop, watcher);
			return;
		}
	}
	if ((mode & MODE_CLIENT) == 0) {
		return;
	}

	const ev_tstamp now = ev_now(loop);
	if (s->pkt.inflight_ping != TSTAMP_NIL) {
		const double next = s->pkt.inflight_ping + s->ping_timeout;
		if (now < next) {
			watcher->repeat = next - now;
			ev_timer_again(loop, watcher);
			return;
		}
		LOGD("ping timeout");
		s->pkt.inflight_ping = TSTAMP_NIL;
	}

	if (s->pkt.last_send_time != TSTAMP_NIL) {
		const double next = s->pkt.last_send_time + s->keepalive;
		if (now < next) {
			watcher->repeat = next - now;
			ev_timer_again(loop, watcher);
			return;
		}
	}

	server_ping(s);
	watcher->repeat = s->ping_timeout;
	ev_timer_again(loop, watcher);
}

void resolve_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct server *restrict s = watcher->data;
	const ev_tstamp now = ev_now(loop);

	if (s->last_resolve_time != TSTAMP_NIL) {
		const double next = s->last_resolve_time + s->timeout;
		if (now < next) {
			watcher->repeat = next - now;
			ev_timer_again(loop, watcher);
			return;
		}
	}

	if (s->pkt.last_recv_time != TSTAMP_NIL) {
		const double next = s->pkt.last_recv_time + s->timeout;
		if (now < next) {
			watcher->repeat = next - now;
			ev_timer_again(loop, watcher);
			return;
		}
	}

	if ((s->conf->mode & MODE_CLIENT) != 0) {
		LOGW("peer is not responding, try resolve addresses");
	} else {
		LOGI("server is idle, try resolve addresses");
	}
	(void)server_resolve(s);
#if WITH_CRYPTO
	struct noncegen *restrict noncegen = s->pkt.queue->noncegen;
	if (noncegen != NULL) {
		noncegen_init(noncegen);
	}
#endif
	s->last_resolve_time = now;

	watcher->repeat = s->timeout;
	ev_timer_again(loop, watcher);
}

void timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	UNUSED(loop);
	CHECK_REVENTS(revents, EV_TIMER);
	struct server *restrict s = watcher->data;

	/* session timeout */
	s->sessions = table_filter(s->sessions, timeout_filt, s);

	/* mcache maintenance */
	mcache_shrink(msgpool, 1);
}
