#include "event.h"
#include "event_impl.h"
#include "session.h"
#include "util.h"
#include "strbuilder.h"
#include "server.h"
#include "pktqueue.h"
#include "serialize.h"
#include "nonce.h"
#include "obfs.h"

#include "kcp/ikcp.h"
#include <ev.h>

#include <assert.h>
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
	assert(ss->state < STATE_MAX);
	const double last_seen =
		ss->last_send > ss->last_recv ? ss->last_send : ss->last_recv;
	const double not_seen = now - last_seen;
	switch (ss->state) {
	case STATE_HALFOPEN:
		if (not_seen > s->dial_timeout) {
			LOGW_F("session [%08" PRIX32 "] close: "
			       "kcp dial timed out",
			       ss->conv);
			session_stop(ss);
			kcp_reset(ss);
			return true;
		}
		break;
	case STATE_CONNECT:
	case STATE_CONNECTED:
		if (not_seen > s->session_timeout) {
			LOGW_F("session [%08" PRIX32 "] close: "
			       "timed out in state %d",
			       ss->conv, ss->state);
			session_stop(ss);
			kcp_close(ss);
			return true;
		}
		if (!ss->is_accepted && not_seen > s->session_keepalive) {
			LOGD_F("session [%08" PRIX32 "] send: keepalive",
			       ss->conv);
			kcp_sendmsg(ss, SMSG_KEEPALIVE);
		}
		break;
	case STATE_LINGER:
		if (not_seen > s->linger) {
			LOGD_F("session [%08" PRIX32 "] linger timed out",
			       ss->conv);
			session_set_wait(ss);
		}
		return true;
	case STATE_TIME_WAIT:
		if (not_seen > s->time_wait) {
			session_free(ss);
			return false;
		}
		return true;
	default:
		LOGW_F("unexpected session state: %d (bug?)", ss->state);
		assert(0);
		session_free(ss);
		return false;
	}
	return true;
}

static void timeout_check(struct server *restrict s)
{
	const size_t n_sessions = table_size(s->sessions);
	if (n_sessions > 0) {
		table_filter(s->sessions, timeout_filt, s);
	}
}

void timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct server *restrict s = (struct server *)watcher->data;
	timeout_check(s);

	server_sample(s);
#if WITH_OBFS
	struct obfs *obfs = s->pkt.queue->obfs;
	if (obfs != NULL) {
		obfs_sample(obfs);
	}
#endif

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
	if (now - s->pkt.last_recv_time > timeout &&
	    now - s->last_resolve_time > timeout) {
		LOGD_F("remote not seen for %.0lfs, try resolve addresses",
		       now - s->pkt.last_recv_time);
		(void)server_resolve(s);
#if WITH_CRYPTO
		noncegen_init(s->pkt.queue->noncegen);
#endif
		s->last_resolve_time = now;
	}
	if (now - s->pkt.last_send_time < s->keepalive) {
		return;
	}
	const ev_tstamp ping_ts = ev_time();
	const uint32_t tstamp = tstamp2ms(ping_ts);
	unsigned char b[sizeof(uint32_t)];
	write_uint32(b, tstamp);
	ss0_send(s, s->conf->kcp_connect.sa, S0MSG_PING, b, sizeof(b));
	pkt_flush(s);
	s->pkt.inflight_ping = ping_ts;
}
