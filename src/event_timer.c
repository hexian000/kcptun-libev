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

struct print_session_ctx {
	size_t num_in_state[STATE_MAX];
	ev_tstamp now;
	struct strbuilder sb;
};

static bool print_session_iter(
	struct hashtable *t, const hashkey_t *key, void *value, void *user)
{
	UNUSED(t);
	UNUSED(key);
	struct session *restrict ss = value;
	struct print_session_ctx *restrict ctx = user;
	ctx->num_in_state[ss->state]++;
	char addr_str[64];
	format_sa(&ss->raddr.sa, addr_str, sizeof(addr_str));
	const double last_seen =
		ss->last_send > ss->last_recv ? ss->last_send : ss->last_recv;
	const double not_seen = ctx->now - last_seen;
	(void)strbuilder_appendf(
		&ctx->sb, 4096,
		"    [%08" PRIX32 "] "
		"%c peer=%s seen=%.0lfs "
		"rtt=%" PRId32 " rto=%" PRId32 " waitsnd=%d "
		"up/down=%zu/%zu\n",
		ss->conv, session_state_char[ss->state], addr_str, not_seen,
		ss->kcp->rx_srtt, ss->kcp->rx_rto, ikcp_waitsnd(ss->kcp),
		ss->stats.tcp_rx, ss->stats.tcp_tx);
	return true;
}

static void print_session_table(struct server *restrict s, const ev_tstamp now)
{
	const size_t n_sessions = table_size(s->sessions);
	if (n_sessions == 0) {
		return;
	}
	struct print_session_ctx ctx = (struct print_session_ctx){
		.now = now,
	};
	strbuilder_reserve(&ctx.sb, 16384);
	table_iterate(s->sessions, &print_session_iter, &ctx);
	LOGD_F("session table:\n%*s"
	       "    ^ %zu sessions: %zu halfopen, %zu connected, %zu linger, %zu time_wait",
	       (int)ctx.sb.len, ctx.sb.buf, n_sessions,
	       ctx.num_in_state[STATE_HALFOPEN] +
		       ctx.num_in_state[STATE_CONNECT],
	       ctx.num_in_state[STATE_CONNECTED],
	       ctx.num_in_state[STATE_LINGER],
	       ctx.num_in_state[STATE_TIME_WAIT]);
}

static void print_server_stats(struct server *restrict s, const ev_tstamp now)
{
	static struct link_stats last_stats = { 0 };
	static double last_print_time = TSTAMP_NIL;
	if (last_print_time == TSTAMP_NIL) {
		last_print_time = now;
		last_stats = s->stats;
		return;
	}
	if (now - last_print_time < 30.0) {
		return;
	}
	if (table_size(s->sessions) > 0) {
		print_session_table(s, now);
	}

	struct link_stats *restrict stats = &s->stats;
	const double dt = now - last_print_time;
	struct link_stats dstats = (struct link_stats){
		.pkt_rx = stats->pkt_rx - last_stats.pkt_rx,
		.pkt_tx = stats->pkt_tx - last_stats.pkt_tx,
		.kcp_rx = stats->kcp_rx - last_stats.kcp_rx,
		.kcp_tx = stats->kcp_tx - last_stats.kcp_tx,
		.tcp_rx = stats->tcp_rx - last_stats.tcp_rx,
		.tcp_tx = stats->tcp_tx - last_stats.tcp_tx,
	};

	if (dstats.kcp_rx || dstats.kcp_tx || dstats.tcp_rx || dstats.tcp_tx) {
		const double dkcp_rx = (double)(dstats.kcp_rx >> 10u) / dt;
		const double dkcp_tx = (double)(dstats.kcp_tx >> 10u) / dt;
		const double dtcp_rx = (double)(dstats.tcp_tx >> 10u) / dt;
		const double dtcp_tx = (double)(dstats.tcp_rx >> 10u) / dt;
		const double deff_rx =
			(double)dstats.tcp_tx / (double)dstats.kcp_rx;
		const double deff_tx =
			(double)dstats.tcp_rx / (double)dstats.kcp_tx;

		const double kcp_rx = (double)(stats->kcp_rx >> 10u) / dt;
		const double kcp_tx = (double)(stats->kcp_tx >> 10u) / dt;
		const double tcp_rx = (double)(stats->tcp_tx >> 10u) / dt;
		const double tcp_tx = (double)(stats->tcp_rx >> 10u) / dt;
		const double eff_rx =
			(double)stats->tcp_tx / (double)stats->kcp_rx;
		const double eff_tx =
			(double)stats->tcp_rx / (double)stats->kcp_tx;

		LOGD_F("traffic stats (rx/tx, in KiB)\n"
		       "    current kcp: %.1lf/%.1lf; tcp: %.1lf/%.1lf; efficiency: %.1lf%%/%.1lf%%\n"
		       "    total kcp: %.1lf/%.1lf; tcp: %.1lf/%.1lf; efficiency: %.1lf%%/%.1lf%%",
		       dkcp_rx, dkcp_tx, dtcp_rx, dtcp_tx, deff_rx * 100.0,
		       deff_tx * 100.0, kcp_rx, kcp_tx, tcp_rx, tcp_tx,
		       eff_rx * 100.0, eff_tx * 100.0);
	}

	last_print_time = now;
	last_stats = s->stats;
}

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
			ss->state = STATE_TIME_WAIT;
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

static void timeout_check(struct server *restrict s, const ev_tstamp now)
{
	const double check_interval = 10.0;
	static ev_tstamp last_check = TSTAMP_NIL;
	if (last_check != TSTAMP_NIL && now - last_check < check_interval) {
		return;
	}
	last_check = now;
	const size_t n_sessions = table_size(s->sessions);
	if (n_sessions > 0) {
		table_filter(s->sessions, timeout_filt, s);
	}
}

void timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct server *restrict s = (struct server *)watcher->data;
	const ev_tstamp now = ev_now(loop);
	timeout_check(s, now);

	if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
		print_server_stats(s, now);
#if WITH_OBFS
		if (s->pkt.queue->obfs != NULL) {
			obfs_stats(s->pkt.queue->obfs);
		}
#endif
	}

	if ((s->conf->mode & MODE_CLIENT) == 0) {
		return;
	}
	if (!(s->keepalive > 0.0)) {
		return;
	}
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
