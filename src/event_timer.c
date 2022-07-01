#include "conf.h"
#include "event_impl.h"
#include "hashtable.h"
#include "packet.h"
#include "serialize.h"
#include "server.h"
#include "session.h"
#include "slog.h"
#include "sockutil.h"
#include "util.h"

#include <ev.h>
#include <stdint.h>
#include <sys/socket.h>

#include <math.h>

struct session_stats {
	size_t data[STATE_MAX];
	ev_tstamp now;
};

static void print_session_info(
	struct session *restrict ss, struct link_stats *restrict session_stats)
{
	LOGD_F("session [%08" PRIX32
	       "] state: %d tcp_in: %zu kcp_out: %zu udp_out: %zu udp_in: %zu kcp_in: %zu tcp_out: %zu",
	       ss->conv, ss->state, session_stats->tcp_in,
	       session_stats->kcp_out, session_stats->udp_out,
	       session_stats->udp_in, session_stats->kcp_in,
	       session_stats->tcp_out);
	char addr_str[64];
	format_sa(
		(struct sockaddr *)&ss->udp_remote, addr_str, sizeof(addr_str));
	LOGD_F("      - [%08" PRIX32
	       "] buf(%zu, %zu, %zu) kcp_peek=%d kcp_waitsnd=%d addr=%s w_read=%d w_write=%d",
	       ss->conv, ss->rbuf_len, ss->wbuf_len, ss->wbuf_flush,
	       ikcp_peeksize(ss->kcp), ikcp_waitsnd(ss->kcp), addr_str,
	       ss->w_read ? ev_is_active(ss->w_read) : -1,
	       ss->w_write ? ev_is_active(ss->w_write) : -1);
}

bool timeout_filt(
	struct hashtable *t, const hashkey_t *key, void *value, void *user)
{
	UNUSED(t);
	UNUSED(key);

	bool remove = false;

	struct session *restrict ss = value;
	struct server *restrict s = ss->server;
	struct session_stats *restrict stats = user;
	UTIL_ASSERT(ss->state < STATE_MAX);
	stats->data[ss->state]++;
	const double last_seen =
		ss->last_send > ss->last_recv ? ss->last_send : ss->last_recv;
	const double not_seen = stats->now - last_seen;

	switch (ss->state) {
	case STATE_CONNECT:
	case STATE_CONNECTED: {
		if (not_seen > s->timeout) {
			LOGI_F("session [%08" PRIX32 "] timed out", ss->conv);
			session_shutdown(ss);
			kcp_close(ss);
		} else if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
			print_session_info(ss, &(ss->stats));
		}
	} break;
	case STATE_LINGER: {
		if (not_seen > s->linger) {
			LOGD_F("session [%08" PRIX32 "] linger timed out",
			       ss->conv);
			ss->state = STATE_TIME_WAIT;
		} else if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
			print_session_info(ss, &(ss->stats));
		}
	} break;
	case STATE_TIME_WAIT: {
		if (not_seen > s->time_wait) {
			LOGD_F("session [%08" PRIX32 "] wait timed out",
			       ss->conv);
			ss->state = STATE_CLOSED;
			remove = true;
			session_free(ss);
		}
	} break;
	case STATE_CLOSED: {
		UTIL_ASSERT(0);
	} break;
	default: {
		LOGW_F("unexpected session state: %d", ss->state);
		UTIL_ASSERT(0);
		remove = true;
		session_free(ss);
	} break;
	}
	return !remove;
}

static void traffic_stats(struct server *restrict s, const ev_tstamp now)
{
	static struct link_stats last_stats = { 0 };
	static double last_stat_time = NAN;
	if (!isfinite(last_stat_time)) {
		last_stat_time = now;
		last_stats = s->stats;
		return;
	}
	const double dt = now - last_stat_time;
	struct link_stats dstats = (struct link_stats){
		.udp_in = s->stats.udp_in - last_stats.udp_in,
		.udp_out = s->stats.udp_out - last_stats.udp_out,
		.kcp_in = s->stats.kcp_in - last_stats.kcp_in,
		.kcp_out = s->stats.kcp_out - last_stats.kcp_out,
		.tcp_in = s->stats.tcp_in - last_stats.tcp_in,
		.tcp_out = s->stats.tcp_out - last_stats.tcp_out,
	};
	double udp_up, udp_down, tcp_up, tcp_down;
	udp_up = (dstats.udp_out >> 10u) / dt;
	udp_down = (dstats.udp_in >> 10u) / dt;
	tcp_up = (dstats.tcp_in >> 10u) / dt;
	tcp_down = (dstats.tcp_out >> 10u) / dt;
	LOGD_F("traffic(KiB/s) udp up/down: %.1f/%.1f; tcp up/down: %.1f/%.1f; efficiency: %.1f%%/%.1f%%",
	       udp_up, udp_down, tcp_up, tcp_down, tcp_up / udp_up * 100.0,
	       tcp_down / udp_down * 100.0);
	LOGD_F("total udp up/down: %zu/%zu; tcp up/down: %zu/%zu; efficiency: %.1f%%/%.1f%%",
	       s->stats.udp_out, s->stats.udp_in, s->stats.tcp_in,
	       s->stats.tcp_out, s->stats.tcp_in * 100.0 / s->stats.udp_out,
	       s->stats.tcp_out * 100.0 / s->stats.udp_in);
	last_stat_time = now;
	last_stats = s->stats;
}

static void timeout_check(struct server *restrict s, const ev_tstamp now)
{
	const double check_interval = 10.0;
	static ev_tstamp last_check = 0.0;
	if (now - last_check < check_interval) {
		return;
	}
	last_check +=
		floor((now - last_check) / check_interval) * check_interval;
	const size_t n_sessions = table_size(s->sessions);
	if (n_sessions > 0) {
		struct session_stats stats = (struct session_stats){
			.data = { 0 },
			.now = now,
		};
		table_filter(s->sessions, timeout_filt, &stats);
		LOGD_F("=== %zu sessions: %zu connected, %zu linger, w_read=%d, w_write=%d",
		       n_sessions, stats.data[STATE_CONNECTED],
		       stats.data[STATE_LINGER],
		       s->udp.w_read ? ev_is_active(s->udp.w_read) : -1,
		       s->udp.w_write ? ev_is_active(s->udp.w_write) : -1);
		if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
			traffic_stats(s, now);
		}
	}
}

void keepalive_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct server *restrict s = (struct server *)watcher->data;
	const ev_tstamp now = ev_now(loop);
	timeout_check(s, now);

	if (s->conf->mode == MODE_SERVER) {
		return;
	}
	if (now - s->udp.last_recv_time > 60.0 &&
	    now - s->last_resolve_time > 60.0) {
		LOGD_F("remote not seen for %.0fs, try resolve addresses",
		       now - s->udp.last_recv_time);
		conf_resolve(s->conf);
		s->last_resolve_time = now;
	}
	if (now - s->udp.last_send_time < s->keepalive) {
		return;
	}
	const uint32_t tstamp = tstamp2ms(ev_time());
	unsigned char b[sizeof(uint32_t)];
	write_uint32(b, tstamp);
	send_ss0(s, s->conf->udp_connect.sa, S0MSG_PING, b, sizeof(b));
}
