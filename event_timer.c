#include "event_impl.h"

bool kcp_update_iter(struct conv_table *restrict table, uint32_t conv,
		     void *session, void *user, bool *delete)
{
	UNUSED(table);
	UNUSED(conv);
	UNUSED(delete);

	struct session *restrict s = (struct session *)session;
	const ev_tstamp now = *(const ev_tstamp *)user;
	const double not_seen = now - s->last_seen;
	switch (s->state) {
	case STATE_CONNECT:
	case STATE_CONNECTED: {
		if (not_seen > s->server->timeout) {
			LOGF_I("session [%08" PRIX32 "] timed out",
			       (uint32_t)s->kcp->conv);
			session_shutdown(s);
			kcp_close(s, now);
			return true;
		}
	} break;
	case STATE_LINGER: {
		if (not_seen > s->server->linger) {
			LOGF_D("session [%08" PRIX32 "] linger timed out",
			       (uint32_t)s->kcp->conv);
			s->state = STATE_CLOSED; /* TIME_WAIT */
			return true;
		}
	} break;
	default: {
		return true;
	} break;
	}

	const uint32_t now_ms = tstamp2ms(now);
	if (!s->kcp_checked || timecomp(s->kcp_next, now_ms) < 0) {
		ikcp_update(s->kcp, now_ms);
		s->kcp_next = ikcp_check(s->kcp, now_ms);
		s->kcp_checked = true;
		if (s->w_write != NULL && ikcp_peeksize(s->kcp) >= 0) {
			ev_io_start(s->server->loop, s->w_write);
		}
	}
	if (s->kcp_blocked) {
		const int window_size = s->server->conf->kcp_sndwnd;
		if (s->w_read != NULL && ikcp_waitsnd(s->kcp) <= window_size) {
			s->kcp_blocked = false;
			ev_io_start(s->server->loop, s->w_read);
		}
	}
	return true;
}

void kcp_update_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct server *server = (struct server *)watcher->data;
	ev_tstamp now = ev_now(loop);
	conv_iterate(server->conv, kcp_update_iter, &now);
	//ev_timer_stop(loop, watcher);
	//ev_io_start(loop, server->udp.w_write);
}

struct session_stats {
	size_t data[STATE_MAX];
};

bool timeout_iter(struct conv_table *restrict table, uint32_t conv,
		  void *session, void *user, bool *delete)
{
	UNUSED(table);

	struct session *restrict s = session;
	struct link_stats *restrict session_stats = &(s->stats);
	LOGF_V("session [%08" PRIX32
	       "] state: %d tcp_in: %zu kcp_out: %zu udp_out: %zu udp_in: %zu kcp_in: %zu tcp_out: %zu",
	       conv, s->state, session_stats->tcp_in, session_stats->kcp_out,
	       session_stats->udp_out, session_stats->udp_in,
	       session_stats->kcp_in, session_stats->tcp_out);
	struct session_stats *restrict stats = user;
	assert(s->state < STATE_MAX);
	stats->data[s->state]++;

	switch (s->state) {
	case STATE_CONNECT:
	case STATE_LINGER: {
	} break;
	case STATE_CONNECTED: {
		if (slice_len(s->rbuf) != 0) {
			LOGF_V("rbuf %zu %zu", s->rbuf.start, s->rbuf.end);
		}
		if (slice_len(s->wbuf) != 0 || s->wbuf.start != s->wbuf_flush) {
			struct tlv_header header =
				tlv_header_read(s->wbuf.data);
			LOGF_V("wbuf %zu %zu %zu %04" PRIX16 " %" PRIu16
			       " peek=%d",
			       s->wbuf.start, s->wbuf_flush, s->wbuf.end,
			       header.msg, header.len, ikcp_peeksize(s->kcp));
		}
	} break;
	case STATE_CLOSED: {
		*delete = true;
		session_free(s);
	} break;
	default: {
		LOGF_W("unexpected session state: %d", s->state);
		assert(0);
		*delete = true;
		session_free(s);
	} break;
	}
	return true;
}

struct session0_header {
	uint32_t zero;
	uint16_t what;
};

#define SESSION0_HEADER_SIZE (sizeof(uint32_t) + sizeof(uint16_t))

static inline struct session0_header s0_header_read(const char *d)
{
	return (struct session0_header){
		.zero = read_uint32((const uint8_t *)d),
		.what = read_uint16((const uint8_t *)d + sizeof(uint32_t)),
	};
}

static inline void s0_header_write(char *d, struct session0_header header)
{
	write_uint32((uint8_t *)d, header.zero);
	write_uint16((uint8_t *)d + sizeof(uint32_t), header.what);
}

struct keepalive_msg {
	uint32_t timestamp;
};

#define SESSION0_KEEPALIVE_SIZE sizeof(struct keepalive_msg)

static inline struct keepalive_msg s0_keepalive_read(const char *d)
{
	return (struct keepalive_msg){
		.timestamp = read_uint32((const uint8_t *)d),
	};
}

static inline void s0_keepalive_write(char *d, struct keepalive_msg msg)
{
	write_uint32((uint8_t *)d, msg.timestamp);
}

static void traffic_stats(struct server *restrict s, const ev_tstamp now)
{
	static bool first_sample = true;
	static ev_tstamp last_time = 0;
	static struct link_stats last_stats = { 0 };
	if (first_sample) {
		first_sample = false;
	} else {
		const double dt = now - last_time;
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
		LOGF_D("traffic(KiB/s) udp up/down: %.1f/%.1f; tcp up/down: %.1f/%.1f",
		       udp_up, udp_down, tcp_up, tcp_down);
	}
	last_time = now;
	last_stats = s->stats;
}

void keepalive_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct server *restrict server = (struct server *)watcher->data;
	const ev_tstamp now = ev_now(loop);

	const size_t n_sessions = conv_size(server->conv);
	if (n_sessions > 0) {
		struct session_stats stats = (struct session_stats){ { 0 } };
		conv_iterate(server->conv, timeout_iter, &stats);
		LOGF_D("=== %zu sessions: %zu connected, %zu linger",
		       n_sessions, stats.data[STATE_CONNECTED],
		       stats.data[STATE_LINGER]);
		traffic_stats(server, now);
	}

	if (now - server->udp.last_sent > server->keepalive) {
		if (is_server(server)) {
			return;
		}
		size_t dst_size;
		char *dst = get_udp_send_buf(server, &dst_size);
		assert(dst_size >=
		       SESSION0_HEADER_SIZE + SESSION0_KEEPALIVE_SIZE);
		char *p = dst;
		s0_header_write(p, (struct session0_header){
					   .zero = 0,
					   .what = S0MSG_KEEPALIVE,
				   });
		p += SESSION0_HEADER_SIZE;
		const uint32_t now_ms = tstamp2ms(now);
		s0_keepalive_write(p, (struct keepalive_msg){
					      .timestamp = now_ms,
				      });

		udp_send(server,
			 (struct sockaddr *)server->conf->addr_udp_connect,
			 sizeof(struct sockaddr_in), dst,
			 SESSION0_HEADER_SIZE + SESSION0_KEEPALIVE_SIZE);
	}
}

static inline void session0_keepalive(struct server *restrict server,
				      struct sockaddr *addr, socklen_t addr_len,
				      const char *data, size_t n)
{
	if (n < SESSION0_HEADER_SIZE + SESSION0_KEEPALIVE_SIZE) {
		LOGF_W("short keepalive message: %zu", n);
		return;
	}
	struct keepalive_msg msg =
		s0_keepalive_read(data + SESSION0_HEADER_SIZE);

	if (!is_server(server)) {
		/* client: print RTT */
		const uint32_t now_ms = tstamp2ms(ev_time());
		LOGF_I("roundtrip finished, RTT: %" PRIu32 " ms",
		       now_ms - msg.timestamp);
		return;
	}

	/* server: send echo message */
	udp_send(server, addr, addr_len, data, n);
}

void session0(struct server *restrict server, struct sockaddr *addr,
	      socklen_t addr_len, const char *data, size_t n)
{
	if (n < SESSION0_HEADER_SIZE) {
		LOGF_W("short session 0 message: %zu", n);
		return;
	}
	struct session0_header header = s0_header_read(data);
	switch (header.what) {
	case S0MSG_KEEPALIVE:
		session0_keepalive(server, addr, addr_len, data, n);
		break;
	default:
		LOGF_W("unknown session 0 message: %04" PRIX16, header.what);
		break;
	}
}
