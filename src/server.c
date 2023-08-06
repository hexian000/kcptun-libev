/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "server.h"
#include "utils/slog.h"
#include "utils/buffer.h"
#include "utils/formats.h"
#include "algo/hashtable.h"
#include "math/rand.h"
#include "conf.h"
#include "event.h"
#include "pktqueue.h"
#include "obfs.h"
#include "session.h"
#include "util.h"
#include "sockutil.h"

#include <ev.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <time.h>

static int
tcp_listen(const struct config *restrict conf, const struct sockaddr *sa)
{
	/* Create server socket */
	const int fd = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		const int err = errno;
		LOGE_F("socket: %s", strerror(err));
		return -1;
	}
	if (!socket_set_nonblock(fd)) {
		const int err = errno;
		LOGE_F("fcntl: %s", strerror(err));
		(void)close(fd);
		return -1;
	}
	socket_set_reuseport(fd, conf->tcp_reuseport);
	socket_set_tcp(fd, conf->tcp_nodelay, conf->tcp_keepalive);
	socket_set_buffer(fd, conf->tcp_sndbuf, conf->tcp_rcvbuf);
	/* Bind socket to address */
	if (bind(fd, sa, getsocklen(sa)) != 0) {
		const int err = errno;
		LOGE_F("bind error: %s", strerror(err));
		(void)close(fd);
		return -1;
	}
	/* Start listing on the socket */
	if (listen(fd, 16)) {
		const int err = errno;
		LOGE_F("listen error: %s", strerror(err));
		(void)close(fd);
		return -1;
	}
	return fd;
}

static bool listener_start(struct server *restrict s)
{
	const struct config *restrict conf = s->conf;
	struct listener *restrict l = &(s->listener);

	if (conf->listen != NULL) {
		sockaddr_max_t addr;
		if (!resolve_sa(&addr, conf->listen, RESOLVE_PASSIVE)) {
			return false;
		}
		const int fd = tcp_listen(conf, &addr.sa);
		if (fd == -1) {
			return false;
		}
		/* Initialize and start a watcher to accepts client requests */
		struct ev_io *restrict w_accept = &l->w_accept;
		ev_io_init(w_accept, tcp_accept_cb, fd, EV_READ);
		ev_set_priority(w_accept, EV_MINPRI);
		w_accept->data = s;
		ev_io_start(s->loop, w_accept);
		l->fd = fd;
		if (LOGLEVEL(LOG_LEVEL_INFO)) {
			char addr_str[64];
			format_sa(&addr.sa, addr_str, sizeof(addr_str));
			LOGI_F("listen at: %s", addr_str);
		}
	}

	if (conf->http_listen != NULL) {
		sockaddr_max_t addr;
		if (!resolve_sa(&addr, conf->http_listen, RESOLVE_PASSIVE)) {
			return false;
		}
		const int fd = tcp_listen(conf, &addr.sa);
		if (fd == -1) {
			return false;
		}
		struct ev_io *restrict w_accept = &l->w_accept_http;
		ev_io_init(w_accept, http_accept_cb, fd, EV_READ);
		ev_set_priority(w_accept, EV_MINPRI);
		w_accept->data = s;
		ev_io_start(s->loop, w_accept);
		l->fd_http = fd;
		if (LOGLEVEL(LOG_LEVEL_INFO)) {
			char addr_str[64];
			format_sa(&addr.sa, addr_str, sizeof(addr_str));
			LOGI_F("http listen at: %s", addr_str);
		}
	}

	struct ev_timer *restrict w_listener = &s->listener.w_timer;
	ev_timer_init(w_listener, listener_cb, 0.5, 0.0);
	ev_set_priority(w_listener, EV_MINPRI);
	w_listener->data = l;
	return true;
}

static bool udp_init(
	struct pktconn *restrict udp, const struct config *restrict conf,
	const int udp_af)
{
	/* Setup a udp socket. */
	if ((udp->fd = socket(udp_af, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		const int err = errno;
		LOGE_F("udp socket: %s", strerror(err));
		return false;
	}
	if (!socket_set_nonblock(udp->fd)) {
		const int err = errno;
		LOGE_F("fcntl: %s", strerror(err));
		return false;
	}
	socket_set_buffer(udp->fd, conf->udp_sndbuf, conf->udp_rcvbuf);
	return true;
}

static bool
udp_bind(struct pktconn *restrict udp, const struct config *restrict conf)
{
	if (conf->netdev != NULL) {
		socket_bind_netdev(udp->fd, conf->netdev);
	}
	if (conf->kcp_bind != NULL) {
		sockaddr_max_t addr;
		if (!resolve_sa(
			    &addr, conf->kcp_bind,
			    RESOLVE_UDP | RESOLVE_PASSIVE)) {
			return false;
		}
		if (udp->fd == -1) {
			if (!udp_init(udp, conf, addr.sa.sa_family)) {
				return false;
			}
		}
		if (bind(udp->fd, &addr.sa, getsocklen(&addr.sa))) {
			const int err = errno;
			LOGE_F("udp bind: %s", strerror(err));
			return false;
		}
		char addr_str[64];
		format_sa(&addr.sa, addr_str, sizeof(addr_str));
		LOGI_F("udp bind: %s", addr_str);
	}
	if (conf->kcp_connect != NULL) {
		if (!resolve_sa(
			    &udp->kcp_connect, conf->kcp_connect,
			    RESOLVE_UDP)) {
			return false;
		}
		const struct sockaddr *sa = &udp->kcp_connect.sa;
		if (udp->fd == -1) {
			if (!udp_init(udp, conf, sa->sa_family)) {
				return false;
			}
		}
		if (connect(udp->fd, sa, getsocklen(sa))) {
			const int err = errno;
			LOGE_F("udp connect: %s", strerror(err));
			return false;
		}
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOGI_F("udp connect: %s", addr_str);
	}
	return true;
}

bool server_resolve(struct server *restrict s)
{
	const struct config *restrict conf = s->conf;
	if (conf->connect != NULL) {
		if (!resolve_sa(&s->connect, conf->connect, RESOLVE_TCP)) {
			return false;
		}
	}
#if WITH_OBFS
	if (s->pkt.queue->obfs != NULL) {
		return obfs_resolve(s->pkt.queue->obfs);
	}
#endif
	return udp_bind(&s->pkt, conf);
}

static bool udp_start(struct server *restrict s)
{
	struct pktconn *restrict udp = &s->pkt;
	const struct config *restrict conf = s->conf;
	if (!udp_bind(udp, conf)) {
		return false;
	}

	struct ev_io *restrict w_read = &udp->w_read;
	ev_io_init(w_read, pkt_read_cb, udp->fd, EV_READ);
	w_read->data = s;
	ev_io_start(s->loop, w_read);

	struct ev_io *restrict w_write = &udp->w_write;
	ev_io_init(w_write, pkt_write_cb, udp->fd, EV_WRITE);
	w_write->data = s;
	ev_io_start(s->loop, w_write);

	const ev_tstamp now = ev_time();
	udp->last_send_time = now;
	udp->last_recv_time = now;
	return true;
}

struct server *server_new(struct ev_loop *loop, struct config *restrict conf)
{
	struct server *s = malloc(sizeof(struct server));
	if (s == NULL) {
		return NULL;
	}
	const double ping_timeout = 4.0;
	*s = (struct server){
		.loop = loop,
		.conf = conf,
		.m_conv = (uint32_t)rand64(),
		.listener = (struct listener){ .fd = -1 },
		.pkt =
			(struct pktconn){
				.fd = -1,
				.inflight_ping = TSTAMP_NIL,
				.last_send_time = TSTAMP_NIL,
				.last_recv_time = TSTAMP_NIL,
			},
		.started = TSTAMP_NIL,
		.last_resolve_time = TSTAMP_NIL,
		.last_stats_time = TSTAMP_NIL,
		.linger = conf->linger,
		.dial_timeout = 30.0,
		.session_timeout = conf->timeout,
		.session_keepalive = conf->timeout / 2.0,
		.keepalive = conf->keepalive,
		.timeout = CLAMP(
			conf->keepalive * 3.0 + ping_timeout, 60.0, 1800.0),
		.ping_timeout = ping_timeout,
		.time_wait = conf->time_wait,
		.clock = (clock_t)(-1),
		.last_clock = (clock_t)(-1),
	};

	{
		const double interval = conf->kcp_interval * 1e-3;
		struct ev_timer *restrict w_kcp_update = &s->w_kcp_update;
		ev_timer_init(w_kcp_update, kcp_update_cb, interval, interval);
		w_kcp_update->data = s;

		struct ev_timer *restrict w_keepalive = &s->w_keepalive;
		ev_timer_init(w_keepalive, keepalive_cb, 0.0, s->keepalive);
		ev_set_priority(w_keepalive, EV_MINPRI);
		w_keepalive->data = s;

		struct ev_timer *restrict w_resolve = &s->w_resolve;
		ev_timer_init(w_resolve, resolve_cb, s->timeout, s->timeout);
		ev_set_priority(w_resolve, EV_MINPRI);
		w_resolve->data = s;

		struct ev_timer *restrict w_timeout = &s->w_timeout;
		ev_timer_init(w_timeout, timeout_cb, 10.0, 10.0);
		ev_set_priority(w_timeout, EV_MINPRI);
		w_timeout->data = s;
	}

	if (conf->mode == MODE_SERVER) {
		s->sessions = table_new(TABLE_FAST);
	} else {
		s->sessions = table_new(TABLE_DEFAULT);
	}
	if (s->sessions == NULL) {
		server_free(s);
		return NULL;
	}
	s->pkt.queue = queue_new(s);
	if (s->pkt.queue == NULL) {
		LOGE("failed creating packet queue");
		server_free(s);
		return false;
	}
	return s;
}

bool server_start(struct server *s)
{
	struct ev_loop *loop = s->loop;
	const ev_tstamp now = ev_now(loop);
	if (!listener_start(s)) {
		return false;
	}
	s->started = now;
	s->last_stats_time = now;
	const struct config *restrict conf = s->conf;
	if (conf->connect != NULL) {
		if (!resolve_sa(&s->connect, conf->connect, RESOLVE_TCP)) {
			return false;
		}
	}
	s->last_resolve_time = now;
	ev_timer_start(loop, &s->w_kcp_update);
	if ((s->conf->mode & MODE_CLIENT) && conf->keepalive > 0.0) {
		ev_timer_start(loop, &s->w_keepalive);
		ev_timer_start(loop, &s->w_resolve);
	}
	ev_timer_start(loop, &s->w_timeout);

#if WITH_OBFS
	struct pktqueue *restrict q = s->pkt.queue;
	if (q->obfs != NULL) {
		const bool ok = obfs_start(q->obfs, s);
		q->msg_offset = obfs_offset(q->obfs);
		return ok;
	}
#endif
	return udp_start(s);
}

void server_ping(struct server *restrict s)
{
	const ev_tstamp now = ev_now(s->loop);
	const uint32_t tstamp = TSTAMP2MS(now);
	unsigned char b[sizeof(uint32_t)];
	write_uint32(b, tstamp);
	ss0_send(s, &s->pkt.kcp_connect.sa, S0MSG_PING, b, sizeof(b));
	s->pkt.inflight_ping = now;
}

static void udp_stop(struct ev_loop *loop, struct pktconn *restrict conn)
{
	if (conn->fd == -1) {
		return;
	}
	ev_io_stop(loop, &conn->w_read);
	ev_io_stop(loop, &conn->w_write);
	if (close(conn->fd) != 0) {
		const int err = errno;
		LOGW_F("close: %s", strerror(err));
	}
	conn->fd = -1;
}

static void udp_free(struct pktconn *restrict conn)
{
	if (conn == NULL) {
		return;
	}
	if (conn->queue != NULL) {
		queue_free(conn->queue);
		conn->queue = NULL;
	}
}

static void listener_stop(struct ev_loop *loop, struct listener *restrict l)
{
	if (l->fd != -1) {
		LOGD_F("listener close: %d", l->fd);
		struct ev_io *restrict w_accept = &l->w_accept;
		ev_io_stop(loop, w_accept);
		if (close(l->fd) != 0) {
			const int err = errno;
			LOGW_F("close: %s", strerror(err));
		}
		l->fd = -1;
	}
	if (l->fd_http != -1) {
		LOGD_F("http listener close: %d", l->fd_http);
		struct ev_io *restrict w_accept = &l->w_accept;
		ev_io_stop(loop, w_accept);
		if (close(l->fd_http) != 0) {
			const int err = errno;
			LOGW_F("close: %s", strerror(err));
		}
		l->fd_http = -1;
	}
	ev_timer_stop(loop, &l->w_timer);
}

void server_stop(struct server *restrict s)
{
	struct ev_loop *loop = s->loop;
	listener_stop(loop, &s->listener);
	session_close_all(s->sessions);
	ev_timer_stop(loop, &s->w_kcp_update);
	ev_timer_stop(loop, &s->w_keepalive);
	ev_timer_stop(loop, &s->w_resolve);
	ev_timer_stop(loop, &s->w_timeout);
#if WITH_OBFS
	if (s->pkt.queue->obfs != NULL) {
		obfs_stop(s->pkt.queue->obfs, s);
	} else {
		udp_stop(s->loop, &s->pkt);
	}
#else
	udp_stop(s->loop, &s->pkt);
#endif
}

void server_free(struct server *restrict s)
{
	udp_free(&s->pkt);
	if (s->sessions != NULL) {
		table_free(s->sessions);
		s->sessions = NULL;
	}
	free(s);
}

static uint32_t conv_next(uint32_t conv)
{
	conv++;
	/* 0 is reserved */
	if (conv == UINT32_C(0)) {
		conv++;
	}
	return conv;
}

uint32_t conv_new(struct server *restrict s, const struct sockaddr *sa)
{
	uint32_t conv = conv_next(s->m_conv);
	struct session_key key;
	SESSION_MAKE_KEY(key, sa, conv);
	if (table_find(s->sessions, (hashkey_t *)&key) != NULL) {
		const double usage =
			(double)table_size(s->sessions) / (double)INT_MAX;
		do {
			if (usage < 1e-3) {
				conv = (uint32_t)rand64();
			}
			conv = conv_next(conv);
			SESSION_MAKE_KEY(key, sa, conv);
		} while (table_find(s->sessions, (hashkey_t *)&key) != NULL);
	}
	s->m_conv = conv;
	return conv;
}

struct server_stats_ctx {
	size_t num_in_state[STATE_MAX];
	int level;
	ev_tstamp now;
	struct vbuffer *restrict buf;
};

static bool print_session_iter(
	struct hashtable *t, const hashkey_t *key, void *element, void *user)
{
	UNUSED(t);
	UNUSED(key);
	struct session *restrict ss = element;
	assert(key == (hashkey_t *)&ss->key);
	struct server_stats_ctx *restrict ctx = user;
	const int state = ss->kcp_state;
	ctx->num_in_state[state]++;
	if (ss->kcp_state > ctx->level) {
		return true;
	}
	char addr_str[64];
	format_sa(&ss->raddr.sa, addr_str, sizeof(addr_str));
	ev_tstamp last_seen = ss->created;
	if (ss->last_send != TSTAMP_NIL && ss->last_send > last_seen) {
		last_seen = ss->last_send;
	}
	if (ss->last_recv != TSTAMP_NIL && ss->last_recv > last_seen) {
		last_seen = ss->last_recv;
	}
	const double not_seen =
		last_seen != TSTAMP_NIL ? ctx->now - last_seen : TSTAMP_NIL;

#define FORMAT_BYTES(name, value)                                              \
	char name[16];                                                         \
	(void)format_iec_bytes(name, sizeof(name), (value))

	FORMAT_BYTES(kcp_rx, (double)ss->stats.tcp_tx);
	FORMAT_BYTES(kcp_tx, (double)ss->stats.tcp_rx);
	ctx->buf = VBUF_APPENDF(
		ctx->buf,
		"[%08" PRIX32 "] %c peer=%s seen=%.0lfs "
		"rtt=%" PRId32 " rto=%" PRId32 " waitsnd=%" PRIu32 " "
		"rx/tx=%s/%s\n",
		ss->conv, session_state_char[state], addr_str, not_seen,
		ss->kcp->rx_srtt, ss->kcp->rx_rto, ikcp_waitsnd(ss->kcp),
		kcp_rx, kcp_tx);
#undef FORMAT_BYTES

	return true;
}

static struct vbuffer *print_session_table(
	const struct server *restrict s, struct vbuffer *restrict buf,
	const int level)
{
	struct server_stats_ctx ctx = (struct server_stats_ctx){
		.level = level,
		.now = ev_now(s->loop),
		.buf = buf,
	};
	table_iterate(s->sessions, &print_session_iter, &ctx);
	return VBUF_APPENDF(
		ctx.buf,
		"  = %d sessions: %zu halfopen, %zu connected, %zu linger, %zu time_wait\n\n",
		table_size(s->sessions), ctx.num_in_state[STATE_CONNECT],
		ctx.num_in_state[STATE_CONNECTED],
		ctx.num_in_state[STATE_LINGER],
		ctx.num_in_state[STATE_TIME_WAIT]);
}

static bool update_load(
	struct server *restrict s, char *buf, size_t bufsize, const double dt)
{
	bool ok = false;
	s->clock = clock();
	if (s->clock != (clock_t)(-1) && s->last_clock != (clock_t)(-1) &&
	    s->clock > s->last_clock) {
		const double load = (double)(s->clock - s->last_clock) /
				    (double)(CLOCKS_PER_SEC) / dt * 100.0;
		(void)snprintf(buf, bufsize, "%.03f%%", load);
		ok = true;
	}
	s->last_clock = s->clock;
	return ok;
}

struct vbuffer *
server_stats_const(const struct server *s, struct vbuffer *buf, int level)
{
	buf = print_session_table(s, buf, level);

	const ev_tstamp now = ev_now(s->loop);
	char uptime[16];
	(void)format_duration(
		uptime, sizeof(uptime), make_duration(now - s->started));
	const struct link_stats *restrict stats = &s->stats;

#define FORMAT_BYTES(name, value)                                              \
	char name[16];                                                         \
	(void)format_iec_bytes(name, sizeof(name), (value))

	{
		FORMAT_BYTES(tcp_rx, (double)(stats->tcp_rx));
		FORMAT_BYTES(tcp_tx, (double)(stats->tcp_tx));
		FORMAT_BYTES(kcp_rx, (double)(stats->kcp_rx));
		FORMAT_BYTES(kcp_tx, (double)(stats->kcp_tx));
		FORMAT_BYTES(pkt_rx, (double)(stats->pkt_rx));
		FORMAT_BYTES(pkt_tx, (double)(stats->pkt_tx));
		buf = VBUF_APPENDF(
			buf, "[total] tcp: %s, %s; kcp: %s, %s; pkt: %s, %s\n",
			tcp_rx, tcp_tx, kcp_rx, kcp_tx, pkt_rx, pkt_tx);
	}

#undef FORMAT_BYTES

	buf = VBUF_APPENDF(buf, "  = uptime: %s\n", uptime);
	return buf;
}

struct vbuffer *server_stats(
	struct server *restrict s, struct vbuffer *restrict buf,
	const int level)
{
	buf = print_session_table(s, buf, level);

	const ev_tstamp now = ev_now(s->loop);
	char uptime[16];
	(void)format_duration(
		uptime, sizeof(uptime), make_duration(now - s->started));
	const double dt = now - s->last_stats_time;
	const struct link_stats *restrict stats = &s->stats;

#define FORMAT_BYTES(name, value)                                              \
	char name[16];                                                         \
	(void)format_iec_bytes(name, sizeof(name), (value))

	const struct link_stats *restrict last_stats = &s->last_stats;
	const struct link_stats dstats = (struct link_stats){
		.tcp_rx = stats->tcp_rx - last_stats->tcp_rx,
		.tcp_tx = stats->tcp_tx - last_stats->tcp_tx,
		.kcp_rx = stats->kcp_rx - last_stats->kcp_rx,
		.kcp_tx = stats->kcp_tx - last_stats->kcp_tx,
		.pkt_rx = stats->pkt_rx - last_stats->pkt_rx,
		.pkt_tx = stats->pkt_tx - last_stats->pkt_tx,
	};
	FORMAT_BYTES(dpkt_rx, dstats.pkt_rx / dt);
	FORMAT_BYTES(dpkt_tx, dstats.pkt_tx / dt);

	{
		FORMAT_BYTES(dtcp_rx, dstats.tcp_rx / dt);
		FORMAT_BYTES(dtcp_tx, dstats.tcp_tx / dt);
		FORMAT_BYTES(dkcp_rx, dstats.kcp_rx / dt);
		FORMAT_BYTES(dkcp_tx, dstats.kcp_tx / dt);
		const double deff_rx =
			(double)dstats.tcp_tx * 100.0 / (double)dstats.kcp_rx;
		const double deff_tx =
			(double)dstats.tcp_rx * 100.0 / (double)dstats.kcp_tx;

		buf = VBUF_APPENDF(
			buf,
			"[rx,tx] tcp: %s/s, %s/s; kcp: %s/s, %s/s; efficiency: %.1lf%%, %.1lf%%\n",
			dtcp_rx, dtcp_tx, dkcp_rx, dkcp_tx, deff_rx, deff_tx);
	}

	{
		FORMAT_BYTES(tcp_rx, (double)(stats->tcp_rx));
		FORMAT_BYTES(tcp_tx, (double)(stats->tcp_tx));
		FORMAT_BYTES(kcp_rx, (double)(stats->kcp_rx));
		FORMAT_BYTES(kcp_tx, (double)(stats->kcp_tx));
		FORMAT_BYTES(pkt_rx, (double)(stats->pkt_rx));
		FORMAT_BYTES(pkt_tx, (double)(stats->pkt_tx));
		buf = VBUF_APPENDF(
			buf, "[total] tcp: %s, %s; kcp: %s, %s; pkt: %s, %s\n",
			tcp_rx, tcp_tx, kcp_rx, kcp_tx, pkt_rx, pkt_tx);
	}

	char load_buf[16];
	const char *load_str = "(unknown)";
	if (update_load(s, load_buf, sizeof(load_buf), dt)) {
		load_str = load_buf;
	}
	buf = VBUF_APPENDF(
		buf, "  = load: %s; pkt: %s/s, %s/s; uptime: %s\n", load_str,
		dpkt_rx, dpkt_tx, uptime);
#undef FORMAT_BYTES

	/* rotate stats */
	s->last_clock = s->clock;
	s->last_stats = s->stats;
	s->last_stats_time = now;
	return buf;
}
