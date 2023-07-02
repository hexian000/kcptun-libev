/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "server.h"
#include "utils/slog.h"
#include "utils/buffer.h"
#include "utils/formats.h"
#include "algo/hashtable.h"
#include "algo/rand.h"
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
#include <time.h>

static int tcp_listen(const struct config *restrict conf, struct netaddr *addr)
{
	if (!resolve_netaddr(addr, RESOLVE_TCP | RESOLVE_PASSIVE)) {
		return false;
	}
	const struct sockaddr *sa = addr->sa;
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
	struct config *restrict conf = s->conf;
	struct listener *restrict l = &(s->listener);

	if (conf->listen.str != NULL) {
		const int fd = tcp_listen(conf, &conf->listen);
		if (fd == -1) {
			return false;
		}
		/* Initialize and start a watcher to accepts client requests */
		struct ev_io *restrict w_accept = &l->w_accept;
		ev_io_init(w_accept, accept_cb, fd, EV_READ);
		w_accept->data = s;
		ev_io_start(s->loop, w_accept);
		l->fd = fd;
		if (conf->listen.sa != NULL && LOGLEVEL(LOG_LEVEL_INFO)) {
			char addr_str[64];
			format_sa(conf->listen.sa, addr_str, sizeof(addr_str));
			LOGI_F("listen at: %s", addr_str);
		}
	}

	if (conf->http_listen.str != NULL) {
		const int fd = tcp_listen(conf, &conf->http_listen);
		if (fd == -1) {
			return false;
		}
		struct ev_io *restrict w_accept = &l->w_accept_http;
		ev_io_init(w_accept, http_accept_cb, fd, EV_READ);
		w_accept->data = s;
		ev_io_start(s->loop, w_accept);
		l->fd_http = fd;
		if (conf->http_listen.sa != NULL && LOGLEVEL(LOG_LEVEL_INFO)) {
			char addr_str[64];
			format_sa(
				conf->http_listen.sa, addr_str,
				sizeof(addr_str));
			LOGI_F("http listen at: %s", addr_str);
		}
	}

	return true;
}

static bool udp_resolve(struct config *restrict conf)
{
	if (conf->kcp_bind.str != NULL) {
		if (!resolve_netaddr(
			    &conf->kcp_bind, RESOLVE_UDP | RESOLVE_PASSIVE)) {
			return false;
		}
	}
	if (conf->kcp_connect.str != NULL) {
		if (!resolve_netaddr(&conf->kcp_connect, RESOLVE_UDP)) {
			return false;
		}
	}
	return true;
}

static bool udp_bind(struct pktconn *restrict udp, struct config *restrict conf)
{
	if (conf->netdev != NULL) {
		socket_bind_netdev(udp->fd, conf->netdev);
	}
	if (conf->kcp_bind.sa != NULL) {
		const struct sockaddr *sa = conf->kcp_bind.sa;
		if (bind(udp->fd, sa, getsocklen(sa))) {
			const int err = errno;
			LOGE_F("udp bind: %s", strerror(err));
			return false;
		}
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOGI_F("udp bind: %s", addr_str);
	}
	if (conf->kcp_connect.sa != NULL) {
		const struct sockaddr *sa = conf->kcp_connect.sa;
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

static bool udp_rebind(struct pktconn *udp, struct config *conf)
{
	return udp_resolve(conf) && udp_bind(udp, conf);
}

bool server_resolve(struct server *restrict s)
{
	struct config *restrict conf = s->conf;
	if (conf->connect.str != NULL &&
	    !resolve_netaddr(&s->conf->connect, RESOLVE_TCP)) {
		return false;
	}
#if WITH_OBFS
	if (s->pkt.queue->obfs != NULL) {
		return obfs_resolve(s->pkt.queue->obfs);
	}
#endif
	return udp_rebind(&s->pkt, conf);
}

static bool udp_start(struct server *restrict s)
{
	struct config *restrict conf = s->conf;
	if (!udp_resolve(conf)) {
		return false;
	}
	struct pktconn *restrict udp = &s->pkt;

	// Setup a udp socket.
	const int udp_af = conf->kcp_bind.sa != NULL ?
				   conf->kcp_bind.sa->sa_family :
				   conf->kcp_connect.sa->sa_family;
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
	const ev_tstamp now = ev_now(loop);
	*s = (struct server){
		.loop = loop,
		.conf = conf,
		.m_conv = rand32(),
		.listener = (struct listener){ .fd = -1 },
		.pkt =
			(struct pktconn){
				.fd = -1,
				.inflight_ping = TSTAMP_NIL,
				.last_send_time = TSTAMP_NIL,
				.last_recv_time = TSTAMP_NIL,
			},
		.uptime = now,
		.last_resolve_time = now,
		.last_stats_time = now,
		.interval = conf->kcp_interval * 1e-3,
		.linger = conf->linger,
		.dial_timeout = 30.0,
		.session_timeout = conf->timeout,
		.session_keepalive = conf->timeout / 2.0,
		.keepalive = conf->keepalive,
		.timeout = CLAMP(s->keepalive * 3.0, 60.0, 1800.0),
		.time_wait = conf->time_wait,
		.clock = (clock_t)(-1),
		.last_clock = (clock_t)(-1),
	};

	struct ev_timer *restrict w_kcp_update = &s->w_kcp_update;
	ev_timer_init(w_kcp_update, kcp_update_cb, s->interval, s->interval);
	w_kcp_update->data = s;
	struct ev_timer *restrict w_timer = &s->w_timer;
	ev_timer_init(w_timer, ticker_cb, 1.0, 1.0);
	w_timer->data = s;

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
	struct config *restrict conf = s->conf;
	if (!listener_start(s)) {
		return false;
	}
	if (conf->connect.str != NULL &&
	    !resolve_netaddr(&conf->connect, RESOLVE_TCP)) {
		return false;
	}
	struct ev_timer *restrict w_kcp_update = &s->w_kcp_update;
	ev_timer_start(loop, w_kcp_update);
	struct ev_timer *restrict w_timer = &s->w_timer;
	ev_timer_start(loop, w_timer);

#if WITH_OBFS
	struct pktqueue *restrict q = s->pkt.queue;
	if (q->obfs != NULL) {
		return obfs_start(q->obfs, s);
	}
#endif
	return udp_start(s);
}

void server_ping(struct server *restrict s)
{
	const ev_tstamp now = ev_now(s->loop);
	const uint32_t tstamp = tstamp2ms(now);
	unsigned char b[sizeof(uint32_t)];
	write_uint32(b, tstamp);
	ss0_send(s, s->conf->kcp_connect.sa, S0MSG_PING, b, sizeof(b));
	s->pkt.inflight_ping = now;
}

static void udp_stop(struct ev_loop *loop, struct pktconn *restrict conn)
{
	if (conn->fd == -1) {
		return;
	}
	struct ev_io *restrict w_read = &conn->w_read;
	ev_io_stop(loop, w_read);
	struct ev_io *restrict w_write = &conn->w_write;
	ev_io_stop(loop, w_write);
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
}

void server_stop(struct server *restrict s)
{
	listener_stop(s->loop, &s->listener);
	session_close_all(s->sessions);
	struct ev_timer *restrict w_kcp_update = &s->w_kcp_update;
	if (ev_is_active(w_kcp_update)) {
		ev_timer_stop(s->loop, w_kcp_update);
	}
	struct ev_timer *restrict w_timer = &s->w_timer;
	if (ev_is_active(w_timer)) {
		ev_timer_stop(s->loop, w_timer);
	}
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
	hashkey_t key;
	conv_make_key(&key, sa, conv);
	if (table_find(s->sessions, &key, NULL)) {
		/* first conflict, try random */
		conv = rand32();
		conv_make_key(&key, sa, conv);
		while (table_find(s->sessions, &key, NULL)) {
			/* many conflicts, do scan */
			conv = conv_next(conv);
			conv_make_key(&key, sa, conv);
		}
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
	struct hashtable *t, const hashkey_t *key, void *value, void *user)
{
	UNUSED(t);
	UNUSED(key);
	struct session *restrict ss = value;
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
	ctx->buf = vbuf_appendf(
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
	return vbuf_appendf(
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

struct vbuffer *server_stats(
	struct server *restrict s, struct vbuffer *restrict buf,
	const bool update, const int level)
{
	buf = print_session_table(s, buf, level);

	const ev_tstamp now = ev_now(s->loop);
	char uptime[16];
	(void)format_duration(
		uptime, sizeof(uptime), make_duration(now - s->uptime));
	const double dt = now - s->last_stats_time;
	const struct link_stats *restrict stats = &s->stats;

	if (update) {
		const struct link_stats *restrict last_stats = &s->last_stats;
		const struct link_stats dstats = (struct link_stats){
			.tcp_rx = stats->tcp_rx - last_stats->tcp_rx,
			.tcp_tx = stats->tcp_tx - last_stats->tcp_tx,
			.kcp_rx = stats->kcp_rx - last_stats->kcp_rx,
			.kcp_tx = stats->kcp_tx - last_stats->kcp_tx,
			.pkt_rx = stats->pkt_rx - last_stats->pkt_rx,
			.pkt_tx = stats->pkt_tx - last_stats->pkt_tx,
		};

#define FORMAT_BYTES(name, value)                                              \
	char name[16];                                                         \
	(void)format_iec_bytes(name, sizeof(name), (value))

		FORMAT_BYTES(dtcp_rx, dstats.tcp_rx / dt);
		FORMAT_BYTES(dtcp_tx, dstats.tcp_tx / dt);
		FORMAT_BYTES(dkcp_rx, dstats.kcp_rx / dt);
		FORMAT_BYTES(dkcp_tx, dstats.kcp_tx / dt);
		const double deff_rx =
			(double)dstats.tcp_tx * 100.0 / (double)dstats.kcp_rx;
		const double deff_tx =
			(double)dstats.tcp_rx * 100.0 / (double)dstats.kcp_tx;

		buf = vbuf_appendf(
			buf,
			"[rx,tx] tcp: %s/s, %s/s; kcp: %s/s, %s/s; efficiency: %.1lf%%, %.1lf%%\n",
			dtcp_rx, dtcp_tx, dkcp_rx, dkcp_tx, deff_rx, deff_tx);
	}

	FORMAT_BYTES(tcp_rx, (double)(stats->tcp_rx));
	FORMAT_BYTES(tcp_tx, (double)(stats->tcp_tx));
	FORMAT_BYTES(kcp_rx, (double)(stats->kcp_rx));
	FORMAT_BYTES(kcp_tx, (double)(stats->kcp_tx));
	FORMAT_BYTES(pkt_rx, (double)(stats->pkt_rx));
	FORMAT_BYTES(pkt_tx, (double)(stats->pkt_tx));
	buf = vbuf_appendf(
		buf, "[total] tcp: %s, %s; kcp: %s, %s; pkt: %s, %s\n", tcp_rx,
		tcp_tx, kcp_rx, kcp_tx, pkt_rx, pkt_tx);
#undef FORMAT_BYTES

	char load_buf[16];
	const char *load_str = "(unknown)";
	if (update && update_load(s, load_buf, sizeof(load_buf), dt)) {
		load_str = load_buf;
	}
	buf = vbuf_appendf(buf, "  = load: %s, uptime: %s\n", load_str, uptime);

	/* rotate stats */
	if (update) {
		s->last_clock = s->clock;
		s->last_stats = s->stats;
		s->last_stats_time = ev_now(s->loop);
	}
	return buf;
}
