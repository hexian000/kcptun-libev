/* kcptun-libev (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "server.h"
#include "utils/slog.h"
#include "utils/debug.h"
#include "utils/buffer.h"
#include "utils/formats.h"
#include "algo/hashtable.h"
#include "math/rand.h"
#include "conf.h"
#include "event.h"
#include "crypto.h"
#include "pktqueue.h"
#include "obfs.h"
#include "session.h"
#include "util.h"
#include "sockutil.h"

#include "ikcp.h"

#include <ev.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
		CLOSE_FD(fd);
		return -1;
	}
	socket_set_reuseport(fd, conf->tcp_reuseport);
	socket_set_tcp(fd, conf->tcp_nodelay, conf->tcp_keepalive);
	socket_set_buffer(fd, conf->tcp_sndbuf, conf->tcp_rcvbuf);
	/* Bind socket to address */
	if (bind(fd, sa, getsocklen(sa)) != 0) {
		const int err = errno;
		LOGE_F("tcp bind: %s", strerror(err));
		CLOSE_FD(fd);
		return -1;
	}
	/* Start listening on the socket */
	if (listen(fd, SOMAXCONN)) {
		const int err = errno;
		LOGE_F("tcp listen: %s", strerror(err));
		CLOSE_FD(fd);
		return -1;
	}
	return fd;
}

static bool listener_start(struct server *restrict s)
{
	const struct config *restrict conf = s->conf;
	struct listener *restrict l = &(s->listener);

	if (conf->listen != NULL) {
		union sockaddr_max addr;
		if (!resolve_addr(&addr, conf->listen, RESOLVE_PASSIVE)) {
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
		if (LOGLEVEL(NOTICE)) {
			char addr_str[64];
			format_sa(&addr.sa, addr_str, sizeof(addr_str));
			LOG_F(NOTICE, "listen at %s", addr_str);
		}
	}

	if (conf->http_listen != NULL) {
		union sockaddr_max addr;
		if (!resolve_addr(&addr, conf->http_listen, RESOLVE_PASSIVE)) {
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
		if (LOGLEVEL(NOTICE)) {
			char addr_str[64];
			format_sa(&addr.sa, addr_str, sizeof(addr_str));
			LOG_F(NOTICE, "http listen at %s", addr_str);
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
	socket_set_reuseport(udp->fd, conf->udp_reuseport);
	socket_set_buffer(udp->fd, conf->udp_sndbuf, conf->udp_rcvbuf);
	return true;
}

static void addr_set_any(union sockaddr_max *addr, const int family)
{
	switch (family) {
	case AF_INET:
		addr->in = (struct sockaddr_in){
			.sin_family = family,
		};
		return;
	case AF_INET6:
		addr->in6 = (struct sockaddr_in6){
			.sin6_family = family,
		};
		return;
	default:
		break;
	}
	FAIL();
}

static bool addr_set_local(union sockaddr_max *addr, const struct sockaddr *sa)
{
	const int fd = socket(sa->sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		const int err = errno;
		LOGW_F("socket: %s", strerror(err));
		return false;
	}
	if (connect(fd, sa, getsocklen(sa))) {
		const int err = errno;
		LOGW_F("connect: %s", strerror(err));
		return false;
	}
	socklen_t len = sizeof(*addr);
	if (getsockname(fd, &addr->sa, &len)) {
		const int err = errno;
		LOGW_F("getsockname: %s", strerror(err));
		return false;
	}
	CLOSE_FD(fd);
	return true;
}

static bool
udp_bind(struct pktconn *restrict udp, const struct config *restrict conf)
{
	if (conf->kcp_bind != NULL) {
		union sockaddr_max addr;
		if (!resolve_addr(
			    &addr, conf->kcp_bind,
			    RESOLVE_UDP | RESOLVE_PASSIVE)) {
			return false;
		}
		udp->domain = addr.sa.sa_family;
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
		if (LOGLEVEL(NOTICE)) {
			char addr_str[64];
			format_sa(&addr.sa, addr_str, sizeof(addr_str));
			LOG_F(NOTICE, "udp bind: %s", addr_str);
		}
	}
	if (conf->kcp_connect != NULL) {
		union sockaddr_max addr;
		if (!resolve_addr(&addr, conf->kcp_connect, RESOLVE_UDP)) {
			return false;
		}
		const socklen_t socklen = getsocklen(&addr.sa);
		udp->domain = addr.sa.sa_family;
		if (udp->fd == -1) {
			if (!udp_init(udp, conf, addr.sa.sa_family)) {
				return false;
			}
		}
		if (connect(udp->fd, &addr.sa, socklen)) {
			const int err = errno;
			LOGE_F("udp connect: %s", strerror(err));
			return false;
		}
		memcpy(&udp->kcp_connect.sa, &addr.sa, socklen);
		if (LOGLEVEL(INFO)) {
			char addr_str[64];
			format_sa(&addr.sa, addr_str, sizeof(addr_str));
			LOG_F(INFO, "udp connect: %s", addr_str);
		}
		udp->connected = true;
	}
	if ((conf->mode & MODE_RENDEZVOUS) != 0) {
		union sockaddr_max addr, laddr;
		if (!resolve_addr(&addr, conf->rendezvous_server, RESOLVE_UDP)) {
			return false;
		}
		udp->domain = addr.sa.sa_family;
		if (udp->fd == -1) {
			if (!udp_init(udp, conf, addr.sa.sa_family)) {
				return false;
			}
		}
		udp->rendezvous_server = addr;
		if (!addr_set_local(&laddr, &addr.sa)) {
			addr_set_any(&laddr, addr.sa.sa_family);
		}
		udp->rendezvous_local = laddr;
		if (LOGLEVEL(INFO)) {
			char addr_str[64], laddr_str[64];
			format_sa(&addr.sa, addr_str, sizeof(addr_str));
			format_sa(&laddr.sa, laddr_str, sizeof(laddr_str));
			LOG_F(INFO, "rendezvous mode: %s -> %s", laddr_str,
			      addr_str);
		}
	}
	if (conf->netdev != NULL) {
		socket_bind_netdev(udp->fd, conf->netdev);
	}
	return true;
}

size_t udp_overhead(const struct pktconn *restrict udp)
{
	switch (udp->domain) {
	case AF_INET:
		/* UDP/IP4 */
		return 28;
	case AF_INET6:
		/* UDP/IP6 */
		return 48;
	default:
		break;
	}
	FAIL();
}

/* calculate max send size */
static size_t server_mss(const struct server *restrict s)
{
	size_t mss = (size_t)s->conf->kcp_mtu;
	const struct pktqueue *restrict q = s->pkt.queue;
	UNUSED(q);
#if WITH_OBFS
	const struct obfs *restrict obfs = q->obfs;
	if (obfs != NULL) {
		mss -= obfs_overhead(obfs);
	} else {
		mss -= udp_overhead(&s->pkt);
	}
#else
	mss -= udp_overhead(&s->pkt);
#endif
#if WITH_CRYPTO
	const struct crypto *restrict crypto = q->crypto;
	if (crypto != NULL) {
		mss -= (crypto->overhead + crypto->nonce_size);
	}
#endif
	return mss;
}

bool server_resolve(struct server *restrict s)
{
	const struct config *restrict conf = s->conf;
	if (conf->connect != NULL) {
		if (!resolve_addr(&s->connect, conf->connect, RESOLVE_TCP)) {
			return false;
		}
	}
	struct pktqueue *restrict q = s->pkt.queue;
#if WITH_OBFS
	if (q->obfs != NULL) {
		if (!obfs_resolve(q->obfs)) {
			return false;
		}
		q->msg_offset = (uint16_t)obfs_overhead(q->obfs);
		q->mss = (uint16_t)server_mss(s);
		return true;
	}
#endif
	s->pkt.connected = false;
	if (!udp_bind(&s->pkt, conf)) {
		return false;
	}
	q->mss = (uint16_t)server_mss(s);
	return true;
}

void udp_rendezvous(struct server *restrict s, const uint16_t what)
{
	const struct sockaddr *sa_server = &s->pkt.rendezvous_server.sa;
	const struct sockaddr *sa_local = &s->pkt.rendezvous_local.sa;
	unsigned char b[INET6ADDR_LENGTH];
	const size_t n = inetaddr_write(b, sizeof(b), sa_local);
	assert(n > 0);
	ss0_send(s, sa_server, what, b, n);
}

static bool udp_start(struct server *restrict s)
{
	struct pktconn *restrict udp = &s->pkt;
	if (!udp_bind(udp, s->conf)) {
		return false;
	}

	struct ev_io *restrict w_read = &udp->w_read;
	ev_io_init(w_read, pkt_read_cb, udp->fd, EV_READ);
	w_read->data = s;
	ev_io_start(s->loop, w_read);

	struct ev_io *restrict w_write = &udp->w_write;
	ev_io_init(w_write, pkt_write_cb, udp->fd, EV_WRITE);
	w_write->data = s;

	const ev_tstamp now = ev_time();
	udp->last_send_time = now;
	udp->last_recv_time = now;
	return true;
}

struct server *server_new(struct ev_loop *loop, struct config *restrict conf)
{
	struct server *restrict s = malloc(sizeof(struct server));
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

	const int mode =
		conf->mode & (MODE_SERVER | MODE_CLIENT | MODE_RENDEZVOUS);
	if (mode == MODE_SERVER || mode == MODE_RENDEZVOUS) {
		/* server only: disable keepalive and resolve */
		s->keepalive = 0.0;
	}
	if ((mode & MODE_SERVER) != 0) {
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
		if (!resolve_addr(&s->connect, conf->connect, RESOLVE_TCP)) {
			return false;
		}
	}
	s->last_resolve_time = now;
	ev_timer_start(loop, &s->w_kcp_update);
	if (s->keepalive > 0.0) {
		ev_timer_start(loop, &s->w_keepalive);
		ev_timer_start(loop, &s->w_resolve);
	}
	ev_timer_start(loop, &s->w_timeout);

	struct pktqueue *restrict q = s->pkt.queue;
#if WITH_OBFS
	if (q->obfs != NULL) {
		const bool ok = obfs_start(q->obfs, s);
		q->msg_offset = (uint16_t)obfs_overhead(q->obfs);
		q->mss = (uint16_t)server_mss(s);
		return ok;
	}
#endif
	if (!udp_start(s)) {
		return false;
	}
	q->mss = (uint16_t)server_mss(s);
	return true;
}

void server_ping(struct server *restrict s)
{
	if ((s->conf->mode & MODE_CLIENT) == 0) {
		return;
	}

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
	CLOSE_FD(conn->fd);
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
		LOGD_F("listener close: fd=%d", l->fd);
		struct ev_io *restrict w_accept = &l->w_accept;
		ev_io_stop(loop, w_accept);
		CLOSE_FD(l->fd);
		l->fd = -1;
	}
	if (l->fd_http != -1) {
		LOGD_F("http listener close: fd=%d", l->fd_http);
		struct ev_io *restrict w_accept = &l->w_accept;
		ev_io_stop(loop, w_accept);
		CLOSE_FD(l->fd_http);
		l->fd_http = -1;
	}
	ev_timer_stop(loop, &l->w_timer);
}

static bool shutdown_filt(
	const struct hashtable *t, const struct hashkey key, void *element,
	void *user)
{
	UNUSED(t);
	UNUSED(key);
	UNUSED(user);
	struct session *restrict ss = element;
	assert(key.data == ss->key);
	session_free(ss);
	return false;
}

void server_stop(struct server *restrict s)
{
	struct ev_loop *loop = s->loop;
	listener_stop(loop, &s->listener);
	s->sessions = table_filter(s->sessions, shutdown_filt, NULL);
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
	unsigned char key[SESSION_KEY_SIZE];
	const struct hashkey hkey = {
		.len = sizeof(key),
		.data = key,
	};
	SESSION_MAKEKEY(key, sa, conv);
	if (table_find(s->sessions, hkey, NULL)) {
		const double usage =
			(double)table_size(s->sessions) / (double)UINT32_MAX;
		do {
			if (usage < 1e-3) {
				conv = (uint32_t)rand64();
			}
			conv = conv_next(conv);
			SESSION_MAKEKEY(key, sa, conv);
		} while (table_find(s->sessions, hkey, NULL));
	}
	s->m_conv = conv;
	return conv;
}

struct server_stats_ctx {
	size_t num_in_state[STATE_MAX];
	size_t waitsnd;
	int level;
	ev_tstamp now;
	struct vbuffer *restrict buf;
};

static bool print_session_iter(
	const struct hashtable *t, const struct hashkey key, void *element,
	void *user)
{
	UNUSED(t);
	UNUSED(key);
	struct session *restrict ss = element;
	assert(key.data == ss->key);
	struct server_stats_ctx *restrict ctx = user;
	const int state = ss->kcp_state;
	ctx->num_in_state[state]++;
	const size_t waitsnd = (ss->kcp != NULL) ? ikcp_waitsnd(ss->kcp) : 0;
	switch (state) {
	case STATE_CONNECT:
	case STATE_CONNECTED:
	case STATE_LINGER:
		ctx->waitsnd += waitsnd;
		break;
	default:
		break;
	}
	if (state > ctx->level) {
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

	int rtt = -1, rto = -1;
	if (ss->kcp != NULL) {
		rtt = (int)CLAMP(ss->kcp->rx_srtt, INT_MIN, INT_MAX);
		rto = (int)CLAMP(ss->kcp->rx_rto, INT_MIN, INT_MAX);
	}
	ctx->buf = VBUF_APPENDF(
		ctx->buf,
		"[%08" PRIX32 "] %c peer=%s seen=%.0lfs "
		"rtt=%d rto=%d waitsnd=%zu rx/tx=%s/%s\n",
		ss->conv, session_state_char[state], addr_str, not_seen, rtt,
		rto, waitsnd, kcp_rx, kcp_tx);
#undef FORMAT_BYTES

	return true;
}

static struct vbuffer *print_session_table(
	const struct server *restrict s, struct vbuffer *restrict buf,
	const int level)
{
	struct server_stats_ctx ctx = {
		.level = level,
		.now = ev_now(s->loop),
		.buf = buf,
	};
	table_iterate(s->sessions, &print_session_iter, &ctx);
	return VBUF_APPENDF(
		ctx.buf,
		"  = %d sessions: %zu halfopen, %zu connected, %zu linger, %zu time_wait; waitsnd=%zu\n\n",
		table_size(s->sessions), ctx.num_in_state[STATE_CONNECT],
		ctx.num_in_state[STATE_CONNECTED],
		ctx.num_in_state[STATE_LINGER],
		ctx.num_in_state[STATE_TIME_WAIT], ctx.waitsnd);
}

static struct vbuffer *append_traffic_stats(
	struct vbuffer *buf, const struct link_stats *restrict stats)
{
#define FORMAT_BYTES(name, value)                                              \
	char name[16];                                                         \
	(void)format_iec_bytes(name, sizeof(name), (value))

	FORMAT_BYTES(tcp_rx, (double)(stats->tcp_rx));
	FORMAT_BYTES(tcp_tx, (double)(stats->tcp_tx));
	FORMAT_BYTES(kcp_rx, (double)(stats->kcp_rx));
	FORMAT_BYTES(kcp_tx, (double)(stats->kcp_tx));
	FORMAT_BYTES(pkt_rx, (double)(stats->pkt_rx));
	FORMAT_BYTES(pkt_tx, (double)(stats->pkt_tx));

#undef FORMAT_BYTES
	return VBUF_APPENDF(
		buf, "[total] tcp: %s, %s; kcp: %s, %s; pkt: %s, %s\n",
		/* total */ tcp_rx, tcp_tx, kcp_rx, kcp_tx, pkt_rx, pkt_tx);
}

static bool update_load(
	struct server *restrict s, char *buf, const size_t bufsize,
	const double dt)
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
	const double uptime = now - s->started;
	char uptime_str[16];
	(void)format_duration(
		uptime_str, sizeof(uptime_str), make_duration(uptime));
	buf = append_traffic_stats(buf, &s->stats);
	buf = VBUF_APPENDF(buf, "  = uptime: %s\n", uptime_str);
	return buf;
}

struct vbuffer *server_stats(
	struct server *restrict s, struct vbuffer *restrict buf,
	const int level)
{
	buf = print_session_table(s, buf, level);

	const ev_tstamp now = ev_now(s->loop);
	const double uptime = now - s->started;
	char uptime_str[16];
	(void)format_duration(
		uptime_str, sizeof(uptime_str), make_duration(uptime));
	const double dt = now - s->last_stats_time;
	const struct link_stats *restrict stats = &s->stats;

#define FORMAT_BYTES(name, value)                                              \
	char name[16];                                                         \
	(void)format_iec_bytes(name, sizeof(name), (value))

	const struct link_stats *restrict last_stats = &s->last_stats;
	const struct link_stats dstats = {
		.tcp_rx = stats->tcp_rx - last_stats->tcp_rx,
		.tcp_tx = stats->tcp_tx - last_stats->tcp_tx,
		.kcp_rx = stats->kcp_rx - last_stats->kcp_rx,
		.kcp_tx = stats->kcp_tx - last_stats->kcp_tx,
		.pkt_rx = stats->pkt_rx - last_stats->pkt_rx,
		.pkt_tx = stats->pkt_tx - last_stats->pkt_tx,
	};
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
			"[rx,tx] tcp: %s/s, %s/s; kcp: %s/s, %s/s; efficiency: %.1f%%, %.1f%%\n",
			dtcp_rx, dtcp_tx, dkcp_rx, dkcp_tx, deff_rx, deff_tx);
	}

	buf = append_traffic_stats(buf, &s->stats);

	{
		char load_buf[16];
		const char *load_str = "(unknown)";
		if (update_load(s, load_buf, sizeof(load_buf), dt)) {
			load_str = load_buf;
		}
		FORMAT_BYTES(dpkt_rx, dstats.pkt_rx / dt);
		FORMAT_BYTES(dpkt_tx, dstats.pkt_tx / dt);
		buf = VBUF_APPENDF(
			buf, "  = load: %s; pkt: %s/s, %s/s; uptime: %s\n",
			load_str, dpkt_rx, dpkt_tx, uptime_str);
	}
#undef FORMAT_BYTES

	/* rotate stats */
	s->last_clock = s->clock;
	s->last_stats = s->stats;
	s->last_stats_time = now;
	return buf;
}
