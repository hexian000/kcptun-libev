/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "server.h"

#include "conf.h"
#include "crypto.h"
#include "event.h"
#include "obfs.h"
#include "pktqueue.h"
#include "session.h"
#include "util.h"

#include "algo/hashtable.h"
#include "binary/serialize.h"
#include "ikcp.h"
#include "math/rand.h"
#include "meta/minmax.h"
#include "os/socket.h"
#include "strings/format.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static int
tcp_listen(const struct config *restrict conf, const struct sockaddr *sa)
{
	/* Create server socket */
	const int fd = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		LOG_PERROR("tcp socket");
		return -1;
	}
	if (!socket_nonblock_or_close(fd)) {
		return -1;
	}
	LOG_SOCKOPT(
		"socket_set_reuseport",
		socket_set_reuseport(fd, conf->tcp_reuseport));
	tcp_apply_conf(fd, conf);
	/* Bind socket to address */
	if (bind(fd, sa, sa_len(sa)) != 0) {
		LOG_PERROR("tcp bind");
		socket_close(fd);
		return -1;
	}
	/* Start listening on the socket */
	if (listen(fd, SOMAXCONN)) {
		LOG_PERROR("tcp listen");
		socket_close(fd);
		return -1;
	}
	return fd;
}

static bool listener_open(
	struct server *restrict s, const char *addrstr,
	void (*callback)(struct ev_loop *, ev_io *, int), ev_io *watcher,
	int *fd_slot, const char *label)
{
	union sockaddr_max addr;
	if (!resolve_bindaddr(&addr, addrstr, SA_RESOLVE_TCP)) {
		return false;
	}
	const int fd = tcp_listen(s->conf, &addr.sa);
	if (fd == -1) {
		return false;
	}
	ev_io_init(watcher, callback, fd, EV_READ);
	ev_set_priority(watcher, EV_MINPRI);
	watcher->data = s;
	ev_io_start(s->loop, watcher);
	*fd_slot = fd;
	if (LOGLEVEL(NOTICE)) {
		char addr_str[64];
		(void)sa_format(addr_str, sizeof(addr_str), &addr.sa);
		LOG_F(NOTICE, "%s listen: %s", label, addr_str);
	}
	return true;
}

static bool listener_start(struct server *restrict s)
{
	const struct config *restrict conf = s->conf;
	struct listener *restrict l = &s->listener;
	if (conf->listen != NULL && !listener_open(
					    s, conf->listen, tcp_accept_cb,
					    &l->w_accept, &l->fd, "tcp")) {
		return false;
	}
	if (conf->http_listen != NULL &&
	    !listener_open(
		    s, conf->http_listen, http_accept_cb, &l->w_accept_http,
		    &l->fd_http, "http")) {
		return false;
	}
	ev_timer *restrict w_listener = &l->w_timer;
	ev_timer_init(w_listener, listener_cb, 0.5, 0.0);
	ev_set_priority(w_listener, EV_MINPRI);
	w_listener->data = l;
	return true;
}

static bool udp_socket(
	struct pktconn *restrict udp, const struct config *restrict conf,
	const int udp_af)
{
	/* Setup a udp socket. */
	const int fd = socket(udp_af, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		LOG_PERROR("udp socket");
		return false;
	}
	if (!socket_nonblock_or_close(fd)) {
		return false;
	}
	const int reuse_err = socket_set_reuseport(fd, conf->udp_reuseport);
	const int buffer_err =
		socket_set_buffer(fd, conf->udp_sndbuf, conf->udp_rcvbuf);
	if (reuse_err != 0 || buffer_err != 0) {
		LOGE_F("udp socket options: (%d) %s",
		       reuse_err != 0 ? reuse_err : buffer_err,
		       strerror(reuse_err != 0 ? reuse_err : buffer_err));
		socket_close(fd);
		return false;
	}
	udp->fd = fd;
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
	FAILMSGF("invalid address family: %d", family);
}

static bool addr_set_local(
	union sockaddr_max *addr, const struct sockaddr *sa,
	const int transport_fd, const char *netdev)
{
	socklen_t len = sizeof(*addr);
	if (getsockname(transport_fd, &addr->sa, &len) != 0) {
		LOG_PERROR("udp getsockname");
		return false;
	}
	if ((addr->sa.sa_family == AF_INET &&
	     addr->in.sin_addr.s_addr != INADDR_ANY) ||
	    (addr->sa.sa_family == AF_INET6 &&
	     !IN6_IS_ADDR_UNSPECIFIED(&addr->in6.sin6_addr))) {
		return true;
	}
	const int fd = socket(sa->sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		const int err = errno;
		LOGW_F("socket: (%d) %s", err, strerror(err));
		return false;
	}
	if (netdev != NULL && !socket_bind_netdev(fd, netdev)) {
		socket_close(fd);
		return false;
	}
	if (connect(fd, sa, sa_len(sa))) {
		const int err = errno;
		LOGW_F("connect: (%d) %s", err, strerror(err));
		socket_close(fd);
		return false;
	}
	len = sizeof(*addr);
	if (getsockname(fd, &addr->sa, &len)) {
		const int err = errno;
		LOGW_F("getsockname: (%d) %s", err, strerror(err));
		socket_close(fd);
		return false;
	}
	socket_close(fd);
	return true;
}

static bool
udp_resolve(struct pktconn *restrict udp, const struct config *restrict conf)
{
	if (conf->kcp_bind != NULL &&
	    !resolve_bindaddr(&udp->kcp_bind, conf->kcp_bind, SA_RESOLVE_UDP)) {
		return false;
	}
	if (conf->kcp_connect != NULL &&
	    !resolve_addr(
		    &udp->configured_connect, conf->kcp_connect,
		    SA_RESOLVE_UDP)) {
		return false;
	}
	if ((conf->mode & MODE_RENDEZVOUS) != 0 &&
	    !resolve_addr(
		    &udp->rendezvous_server, conf->rendezvous_server,
		    SA_RESOLVE_UDP)) {
		return false;
	}
	const struct sockaddr *addresses[] = {
		&udp->kcp_bind.sa,
		&udp->configured_connect.sa,
		&udp->rendezvous_server.sa,
	};
	for (size_t i = 0; i < sizeof(addresses) / sizeof(addresses[0]); i++) {
		const int family = addresses[i]->sa_family;
		if (family == AF_UNSPEC) {
			continue;
		}
		if (udp->domain != AF_UNSPEC && udp->domain != family) {
			LOGE("udp addresses must use the same address family");
			return false;
		}
		udp->domain = family;
	}
	return true;
}

static bool udp_local_port(struct pktconn *restrict udp)
{
	union sockaddr_max local = { 0 };
	socklen_t len = sizeof(local);
	if (getsockname(udp->fd, &local.sa, &len) != 0) {
		LOG_PERROR("udp getsockname");
		return false;
	}
	switch (udp->domain) {
	case AF_INET:
		udp->rendezvous_local.in.sin_port = local.in.sin_port;
		break;
	case AF_INET6:
		udp->rendezvous_local.in6.sin6_port = local.in6.sin6_port;
		break;
	default:
		FAILMSGF("invalid address family: %d", udp->domain);
	}
	return true;
}

static bool udp_bind(
	struct pktconn *restrict udp, const struct config *restrict conf,
	bool strict)
{
	if (!udp_socket(udp, conf, udp->domain)) {
		return false;
	}
	udp->sndbuf = conf->udp_sndbuf;
	udp->rcvbuf = conf->udp_rcvbuf;
	udp->reuseport = conf->udp_reuseport;
	if (conf->netdev != NULL) {
		udp->netdev = strdup(conf->netdev);
		if (udp->netdev == NULL) {
			LOGOOM();
			return false;
		}
		if (!socket_bind_netdev(udp->fd, udp->netdev)) {
			return false;
		}
	}
	if (udp->kcp_bind.sa.sa_family != AF_UNSPEC) {
		const struct sockaddr *sa = &udp->kcp_bind.sa;
		if (bind(udp->fd, sa, sa_len(sa)) != 0) {
			LOG_PERROR("udp bind");
			return false;
		}
		if (LOGLEVEL(NOTICE)) {
			char addr_str[64];
			(void)sa_format(addr_str, sizeof(addr_str), sa);
			LOG_F(NOTICE, "udp bind: %s", addr_str);
		}
	}
	if (udp->configured_connect.sa.sa_family != AF_UNSPEC) {
		const struct sockaddr *sa = &udp->configured_connect.sa;
		if (connect(udp->fd, sa, sa_len(sa)) != 0) {
			LOG_PERROR("udp connect");
			return false;
		}
		udp->kcp_connect = udp->configured_connect;
		udp->connected = true;
		if (LOGLEVEL(NOTICE)) {
			char addr_str[64];
			(void)sa_format(addr_str, sizeof(addr_str), sa);
			LOG_F(NOTICE, "udp connect: %s", addr_str);
		}
	}
	if ((conf->mode & MODE_RENDEZVOUS) != 0) {
		if (!addr_set_local(
			    &udp->rendezvous_local, &udp->rendezvous_server.sa,
			    udp->fd, udp->netdev)) {
			if (strict) {
				return false;
			}
			addr_set_any(&udp->rendezvous_local, udp->domain);
		}
		if (!udp_local_port(udp) && strict) {
			return false;
		}
		if (LOGLEVEL(INFO)) {
			char addr_str[64], laddr_str[64];
			(void)sa_format(
				addr_str, sizeof(addr_str),
				&udp->rendezvous_server.sa);
			(void)sa_format(
				laddr_str, sizeof(laddr_str),
				&udp->rendezvous_local.sa);
			LOG_F(INFO, "rendezvous mode: %s -> %s", laddr_str,
			      addr_str);
		}
	}
	return true;
}

static size_t udp_overhead(const struct pktconn *restrict udp)
{
	switch (udp->domain) {
	case AF_INET:
		return 28;
	case AF_INET6:
		return 48;
	default:
		FAILMSGF("invalid address family: %d", udp->domain);
	}
}

/* calculate max send size */
static size_t server_mss(const struct server *restrict s)
{
	const size_t mtu = (size_t)s->conf->kcp_mtu;
	size_t mss = mtu;
#if WITH_OBFS
	const struct obfs *restrict obfs = s->pkt.queue->obfs;
	if (obfs != NULL) {
		mss -= obfs_overhead(obfs);
	} else {
		mss -= udp_overhead(&s->pkt);
	}
#else
	mss -= udp_overhead(&s->pkt);
#endif /* WITH_OBFS */
#if WITH_CRYPTO
	const struct crypto *restrict crypto = s->pkt.queue->crypto;
	if (crypto != NULL) {
		mss -= (crypto->overhead + crypto->nonce_size);
	}
#endif
	/* kcp_mtu's conf.c-enforced minimum of 300 keeps this well clear
	 * of the total overhead; catch it loudly if that ever changes */
	ASSERT(mss <= mtu);
	return mss;
}

static bool udp_addr_equal(const struct sockaddr *a, const struct sockaddr *b)
{
	return (a->sa_family == AF_UNSPEC && b->sa_family == AF_UNSPEC) ||
	       sa_equals(a, b);
}

static bool nullable_string_equal(const char *a, const char *b)
{
	return a == NULL ? b == NULL : b != NULL && strcmp(a, b) == 0;
}

/* Preparation owns only candidate resources and never touches live watchers. */
static bool udp_unchanged(
	const struct pktconn *udp, const struct pktconn *next,
	const struct config *conf)
{
	return udp->fd != -1 && udp->sndbuf == conf->udp_sndbuf &&
	       udp->rcvbuf == conf->udp_rcvbuf &&
	       udp->reuseport == conf->udp_reuseport &&
	       nullable_string_equal(udp->netdev, conf->netdev) &&
	       udp_addr_equal(&udp->kcp_bind.sa, &next->kcp_bind.sa) &&
	       udp_addr_equal(
		       &udp->configured_connect.sa,
		       &next->configured_connect.sa) &&
	       udp_addr_equal(
		       &udp->rendezvous_server.sa, &next->rendezvous_server.sa);
}

static void udp_discard(struct pktconn *next)
{
	if (next->fd != -1) {
		socket_close(next->fd);
	}
	free(next->netdev);
}

static void udp_commit(struct server *s, struct pktconn *next)
{
	struct pktconn *udp = &s->pkt;
	if (udp->fd != -1) {
		LOGN("udp socket restart");
		ev_io_stop(s->loop, &udp->w_read);
		ev_io_stop(s->loop, &udp->w_write);
		socket_close(udp->fd);
	}
	free(udp->netdev);
	udp->netdev = next->netdev;
	udp->sndbuf = next->sndbuf;
	udp->rcvbuf = next->rcvbuf;
	udp->reuseport = next->reuseport;
	udp->fd = next->fd;
	udp->domain = next->domain;
	udp->connected = next->connected;
	udp->kcp_bind = next->kcp_bind;
	udp->configured_connect = next->configured_connect;
	udp->kcp_connect = next->kcp_connect;
	udp->rendezvous_server = next->rendezvous_server;
	udp->rendezvous_local = next->rendezvous_local;
	ev_io_init(&udp->w_read, pkt_read_cb, udp->fd, EV_READ);
	udp->w_read.data = s;
	ev_io_start(s->loop, &udp->w_read);
	ev_io_init(&udp->w_write, pkt_write_cb, udp->fd, EV_WRITE);
	udp->w_write.data = s;
	if (udp->queue->mq_send_len > 0) {
		ev_io_start(s->loop, &udp->w_write);
	}
}

static bool udp_restart(struct server *restrict s)
{
	struct pktconn next = { .fd = -1 };
	if (!udp_resolve(&next, s->conf)) {
		return false;
	}
	if (udp_unchanged(&s->pkt, &next, s->conf)) {
		if ((s->conf->mode & (MODE_CLIENT | MODE_RENDEZVOUS)) ==
			    (MODE_CLIENT | MODE_RENDEZVOUS) &&
		    (s->pkt.last_recv_time == TSTAMP_NIL ||
		     ev_now(s->loop) - s->pkt.last_recv_time >= s->timeout)) {
			s->pkt.connected = false;
		}
		return true;
	}
	if (!udp_bind(&next, s->conf, false)) {
		udp_discard(&next);
		return false;
	}
	udp_commit(s, &next);
	return true;
}

static bool resolve_connect(struct server *restrict s)
{
	const struct config *restrict conf = s->conf;
	if (conf->connect == NULL) {
		return true;
	}
	return resolve_addr(&s->connect, conf->connect, SA_RESOLVE_TCP);
}

static void server_update_packet_size(struct server *restrict s)
{
	struct pktqueue *restrict q = s->pkt.queue;
	q->msg_offset = 0;
#if WITH_OBFS
	if (q->obfs != NULL) {
		q->msg_offset = (uint16_t)obfs_overhead(q->obfs);
	}
#endif
	q->mss = (uint16_t)server_mss(s);
}

/* shared by server_new and server_loadconf, so a SIGHUP reload can never
 * drift from the invariants established at startup */
static void
server_apply_conf(struct server *restrict s, const struct config *restrict conf)
{
	const double ping_timeout = 4.0;
	s->linger = conf->linger;
	s->dial_timeout = 30.0;
	s->session_timeout = conf->timeout;
	s->session_keepalive =
		conf->timeout - SESSION_TIMEOUT_INTERVAL - ping_timeout;
	s->keepalive = conf->keepalive;
	if ((conf->mode & (MODE_CLIENT | MODE_RENDEZVOUS)) == 0) {
		/* server mode: disable keepalive */
		s->keepalive = 0.0;
	}
	s->timeout = CLAMP(conf->keepalive * 3.0 + ping_timeout, 10.0, 1800.0);
	s->ping_timeout = ping_timeout;
	s->time_wait = conf->time_wait;
}

struct server *
server_new(struct ev_loop *loop, const struct config *restrict conf)
{
	struct server *restrict s = malloc(sizeof(struct server));
	if (s == NULL) {
		LOGOOM();
		return NULL;
	}
	*s = (struct server){
		.loop = loop,
		.conf = conf,
		.conv = (uint32_t)rand64(),
		.listener = (struct listener){ .fd = -1, .fd_http = -1 },
		.pkt =
			(struct pktconn){
				.fd = -1,
				.last_send_time = TSTAMP_NIL,
				.last_recv_time = TSTAMP_NIL,
				.inflight_ping = TSTAMP_NIL,
			},
		.started = TSTAMP_NIL,
		.last_resolve_time = TSTAMP_NIL,
		.last_stats_time = TSTAMP_NIL,
	};
	ev_io_init(&s->pkt.w_read, pkt_read_cb, -1, EV_READ);
	s->pkt.w_read.data = s;
	ev_io_init(&s->pkt.w_write, pkt_write_cb, -1, EV_WRITE);
	s->pkt.w_write.data = s;
	server_apply_conf(s, conf);

	{
		const double interval = conf->kcp_interval * 1e-3;
		ev_timer *restrict w_kcp_update = &s->w_kcp_update;
		ev_timer_init(w_kcp_update, kcp_update_cb, interval, interval);
		w_kcp_update->data = s;

		ev_timer *restrict w_keepalive = &s->w_keepalive;
		ev_timer_init(w_keepalive, keepalive_cb, 0.0, s->keepalive);
		ev_set_priority(w_keepalive, EV_MINPRI);
		w_keepalive->data = s;

		ev_timer *restrict w_resolve = &s->w_resolve;
		ev_timer_init(w_resolve, resolve_cb, s->timeout, s->timeout);
		ev_set_priority(w_resolve, EV_MINPRI);
		w_resolve->data = s;

		ev_timer *restrict w_timeout = &s->w_timeout;
		ev_timer_init(
			w_timeout, timeout_cb, SESSION_TIMEOUT_INTERVAL,
			SESSION_TIMEOUT_INTERVAL);
		ev_set_priority(w_timeout, EV_MINPRI);
		w_timeout->data = s;
	}

	int flags = 0;
	if ((conf->mode & MODE_SERVER) != 0) {
		flags |= TABLE_FAST;
	}
	const struct table_opts opts = { .flags = flags };
	s->sessions = table_new(&opts);
	if (s->sessions == NULL) {
		LOGOOM();
		server_free(s);
		return NULL;
	}
	s->pkt.services = table_new(&opts);
	if (s->pkt.services == NULL) {
		LOGOOM();
		server_free(s);
		return NULL;
	}
	s->pkt.queue = queue_new(s);
	if (s->pkt.queue == NULL) {
		LOGE("failed to create packet queue");
		server_free(s);
		return NULL;
	}
	return s;
}

static bool reload_compatible(const struct server *s, const struct config *conf)
{
	const struct config *old = s->conf;
	if (old->mode != conf->mode ||
	    !nullable_string_equal(old->listen, conf->listen) ||
	    !nullable_string_equal(old->http_listen, conf->http_listen)) {
		LOGE("config: mode and listener changes require restart");
		return false;
	}
#if WITH_OBFS
	if (!nullable_string_equal(old->obfs, conf->obfs) ||
	    (old->obfs != NULL &&
	     (!nullable_string_equal(old->kcp_bind, conf->kcp_bind) ||
	      !nullable_string_equal(old->kcp_connect, conf->kcp_connect) ||
	      !nullable_string_equal(old->netdev, conf->netdev) ||
	      old->udp_sndbuf != conf->udp_sndbuf ||
	      old->udp_rcvbuf != conf->udp_rcvbuf ||
	      old->tcp_reuseport != conf->tcp_reuseport))) {
		LOGE("config: obfs transport changes require restart");
		return false;
	}
#endif /* WITH_OBFS */
#if WITH_CRYPTO
	if (!nullable_string_equal(old->method, conf->method)) {
		LOGE("config: encryption method changes require restart");
		return false;
	}
	if (conf->method != NULL) {
		struct crypto *candidate = crypto_new(conf->method);
		if (candidate == NULL) {
			return false;
		}
		const bool prepared =
			conf->psk != NULL ?
				crypto_b64psk(candidate, conf->psk) :
				crypto_password(candidate, conf->password);
		const bool same =
			prepared &&
			crypto_same_key(s->pkt.queue->crypto, candidate);
		crypto_free(candidate);
		if (!same) {
			LOGE("config: key setup failed or key change requires restart");
			return false;
		}
	}
#endif /* WITH_CRYPTO */
	return true;
}

bool server_loadconf(
	struct server *restrict s, const struct config *restrict conf)
{
	if (!reload_compatible(s, conf)) {
		return false;
	}
	union sockaddr_max connect = { 0 };
	if (conf->connect != NULL &&
	    !resolve_addr(&connect, conf->connect, SA_RESOLVE_TCP)) {
		return false;
	}
	struct pktconn next = { .fd = -1 };
	bool replace_udp = false;
#if WITH_OBFS
	if (s->pkt.queue->obfs == NULL)
#endif
	{
		if (!udp_resolve(&next, conf)) {
			return false;
		}
		replace_udp = !udp_unchanged(&s->pkt, &next, conf);
		if (replace_udp && !udp_bind(&next, conf, true)) {
			udp_discard(&next);
			return false;
		}
	}
	/* All fallible work is complete. Keep sessions, crypto and replay state. */
	if (replace_udp) {
		udp_commit(s, &next);
	}
	s->conf = conf;
	s->connect = connect;
	server_apply_conf(s, conf);
	const double interval = conf->kcp_interval * 1e-3;
	s->w_kcp_update.repeat = interval;
	ev_timer_again(s->loop, &s->w_kcp_update);
	s->w_keepalive.repeat = s->keepalive;
	ev_timer_again(s->loop, &s->w_keepalive);
	s->w_resolve.repeat = s->timeout;
	ev_timer_again(s->loop, &s->w_resolve);
	s->last_resolve_time = ev_now(s->loop);
	s->resolve_failed = false;
	server_update_packet_size(s);
	return true;
}

bool server_start(struct server *restrict s)
{
	struct ev_loop *loop = s->loop;
	const ev_tstamp now = ev_now(loop);
	if (!listener_start(s)) {
		return false;
	}
	s->started = now;
	s->last_stats_time = now;
	if (!resolve_connect(s)) {
		return false;
	}
	s->last_resolve_time = now;
	ev_timer_start(loop, &s->w_kcp_update);
	if (s->keepalive > 0.0) {
		ev_timer_start(loop, &s->w_keepalive);
	}
	ev_timer_start(loop, &s->w_resolve);
	ev_timer_start(loop, &s->w_timeout);

	bool ok;
#if WITH_OBFS
	struct pktqueue *restrict q = s->pkt.queue;
	if (q->obfs != NULL) {
		ok = obfs_start(q->obfs, s);
	} else
#endif
	{
		ok = udp_restart(s);
	}
	if (!ok) {
		return false;
	}
	server_update_packet_size(s);
	return true;
}

void server_ping(struct server *restrict s)
{
	const struct sockaddr *sa;
	if ((s->conf->mode & MODE_CLIENT) != 0) {
		sa = &s->pkt.kcp_connect.sa;
	} else {
		return;
	}

	const ev_tstamp now = ev_time();
	const uint32_t tstamp = tstamp2ms(now);
	unsigned char b[sizeof(uint32_t)];
	write_uint32(b, tstamp);
	ss0_send(s, sa, S0MSG_PING, b, sizeof(b));
	s->pkt.inflight_ping = now;
}

struct server_stats_ctx {
	size_t num_in_state[KCP_STATE_MAX];
	size_t waitsnd;
	int level;
	ev_tstamp now;
	struct vbuffer *restrict buf;
};

static bool print_session_iter(
	const struct hashtable *t, const void *key, void *element, void *user)
{
	UNUSED(t);
	UNUSED(key);
	struct session *restrict ss = element;
	ASSERT(((const struct hashkey *)key)->data == ss->key);
	struct server_stats_ctx *restrict ctx = user;
	const int state = ss->kcp_state;
	ctx->num_in_state[state]++;
	const size_t waitsnd = (ss->kcp != NULL) ? ikcp_waitsnd(ss->kcp) : 0;
	switch (state) {
	case KCP_STATE_CONNECT:
	case KCP_STATE_ESTABLISHED:
	case KCP_STATE_LINGER:
		ctx->waitsnd += waitsnd;
		break;
	default:
		break;
	}
	if (state > ctx->level) {
		return true;
	}
	char addr_str[64];
	(void)sa_format(addr_str, sizeof(addr_str), &ss->raddr.sa);
	ev_tstamp last_seen = ss->created;
	if (ss->last_send != TSTAMP_NIL && ss->last_send > last_seen) {
		last_seen = ss->last_send;
	}
	if (ss->last_recv != TSTAMP_NIL && ss->last_recv > last_seen) {
		last_seen = ss->last_recv;
	}
	const double not_seen =
		last_seen != TSTAMP_NIL ? ctx->now - last_seen : TSTAMP_NIL;

	/* intentionally shows tcp_tx/tcp_rx, not kcp_rx/kcp_tx: the local
	 * TCP peer's own view of this session's traffic, mirroring the
	 * tcp/kcp-crossing server_stats uses for its efficiency ratio */
	FORMAT_IEC_BYTES(kcp_rx, (double)ss->stats.tcp_tx);
	FORMAT_IEC_BYTES(kcp_tx, (double)ss->stats.tcp_rx);

	int rtt = -1, rto = -1;
	if (ss->kcp != NULL) {
		rtt = (int)ss->kcp->rx_srtt;
		rto = (int)ss->kcp->rx_rto;
	}
	VBUF_APPENDF(
		ctx->buf,
		"[%08" PRIX32 "] %c peer=%s seen=%.0lfs "
		"rtt=%d rto=%d waitsnd=%zu rx/tx=%s/%s\n",
		ss->conv, kcp_state_char[state], addr_str, not_seen, rtt, rto,
		waitsnd, kcp_rx, kcp_tx);

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
	VBUF_APPENDF(
		ctx.buf,
		"  = %zu sessions: %zu halfopen, %zu connected, %zu linger, %zu time_wait; waitsnd=%zu\n\n",
		table_size(s->sessions), ctx.num_in_state[KCP_STATE_CONNECT],
		ctx.num_in_state[KCP_STATE_ESTABLISHED],
		ctx.num_in_state[KCP_STATE_LINGER],
		ctx.num_in_state[KCP_STATE_TIME_WAIT], ctx.waitsnd);
	return ctx.buf;
}

static struct vbuffer *append_traffic_stats(
	struct vbuffer *buf, const struct link_stats *restrict stats)
{
	FORMAT_IEC_BYTES(tcp_rx, (double)(stats->tcp_rx));
	FORMAT_IEC_BYTES(tcp_tx, (double)(stats->tcp_tx));
	FORMAT_IEC_BYTES(kcp_rx, (double)(stats->kcp_rx));
	FORMAT_IEC_BYTES(kcp_tx, (double)(stats->kcp_tx));
	FORMAT_IEC_BYTES(pkt_rx, (double)(stats->pkt_rx));
	FORMAT_IEC_BYTES(pkt_tx, (double)(stats->pkt_tx));

	VBUF_APPENDF(
		buf, "[total] tcp: %s, %s; kcp: %s, %s; pkt: %s, %s\n",
		/* total */ tcp_rx, tcp_tx, kcp_rx, kcp_tx, pkt_rx, pkt_tx);
	return buf;
}

struct vbuffer *server_stats_const(
	const struct server *restrict s, struct vbuffer *restrict buf,
	const int level)
{
	buf = print_session_table(s, buf, level);

	const ev_tstamp now = ev_now(s->loop);
	const double uptime = now - s->started;
	char uptime_str[16];
	(void)format_duration(
		uptime_str, sizeof(uptime_str), make_duration(uptime));
	buf = append_traffic_stats(buf, &s->stats);
	VBUF_APPENDF(buf, "  = uptime: %s\n", uptime_str);
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

#define FORMAT_DURATION(name, value)                                           \
	char name[16];                                                         \
	(void)format_duration(name, sizeof(name), (value))

	const struct link_stats *restrict last_stats = &s->last_stats;
	const struct link_stats dstats = {
		.tcp_rx = stats->tcp_rx - last_stats->tcp_rx,
		.tcp_tx = stats->tcp_tx - last_stats->tcp_tx,
		.kcp_rx = stats->kcp_rx - last_stats->kcp_rx,
		.kcp_tx = stats->kcp_tx - last_stats->kcp_tx,
		.pkt_rx = stats->pkt_rx - last_stats->pkt_rx,
		.pkt_tx = stats->pkt_tx - last_stats->pkt_tx,
	};
	/* two calls within the same event-loop iteration (or a backward
	 * wall-clock step) would otherwise divide by a zero or negative dt */
	if (dt > 0) {
		FORMAT_IEC_BYTES(dtcp_rx, dstats.tcp_rx / dt);
		FORMAT_IEC_BYTES(dtcp_tx, dstats.tcp_tx / dt);
		FORMAT_IEC_BYTES(dkcp_rx, dstats.kcp_rx / dt);
		FORMAT_IEC_BYTES(dkcp_tx, dstats.kcp_tx / dt);
		/* kcp_rx/kcp_tx are legitimately zero on any idle interval */
		const double deff_rx = dstats.kcp_rx > 0 ?
					       (double)dstats.tcp_tx * 100.0 /
						       (double)dstats.kcp_rx :
					       0.0;
		const double deff_tx = dstats.kcp_tx > 0 ?
					       (double)dstats.tcp_rx * 100.0 /
						       (double)dstats.kcp_tx :
					       0.0;

		VBUF_APPENDF(
			buf,
			"[rx,tx] tcp: %s/s, %s/s; kcp: %s/s, %s/s; efficiency: %.1f%%, %.1f%%\n",
			dtcp_rx, dtcp_tx, dkcp_rx, dkcp_tx, deff_rx, deff_tx);
	}

	buf = append_traffic_stats(buf, &s->stats);

	char load_str[16] = "(unknown)";
	const double load = thread_load();
	if (load >= 0) {
		(void)snprintf(
			load_str, sizeof(load_str), "%.03f%%", load * 100);
	}
	FORMAT_DURATION(dt_str, make_duration(dt));
	char dpkt_rx[16] = "(unknown)", dpkt_tx[16] = "(unknown)";
	if (dt > 0) {
		(void)format_iec_bytes(
			dpkt_rx, sizeof(dpkt_rx), (double)dstats.pkt_rx / dt);
		(void)format_iec_bytes(
			dpkt_tx, sizeof(dpkt_tx), (double)dstats.pkt_tx / dt);
	}
	VBUF_APPENDF(
		buf, "  = load: %s (last %s); pkt: %s/s, %s/s; uptime: %s\n",
		load_str, dt_str, dpkt_rx, dpkt_tx, uptime_str);

#undef FORMAT_DURATION

	/* rotate stats */
	s->last_stats = s->stats;
	s->last_stats_time = now;
	return buf;
}

bool server_healthy(
	const struct server *restrict s, char *restrict buf,
	const size_t bufsize)
{
	const int mode = s->conf->mode;
	/* a pure server has no upstream peer to monitor */
	if ((mode & MODE_CLIENT) == 0) {
		(void)snprintf(buf, bufsize, "healthy");
		return true;
	}
	/* a rendezvous client must have located its peer first */
	if ((mode & MODE_RENDEZVOUS) != 0 && !s->pkt.connected) {
		(void)snprintf(buf, bufsize, "rendezvous pending");
		return false;
	}
	const ev_tstamp last = s->pkt.last_recv_time;
	if (last == TSTAMP_NIL) {
		(void)snprintf(buf, bufsize, "peer unreachable");
		return false;
	}
	const double idle = ev_now(s->loop) - last;
	if (idle > s->timeout) {
		(void)snprintf(
			buf, bufsize, "peer not responding (%.0fs)", idle);
		return false;
	}
	(void)snprintf(buf, bufsize, "healthy (peer seen %.0fs ago)", idle);
	return true;
}

bool server_resolve(struct server *restrict s)
{
	bool ok = resolve_connect(s);
	if (ok) {
#if WITH_OBFS
		struct pktqueue *restrict q = s->pkt.queue;
		if (q->obfs != NULL) {
			ok = obfs_resolve(q->obfs);
		} else
#endif
		{
			ok = udp_restart(s);
		}
	}
	s->resolve_failed = !ok;
	s->last_resolve_time = ev_now(s->loop);
	s->w_resolve.repeat = ok ? s->timeout : 5.0;
	ev_timer_again(s->loop, &s->w_resolve);
	if (ok) {
		server_update_packet_size(s);
	}
	return ok;
}

void udp_rendezvous(struct server *restrict s, const uint16_t what)
{
	if (s->pkt.fd == -1) {
		return;
	}
	udp_local_port(&s->pkt);
	const size_t idlen = s->conf->service_idlen;
	const struct sockaddr *sa_server = &s->pkt.rendezvous_server.sa;
	const struct sockaddr *sa_local = &s->pkt.rendezvous_local.sa;
	ASSERT(idlen <= UINT16_MAX);
	unsigned char b[INET6ADDR_LENGTH + sizeof(uint16_t) + idlen];
	unsigned char *p = b;
	size_t n = inetaddr_write(p, sa_local, sizeof(b));
	ASSERT(n > 0);
	p += n;
	write_uint16(p, (uint_fast16_t)idlen);
	p += sizeof(uint16_t), n += sizeof(uint16_t);
	if (idlen > 0) {
		memcpy(p, s->conf->service_id, idlen);
		n += idlen;
	}
	ss0_send(s, sa_server, what, b, n);
}

static bool svc_shutdown_filt(
	const struct hashtable *t, const void *key, void *element, void *user)
{
	UNUSED(t);
	UNUSED(key);
	UNUSED(user);
	struct service *restrict svc = element;
	ASSERT(((const struct hashkey *)key)->data == svc->id);
	free(svc);
	return false;
}

static void udp_stop(struct ev_loop *loop, struct pktconn *restrict conn)
{
	conn->services = table_filter(conn->services, svc_shutdown_filt, NULL);
	if (conn->fd == -1) {
		return;
	}
	ev_io_stop(loop, &conn->w_read);
	ev_io_stop(loop, &conn->w_write);
	socket_close(conn->fd);
	conn->fd = -1;
	ev_io_set(&conn->w_read, -1, EV_READ);
	ev_io_set(&conn->w_write, -1, EV_WRITE);
}

static void udp_free(struct pktconn *restrict conn)
{
	if (conn == NULL) {
		return;
	}
	UTIL_SAFE_FREE(conn->netdev);
	if (conn->queue != NULL) {
		queue_free(conn->queue);
		conn->queue = NULL;
	}
	if (conn->services != NULL) {
		table_free(conn->services);
		conn->services = NULL;
	}
}

static void listener_stop(struct ev_loop *loop, struct listener *restrict l)
{
	if (l->fd != -1) {
		LOGD_F("listener [fd:%d] close", l->fd);
		ev_io *restrict w_accept = &l->w_accept;
		ev_io_stop(loop, w_accept);
		socket_close(l->fd);
		l->fd = -1;
	}
	if (l->fd_http != -1) {
		LOGD_F("http listener [fd:%d] close", l->fd_http);
		ev_io *restrict w_accept_http = &l->w_accept_http;
		ev_io_stop(loop, w_accept_http);
		socket_close(l->fd_http);
		l->fd_http = -1;
	}
	ev_timer_stop(loop, &l->w_timer);
}

static bool shutdown_filt(
	const struct hashtable *t, const void *key, void *element, void *user)
{
	UNUSED(t);
	UNUSED(key);
	UNUSED(user);
	struct session *restrict ss = element;
	ASSERT(((const struct hashkey *)key)->data == ss->key);
	session_free(ss);
	return false;
}

/* stop every server watcher and the packet transport; safe to call on a
   partially-started server (s->pkt.queue may be NULL) */
static void server_watchers_stop(struct server *restrict s)
{
	struct ev_loop *loop = s->loop;
	listener_stop(loop, &s->listener);
	http_stop(s);
	ev_timer_stop(loop, &s->w_kcp_update);
	ev_timer_stop(loop, &s->w_keepalive);
	ev_timer_stop(loop, &s->w_resolve);
	ev_timer_stop(loop, &s->w_timeout);
#if WITH_OBFS
	if (s->pkt.queue != NULL && s->pkt.queue->obfs != NULL) {
		obfs_stop(s->pkt.queue->obfs, s);
	} else {
		udp_stop(s->loop, &s->pkt);
	}
#else
	udp_stop(s->loop, &s->pkt);
#endif
}

void server_stop(struct server *restrict s)
{
	server_watchers_stop(s);
	const size_t num = table_size(s->sessions);
	s->sessions = table_filter(s->sessions, shutdown_filt, NULL);
	LOGI_F("%zu sessions closed", num);
}

void server_free(struct server *restrict s)
{
	/* defensively tear down any still-active state: server_start can fail
	 * after partially starting up, and the caller goes straight to
	 * server_free without calling server_stop first. server_watchers_stop
	 * is a safe no-op if the corresponding state was never started. */
	server_watchers_stop(s);
	udp_free(&s->pkt);
	if (s->sessions != NULL) {
		/* free any surviving session payloads before the table itself,
		   matching server_stop; a no-op when server_stop already ran */
		s->sessions = table_filter(s->sessions, shutdown_filt, NULL);
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
	uint32_t conv = conv_next(s->conv);
	unsigned char key[SESSION_KEY_SIZE];
	const struct hashkey hkey = {
		.len = sizeof(key),
		.data = key,
	};
	SESSION_MAKEKEY(key, sa, conv);
	if (table_find(s->sessions, &hkey, NULL)) {
		const double usage =
			(double)table_size(s->sessions) / (double)MAX_SESSIONS;
		do {
			if (usage < 1e-3) {
				conv = (uint32_t)rand64();
			}
			conv = conv_next(conv);
			SESSION_MAKEKEY(key, sa, conv);
		} while (table_find(s->sessions, &hkey, NULL));
	}
	s->conv = conv;
	return conv;
}
