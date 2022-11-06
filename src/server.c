#include "server.h"
#include "conf.h"
#include "event.h"

#include "hashtable.h"
#include "pktqueue.h"
#include "obfs.h"
#include "slog.h"
#include "util.h"
#include "sockutil.h"

#include <ev.h>

#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdbool.h>
#include <math.h>

static bool listener_start(struct server *restrict s, struct netaddr *addr)
{
	struct config *restrict cfg = s->conf;
	struct listener *restrict l = &(s->listener);
	if (!resolve_netaddr(addr, RESOLVE_TCP | RESOLVE_PASSIVE)) {
		return false;
	}
	const struct sockaddr *sa = addr->sa;
	// Create server socket
	const int fd = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		LOGE_PERROR("socket error");
		return false;
	}
	if (socket_setup(fd)) {
		LOGE_PERROR("fcntl");
		if (close(fd) != 0) {
			LOGW_PERROR("close");
		}
		return false;
	}
	socket_set_reuseport(fd, cfg->tcp_reuseport);
	socket_set_tcp(fd, cfg->tcp_nodelay, cfg->tcp_keepalive);
	socket_set_buffer(fd, cfg->tcp_sndbuf, cfg->tcp_rcvbuf);

	// Bind socket to address
	if (bind(fd, sa, getsocklen(sa)) != 0) {
		LOGE_PERROR("bind error");
		if (close(fd) != 0) {
			LOGW_PERROR("close");
		}
		return false;
	}

	// Start listing on the socket
	if (listen(fd, 16)) {
		LOGE_PERROR("listen error");
		if (close(fd) != 0) {
			LOGW_PERROR("close");
		}
		return false;
	}

	// Initialize and start a watcher to accepts client requests
	struct ev_io *restrict w_accept = &l->w_accept;
	ev_io_init(w_accept, accept_cb, fd, EV_READ);
	w_accept->data = s;
	ev_io_start(s->loop, w_accept);

	if (LOGLEVEL(LOG_LEVEL_INFO)) {
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOGI_F("listen at: %s", addr_str);
	}
	l->fd = fd;
	return true;
}

static bool udp_bind(struct pktconn *restrict udp, struct config *restrict conf)
{
	if (conf->pkt_bind.str != NULL) {
		if (!resolve_netaddr(
			    &conf->pkt_bind, RESOLVE_UDP | RESOLVE_PASSIVE)) {
			return false;
		}
		const struct sockaddr *sa = conf->pkt_bind.sa;
		if (bind(udp->fd, sa, getsocklen(sa))) {
			LOGE_PERROR("udp bind");
			return false;
		}
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOGI_F("udp bind: %s", addr_str);
	}
	if (conf->pkt_connect.str != NULL) {
		if (!resolve_netaddr(&conf->pkt_connect, RESOLVE_UDP)) {
			return false;
		}
		const struct sockaddr *sa = conf->pkt_connect.sa;
		if (connect(udp->fd, sa, getsocklen(sa))) {
			LOGE_PERROR("udp connect");
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
	return udp_bind(&s->pkt, conf);
}

static bool udp_start(struct server *restrict s)
{
	struct config *restrict conf = s->conf;
	struct pktconn *restrict udp = &s->pkt;

	// Setup a udp socket.
	const int udp_af = conf->pkt_bind.sa != NULL ?
				   conf->pkt_bind.sa->sa_family :
				   conf->pkt_connect.sa->sa_family;
	if ((udp->fd = socket(udp_af, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		LOGE_PERROR("udp socket");
		return false;
	}
	if (socket_setup(udp->fd)) {
		LOGE_PERROR("fcntl");
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
	struct server *s = util_malloc(sizeof(struct server));
	if (s == NULL) {
		return NULL;
	}
	*s = (struct server){
		.loop = loop,
		.conf = conf,
		.m_conv = rand32(),
		.listener = (struct listener){ .fd = -1 },
		.pkt =
			(struct pktconn){
				.fd = -1,
				.inflight_ping = TSTAMP_NIL,
			},
		.last_resolve_time = ev_now(loop),
		.interval = conf->kcp_interval * 1e-3,
		.linger = conf->linger,
		.dial_timeout = 30.0,
		.session_timeout = conf->timeout,
		.session_keepalive = conf->timeout / 2.0,
		.keepalive = conf->keepalive,
		.time_wait = conf->time_wait,
	};

	struct ev_timer *restrict w_kcp_update = &s->w_kcp_update;
	ev_timer_init(w_kcp_update, kcp_update_cb, s->interval, s->interval);
	w_kcp_update->data = s;
	struct ev_timer *restrict w_timer = &s->w_timer;
	ev_timer_init(w_timer, timer_cb, 1.0, 1.0);
	w_timer->data = s;

	s->sessions = table_create();
	if (s->sessions == NULL) {
		server_free(s);
		return NULL;
	}
	s->pkt.queue = pktqueue_new(s);
	if (s->pkt.queue == NULL) {
		LOGE("failed creating packet queue");
		server_free(s);
		return false;
	}
	return s;
}

bool server_start(struct server *s)
{
	if (!server_resolve(s)) {
		return false;
	}
	struct ev_loop *loop = s->loop;
	struct config *restrict conf = s->conf;
	if (conf->listen.str) {
		if (!listener_start(s, &conf->listen)) {
			return false;
		}
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
		LOGW_PERROR("close");
	}
	conn->fd = -1;
}

static void udp_free(struct pktconn *restrict conn)
{
	if (conn == NULL) {
		return;
	}
	if (conn->queue != NULL) {
		pktqueue_free(conn->queue);
		conn->queue = NULL;
	}
}

static void listener_stop(struct ev_loop *loop, struct listener *restrict l)
{
	if (l->fd == -1) {
		return;
	}
	LOGD_F("listener close: %d", l->fd);
	struct ev_io *restrict w_accept = &l->w_accept;
	ev_io_stop(loop, w_accept);
	if (close(l->fd) != 0) {
		LOGW_PERROR("close");
	}
	l->fd = -1;
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
	util_free(s);
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
