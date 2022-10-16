#include "server.h"
#include "conf.h"
#include "event.h"

#include "hashtable.h"
#include "packet.h"
#include "slog.h"
#include "util.h"
#include "sockutil.h"

#include <ev.h>

#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdbool.h>
#include <math.h>

#define UDP_BUF_SIZE 65536

static bool
listener_start(struct server *restrict s, const struct sockaddr *addr)
{
	struct config *restrict cfg = s->conf;
	struct listener *restrict l = &(s->listener);
	// Create server socket
	const int fd = socket(addr->sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		LOGE_PERROR("socket error");
		return false;
	}
	if (socket_setup(fd)) {
		LOGE_PERROR("fcntl");
		close(fd);
		return false;
	}
	socket_set_reuseport(fd, cfg->tcp_reuseport);
	socket_set_tcp(fd, cfg->tcp_nodelay, cfg->tcp_keepalive);
	socket_set_buffer(fd, cfg->tcp_sndbuf, cfg->tcp_rcvbuf);

	// Bind socket to address
	if (bind(fd, addr, getsocklen(addr)) != 0) {
		LOGE_PERROR("bind error");
		close(fd);
		return false;
	}

	// Start listing on the socket
	if (listen(fd, 2) < 0) {
		LOGE_PERROR("listen error");
		close(fd);
		return false;
	}

	// Initialize and start a watcher to accepts client requests
	struct ev_io *restrict w_accept = &l->w_accept;
	ev_io_init(w_accept, accept_cb, fd, EV_READ);
	w_accept->data = s;
	ev_io_start(s->loop, w_accept);

	if (LOGLEVEL(LOG_LEVEL_INFO)) {
		char addr_str[64];
		format_sa(addr, addr_str, sizeof(addr_str));
		LOGI_F("listen at: %s", addr_str);
	}
	l->fd = fd;
	LOGD_F("listener fd: %d", l->fd);
	return true;
}

static bool udp_start(struct server *restrict s, struct config *restrict conf)
{
	struct udp_conn *restrict udp = &s->udp;
	udp->inflight_ping = NAN;
	udp->packets = packet_create(conf);
	if (udp->packets == NULL) {
		LOGE("out of memory");
		return false;
	}

	// Setup a udp socket.
	if ((udp->fd = socket(conf->udp_af, SOCK_DGRAM, 0)) < 0) {
		LOGE_PERROR("udp socket");
		return false;
	}
	if (socket_setup(udp->fd)) {
		LOGE_PERROR("fcntl");
		return NULL;
	}
	socket_set_buffer(udp->fd, conf->udp_sndbuf, conf->udp_rcvbuf);
	if (conf->udp_bind.sa) {
		const struct sockaddr *addr = conf->udp_bind.sa;
		if (bind(udp->fd, addr, getsocklen(addr))) {
			LOGE_PERROR("udp bind");
			return false;
		}
		char addr_str[64];
		format_sa(addr, addr_str, sizeof(addr_str));
		LOGI_F("udp bind: %s", addr_str);
	}
	if (conf->udp_connect.sa) {
		const struct sockaddr *addr = conf->udp_connect.sa;
		if (connect(udp->fd, addr, getsocklen(addr))) {
			LOGE_PERROR("udp connect");
			return false;
		}
		char addr_str[64];
		format_sa(addr, addr_str, sizeof(addr_str));
		LOGI_F("udp connect: %s", addr_str);
	}

	struct ev_io *restrict w_read = &udp->w_read;
	ev_io_init(w_read, udp_read_cb, udp->fd, EV_READ);
	w_read->data = s;
	ev_io_start(s->loop, w_read);

	struct ev_io *restrict w_write = &udp->w_write;
	ev_io_init(w_write, udp_write_cb, udp->fd, EV_WRITE);
	w_write->data = s;
	ev_io_start(s->loop, w_write);

	const ev_tstamp now = ev_time();
	udp->last_send_time = now;
	udp->last_recv_time = now;
	return true;
}

struct server *server_start(struct ev_loop *loop, struct config *restrict conf)
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
		.udp = (struct udp_conn){ .fd = -1 },
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
		server_shutdown(s);
		return NULL;
	}
	if (conf->listen.sa) {
		if (!listener_start(s, conf->listen.sa)) {
			server_shutdown(s);
			return NULL;
		}
	}
	if (!udp_start(s, conf)) {
		server_shutdown(s);
		return NULL;
	}

	ev_timer_start(loop, w_kcp_update);
	ev_timer_start(loop, w_timer);
	return s;
}

static void udp_free(struct ev_loop *loop, struct udp_conn *restrict conn)
{
	if (conn->fd != -1) {
		struct ev_io *restrict w_read = &conn->w_read;
		ev_io_stop(loop, w_read);
		struct ev_io *restrict w_write = &conn->w_write;
		ev_io_stop(loop, w_write);
		close(conn->fd);
		conn->fd = -1;
	}
	if (conn->packets != NULL) {
		packet_free(conn->packets);
		conn->packets = NULL;
	}
}

static void listener_free(struct ev_loop *loop, struct listener *restrict l)
{
	if (l->fd != -1) {
		LOGD_F("listener close: %d", l->fd);
		struct ev_io *restrict w_accept = &l->w_accept;
		ev_io_stop(loop, w_accept);
		close(l->fd);
		l->fd = -1;
	}
}

void server_shutdown(struct server *restrict s)
{
	struct ev_timer *restrict w_kcp_update = &s->w_kcp_update;
	ev_timer_stop(s->loop, w_kcp_update);
	struct ev_timer *restrict w_timer = &s->w_timer;
	ev_timer_stop(s->loop, w_timer);
	udp_free(s->loop, &(s->udp));
	listener_free(s->loop, &(s->listener));
	if (s->sessions != NULL) {
		session_close_all(s->sessions);
		table_free(s->sessions);
		s->sessions = NULL;
	}
	util_free(s);
}

uint32_t conv_new(struct server *restrict s)
{
	do {
		s->m_conv++;
	} while (s->m_conv == 0);
	return s->m_conv;
}
