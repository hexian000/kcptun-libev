#include "server.h"
#include "aead.h"
#include "conf.h"
#include "event.h"

#include "hashtable.h"
#include "packet.h"
#include "util.h"
#include "sockutil.h"
#include <ev.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdbool.h>

#define UDP_BUF_SIZE 65536

static bool
listener_start(struct server *restrict s, const struct sockaddr *addr)
{
	struct listener *restrict l = &(s->listener);
	// Create server socket
	if ((l->fd = socket(addr->sa_family, SOCK_STREAM, 0)) < 0) {
		LOGE_PERROR("socket error");
		return false;
	}
	if (socket_setup(l->fd)) {
		LOGE_PERROR("fcntl");
		return false;
	}
	{
		struct config *restrict cfg = s->conf;
		socket_set_reuseport(l->fd, cfg->tcp_reuseport);
		socket_set_tcp(l->fd, cfg->tcp_nodelay, cfg->tcp_keepalive);
		socket_set_buffer(l->fd, cfg->tcp_sndbuf, cfg->tcp_rcvbuf);
	}

	// Bind socket to address
	if (bind(l->fd, addr, getsocklen(addr)) != 0) {
		LOGE_PERROR("bind error");
		close(l->fd);
		l->fd = -1;
		return false;
	}

	// Start listing on the socket
	if (listen(l->fd, 2) < 0) {
		LOGE_PERROR("listen error");
		close(l->fd);
		l->fd = -1;
		return false;
	}

	// Initialize and start a watcher to accepts client requests
	l->w_accept = util_malloc(sizeof(struct ev_io));
	UTIL_ASSERT(l->w_accept);
	ev_io_init(l->w_accept, accept_cb, l->fd, EV_READ);
	l->w_accept->data = s;
	ev_io_start(s->loop, l->w_accept);

	{
		char addr_str[64];
		format_sa(addr, addr_str, sizeof(addr_str));
		LOGI_F("listen at: %s", addr_str);
	}
	return true;
}

static bool udp_start(struct server *restrict s, struct config *restrict conf)
{
	struct udp_conn *restrict udp = &s->udp;
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
	socket_set_reuseport(udp->fd, conf->udp_reuseport);
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

	udp->w_read = util_malloc(sizeof(struct ev_io));
	if (udp->w_read == NULL) {
		LOGE("out of memory");
		return false;
	}
	ev_io_init(udp->w_read, udp_read_cb, udp->fd, EV_READ);
	udp->w_read->data = s;
	ev_io_start(s->loop, udp->w_read);

	udp->w_write = util_malloc(sizeof(struct ev_io));
	if (udp->w_write == NULL) {
		LOGE("out of memory");
		return false;
	}
	ev_io_init(udp->w_write, udp_write_cb, udp->fd, EV_WRITE);
	udp->w_write->data = s;
	ev_io_start(s->loop, udp->w_write);

	const ev_tstamp now = ev_time();
	udp->last_send_time = now;
	udp->last_recv_time = now;
	return true;
}

struct server *server_start(struct ev_loop *loop, struct config *conf)
{
	struct server *s = util_malloc(sizeof(struct server));
	if (s == NULL) {
		return NULL;
	}
	*s = (struct server){
		.loop = loop,
		.conf = conf,
		.m_conv = rand32(),
		.listener =
			(struct listener){
				.w_accept = NULL,
				.fd = -1,
			},
		.last_resolve_time = ev_now(loop),
	};
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
	if (conf->kcp_interval >= 10 && conf->kcp_interval <= 1000) {
		s->interval = conf->kcp_interval * 1e-3;
	} else {
		s->interval = 50e-3;
	}
	if (conf->linger >= 5 && conf->linger <= 600) {
		s->linger = (double)conf->linger;
	} else {
		s->linger = 60.0;
	}
	s->dial_timeout = 30.0;
	if (conf->timeout >= 60 && conf->timeout <= 86400) {
		s->session_timeout = (double)conf->timeout;
	} else {
		s->session_timeout = 7200.0;
	}
	s->session_keepalive = s->session_timeout / 2.0;
	if (conf->keepalive >= 1 && conf->keepalive <= 7200) {
		s->keepalive = (double)conf->keepalive;
	} else {
		s->keepalive = -1.0;
	}
	if (conf->time_wait >= 5 && (double)conf->time_wait > s->linger) {
		s->time_wait = (double)conf->time_wait;
	} else {
		s->time_wait = s->linger * 3.0;
	}

	s->w_kcp_update = util_malloc(sizeof(struct ev_timer));
	if (s->w_kcp_update == NULL) {
		LOGE("out of memory");
		server_shutdown(s);
		return NULL;
	}
	ev_timer_init(s->w_kcp_update, kcp_update_cb, s->interval, s->interval);
	s->w_kcp_update->data = s;
	ev_timer_start(s->loop, s->w_kcp_update);

	s->w_timer = util_malloc(sizeof(struct ev_timer));
	if (s->w_timer == NULL) {
		LOGE("out of memory");
		server_shutdown(s);
		return NULL;
	}
	ev_timer_init(s->w_timer, timer_cb, 1.0, 1.0);
	s->w_timer->data = s;
	ev_timer_start(s->loop, s->w_timer);
	return s;
}

static void udp_free(struct ev_loop *loop, struct udp_conn *restrict conn)
{
	if (conn->packets != NULL) {
		packet_free(conn->packets);
		conn->packets = NULL;
	}
	if (conn->w_read != NULL) {
		ev_io_stop(loop, conn->w_read);
		util_free(conn->w_read);
		conn->w_read = NULL;
	}
	if (conn->w_write != NULL) {
		ev_io_stop(loop, conn->w_write);
		util_free(conn->w_write);
		conn->w_write = NULL;
	}
	if (conn->fd != -1) {
		close(conn->fd);
		conn->fd = -1;
	}
}

static void listener_free(struct ev_loop *loop, struct listener *restrict l)
{
	if (l->w_accept != NULL) {
		ev_io_stop(loop, l->w_accept);
		util_free(l->w_accept);
		l->w_accept = NULL;
	}
	if (l->fd != -1) {
		close(l->fd);
		l->fd = -1;
	}
}

void server_shutdown(struct server *restrict s)
{
	if (s->w_kcp_update != NULL) {
		ev_timer_stop(s->loop, s->w_kcp_update);
		util_free(s->w_kcp_update);
		s->w_kcp_update = NULL;
	}
	if (s->w_timer != NULL) {
		ev_timer_stop(s->loop, s->w_timer);
		util_free(s->w_timer);
		s->w_timer = NULL;
	}
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
