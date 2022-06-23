#include "server.h"
#include "aead.h"
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
		LOG_PERROR("socket error");
		return false;
	}
	socket_set_nonblock(l->fd);
	socket_set_buffer(l->fd, 16384, 16384);
	if (s->conf->reuseport) {
		socket_set_reuseport(l->fd);
	}

	// Bind socket to address
	if (bind(l->fd, addr, getsocklen(addr)) != 0) {
		LOG_PERROR("bind error");
		close(l->fd);
		l->fd = -1;
		return false;
	}

	// Start listing on the socket
	if (listen(l->fd, 2) < 0) {
		LOG_PERROR("listen error");
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
		LOG_PERROR("udp socket");
		return false;
	}
	socket_set_nonblock(udp->fd);
	socket_set_buffer(udp->fd, 65536, 65536);
	if (conf->reuseport) {
		socket_set_reuseport(udp->fd);
	}
	if (conf->addr_udp_bind) {
		const struct sockaddr *addr = conf->addr_udp_bind;
		if (bind(udp->fd, addr, getsocklen(addr))) {
			LOG_PERROR("udp bind");
			return false;
		}
		char addr_str[64];
		format_sa(addr, addr_str, sizeof(addr_str));
		LOGI_F("udp bind: %s", addr_str);
	}
	if (conf->addr_udp_connect) {
		const struct sockaddr *addr = conf->addr_udp_connect;
		if (connect(udp->fd, addr, getsocklen(addr))) {
			LOG_PERROR("udp connect");
			return false;
		}
		char addr_str[64];
		format_sa(addr, addr_str, sizeof(addr_str));
		LOGI_F("udp connect: %s", addr_str);
	}
	// {
	// 	size_t bufsize = 4194304;
	// 	setsockopt(
	// 		udp->fd, SOL_SOCKET, SO_SNDBUF, &bufsize,
	// 		sizeof(bufsize));
	// 	setsockopt(
	// 		udp->fd, SOL_SOCKET, SO_RCVBUF, &bufsize,
	// 		sizeof(bufsize));
	// }

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

	udp->last_send_time = ev_time();
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
	};
	s->sessions = table_create();
	if (s->sessions == NULL) {
		server_shutdown(s);
		return NULL;
	}
	if (conf->addr_listen) {
		if (!listener_start(s, conf->addr_listen)) {
			server_shutdown(s);
			return NULL;
		}
	}
	if (!udp_start(s, conf)) {
		server_shutdown(s);
		return NULL;
	}
	if (conf->linger > 5 && conf->linger < 3600) {
		s->linger = (double)conf->linger;
	} else {
		s->linger = 60.0;
	}
	if (conf->timeout > 5 && conf->timeout < 3600) {
		s->timeout = (double)conf->timeout;
	} else {
		s->timeout = 600.0;
	}
	if (conf->keepalive >= 0 && conf->keepalive < 3600) {
		s->keepalive = (double)conf->keepalive;
	} else {
		s->keepalive = 25.0;
	}
	if (conf->time_wait > 5 && (double)conf->time_wait > s->timeout) {
		s->time_wait = (double)conf->time_wait;
	} else {
		s->time_wait = s->timeout * 3.0;
	}

	s->w_kcp_update = util_malloc(sizeof(struct ev_timer));
	if (s->w_kcp_update == NULL) {
		LOGE("out of memory");
		server_shutdown(s);
		return NULL;
	}
	/* always 10ms */
	ev_timer_init(s->w_kcp_update, kcp_update_cb, 10e-3, 10e-3);
	s->w_kcp_update->data = s;
	ev_timer_start(s->loop, s->w_kcp_update);

	if (s->keepalive > 0.0) {
		s->w_keepalive = util_malloc(sizeof(struct ev_timer));
		if (s->w_keepalive == NULL) {
			LOGE("out of memory");
			server_shutdown(s);
			return NULL;
		}
		ev_timer_init(s->w_keepalive, keepalive_cb, 1.0, 1.0);
		s->w_keepalive->data = s;
		ev_timer_start(s->loop, s->w_keepalive);
	} else {
		s->w_keepalive = NULL;
	}
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
	if (s->w_keepalive != NULL) {
		ev_timer_stop(s->loop, s->w_keepalive);
		util_free(s->w_keepalive);
		s->w_keepalive = NULL;
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
