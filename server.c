#include "server.h"
#include "aead.h"
#include "event.h"

#include <ev.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <stdbool.h>

#define UDP_BUF_SIZE 65536

static inline bool listener_start(struct server *restrict s,
				  struct listener *restrict l,
				  const struct sockaddr_in *restrict addr)
{
	// Create server socket
	if ((l->fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		LOG_PERROR("socket error");
		return false;
	}
	if (s->conf->reuseport) {
		socket_set_reuseport(l->fd);
	}

	// Bind socket to address
	if (bind(l->fd, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) !=
	    0) {
		LOG_PERROR("bind error");
		if (close(l->fd) == -1) {
			LOG_PERROR("close fd");
		}
		return false;
	}

	// Start listing on the socket
	if (listen(l->fd, 2) < 0) {
		LOG_PERROR("listen error");
		if (close(l->fd) == -1) {
			LOG_PERROR("close fd");
		}
		return false;
	}
	socket_set_nonblock(l->fd);

	// Initialize and start a watcher to accepts client requests
	l->w_accept = util_malloc(sizeof(struct ev_io));
	UTIL_ASSERT(l->w_accept);
	ev_io_init(l->w_accept, accept_cb, l->fd, EV_READ);
	l->w_accept->data = s;
	ev_io_start(s->loop, l->w_accept);

	char addr_str[64];
	inet_ntop(AF_INET, &addr->sin_addr, addr_str, INET_ADDRSTRLEN);
	LOGF_I("listen at: %s:%u", addr_str, ntohs(addr->sin_port));
	return true;
}

static inline bool listener_start_all(struct server *server,
				      struct config *conf)
{
	size_t n = conf->n_listen;
	if (n < 1 || conf->addr_listen == NULL) {
		server->listeners = NULL;
		server->n_listener = 0;
		return true;
	}
	server->listeners = util_malloc(n * sizeof(struct listener));
	if (server->listeners == NULL) {
		LOG_E("out of memory");
		return false;
	}
	server->n_listener = n;
	for (size_t i = 0; i < n; i++) {
		server->listeners[i] = (struct listener){
			.w_accept = NULL,
			.fd = -1,
		};
	}
	for (size_t i = 0; i < n; i++) {
		if (!listener_start(server, &server->listeners[i],
				    conf->addr_listen[i])) {
			return false;
		}
	}
	return true;
}

static inline bool udp_start(struct server *restrict s,
			     struct config *restrict conf)
{
	struct udp_conn *restrict conn = &s->udp;
	conn->rbuf = slice_make(UDP_BUF_SIZE);
	if (conn->rbuf.data == NULL) {
		LOG_E("out of memory");
		return false;
	}
	conn->wbuf = slice_make(UDP_BUF_SIZE);
	if (conn->wbuf.data == NULL) {
		LOG_E("out of memory");
		return false;
	}

	// Setup a udp socket.
	if ((conn->fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		LOG_PERROR("udp socket");
		return false;
	}
	if (conf->addr_udp_bind) {
		if (conf->reuseport) {
			socket_set_reuseport(conn->fd);
		}
		const struct sockaddr_in *addr = conf->addr_udp_bind;
		if (bind(conn->fd, (struct sockaddr *)addr,
			 sizeof(struct sockaddr_in))) {
			LOG_PERROR("udp bind");
			return false;
		}
		char addr_str[64];
		inet_ntop(AF_INET, &addr->sin_addr, addr_str, INET_ADDRSTRLEN);
		LOGF_I("udp bind to: %s:%u", addr_str, ntohs(addr->sin_port));
	}
	if (conf->addr_udp_connect) {
		struct sockaddr_in *addr = conf->addr_udp_connect;
		if (connect(conn->fd, (struct sockaddr *)addr,
			    sizeof(struct sockaddr_in))) {
			LOG_PERROR("udp connect");
			return false;
		}
		char addr_str[64];
		inet_ntop(AF_INET, &addr->sin_addr, addr_str, INET_ADDRSTRLEN);
		LOGF_I("udp connect to: %s:%u", addr_str,
		       ntohs(addr->sin_port));
	}
	socket_set_nonblock(conn->fd);

	conn->w_read = util_malloc(sizeof(struct ev_io));
	if (conn->w_read == NULL) {
		LOG_E("out of memory");
		return false;
	}
	ev_io_init(conn->w_read, udp_read_cb, conn->fd, EV_READ);
	conn->w_read->data = s;
	ev_io_start(s->loop, conn->w_read);

	conn->w_write = util_malloc(sizeof(struct ev_io));
	if (conn->w_write == NULL) {
		LOG_E("out of memory");
		return false;
	}
	ev_io_init(conn->w_write, udp_write_cb, conn->fd, EV_WRITE);
	conn->w_write->data = s;
	//ev_io_start(s->loop, conn->w_write);

	conn->last_sent = ev_time();
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
	};
	s->crypto = aead_create(conf->password);
	s->conv = conv_table_create();
	if (s->conv == NULL) {
		server_shutdown(s);
		return NULL;
	}
	if (!listener_start_all(s, conf)) {
		server_shutdown(s);
		return NULL;
	}
	if (!udp_start(s, conf)) {
		server_shutdown(s);
		return NULL;
	}
	if (conf->linger > 1 && conf->linger < 86400) {
		s->linger = (ev_tstamp)conf->linger;
	} else {
		s->linger = 60.0;
	}
	if (conf->timeout > 1 && conf->timeout < 86400) {
		s->timeout = (ev_tstamp)conf->timeout;
	} else {
		s->timeout = 600.0;
	}
	if (conf->keepalive >= 0 && conf->keepalive < 86400) {
		s->keepalive = (ev_tstamp)conf->keepalive;
	} else {
		s->keepalive = 10.0;
	}

	s->w_kcp_update = util_malloc(sizeof(struct ev_timer));
	if (s->w_kcp_update == NULL) {
		LOG_E("out of memory");
		server_shutdown(s);
		return NULL;
	}
	ev_tstamp interval = s->conf->kcp_interval * 1e-3;
	ev_timer_init(s->w_kcp_update, kcp_update_cb, interval, interval);
	s->w_kcp_update->data = s;
	ev_timer_start(s->loop, s->w_kcp_update);

	if (s->keepalive > 0.0) {
		s->w_keepalive = util_malloc(sizeof(struct ev_timer));
		if (s->w_keepalive == NULL) {
			LOG_E("out of memory");
			server_shutdown(s);
			return NULL;
		}
		ev_timer_init(s->w_keepalive, keepalive_cb, s->keepalive,
			      s->keepalive);
		s->w_keepalive->data = s;
		ev_timer_start(s->loop, s->w_keepalive);
	} else {
		s->w_keepalive = NULL;
	}
	return s;
}

static inline void udp_free(struct ev_loop *loop,
			    struct udp_conn *restrict conn)
{
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
		if (close(conn->fd) == -1) {
			LOG_PERROR("close fd");
		}
		conn->fd = -1;
	}
	if (conn->rbuf.data != NULL) {
		conn->rbuf = slice_free(conn->rbuf);
	}
	if (conn->wbuf.data != NULL) {
		conn->wbuf = slice_free(conn->wbuf);
	}
}

static inline void listeners_free(struct ev_loop *loop,
				  struct listener *restrict listeners,
				  const size_t n)
{
	for (size_t i = 0; i < n; i++) {
		struct listener *restrict p = &(listeners[i]);
		if (p->w_accept != NULL) {
			ev_io_stop(loop, p->w_accept);
			util_free(p->w_accept);
			p->w_accept = NULL;
		}
		if (p->fd != -1) {
			if (close(p->fd) == -1) {
				LOG_PERROR("close fd");
			}
			p->fd = -1;
		}
	}
	util_free(listeners);
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
	if (s->listeners != NULL) {
		listeners_free(s->loop, s->listeners, s->n_listener);
		s->listeners = NULL;
		s->n_listener = 0;
	}
	if (s->conv != NULL) {
		session_close_all(s->conv);
		conv_table_free(s->conv);
		s->conv = NULL;
	}
	if (s->conf != NULL) {
		conf_free(s->conf);
		s->conf = NULL;
	}
	if (s->crypto != NULL) {
		aead_destroy(s->crypto);
		s->crypto = NULL;
	}
	util_free(s);
}
