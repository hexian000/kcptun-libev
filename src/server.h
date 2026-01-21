/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SERVER_H
#define SERVER_H

#include "sockutil.h"

#include "algo/hashtable.h"
#include "utils/buffer.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct listener {
	ev_io w_accept;
	ev_io w_accept_http;
	ev_timer w_timer;
	int fd;
	int fd_http;
};

/* plain data object */
struct service {
	ev_tstamp last_seen;
	union sockaddr_max server_addr[2];
	size_t idlen;
	char id[];
};

struct pktconn {
	ev_io w_read, w_write;
	struct pktqueue *queue;
	int fd;
	int domain;
	union sockaddr_max kcp_connect;
	ev_tstamp last_send_time;
	ev_tstamp last_recv_time;
	ev_tstamp inflight_ping;

	bool connected : 1;
	/* map: service_id -> struct service */
	struct hashtable *services;
	union sockaddr_max rendezvous_server;
	union sockaddr_max rendezvous_local;
};

#define MAX_SESSIONS 65535

struct config;

struct link_stats {
	uintmax_t tcp_rx, tcp_tx;
	uintmax_t kcp_rx, kcp_tx;
	uintmax_t pkt_rx, pkt_tx;
};

struct server {
	const struct config *conf;
	struct ev_loop *loop;
	struct listener listener;
	struct pktconn pkt;
	uint32_t m_conv;
	struct hashtable *sessions;
	struct {
		union sockaddr_max connect;

		double dial_timeout;
		double session_timeout, session_keepalive;
		double linger, time_wait;
		double keepalive, timeout;
		double ping_timeout;
	};
	struct {
		ev_timer w_kcp_update;
		ev_timer w_keepalive;
		ev_timer w_resolve;
		ev_timer w_timeout;
	};
	struct {
		struct link_stats stats, last_stats;
		ev_tstamp started;
		ev_tstamp last_stats_time;
		ev_tstamp last_resolve_time;
	};
};

struct server *server_new(struct ev_loop *loop, const struct config *conf);
void server_loadconf(struct server *s, const struct config *conf);
bool server_start(struct server *s);
void server_ping(struct server *s);
struct vbuffer *
server_stats_const(const struct server *s, struct vbuffer *buf, int level);
struct vbuffer *server_stats(struct server *s, struct vbuffer *buf, int level);
bool server_resolve(struct server *s);
void udp_rendezvous(struct server *s, uint16_t what);
void server_stop(struct server *s);
void server_free(struct server *s);

struct sockaddr;

uint32_t conv_new(struct server *s, const struct sockaddr *sa);
size_t udp_overhead(const struct pktconn *udp);

#endif /* SERVER_H */
