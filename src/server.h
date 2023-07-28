/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SERVER_H
#define SERVER_H

#include "conf.h"
#include "algo/hashtable.h"
#include "utils/buffer.h"
#include "session.h"
#include "util.h"

#include "kcp/ikcp.h"

#include <ev.h>

#include <stdint.h>
#include <time.h>

struct listener {
	struct ev_io w_accept;
	int fd;

	struct ev_io w_accept_http;
	int fd_http;

	struct ev_timer w_timer;
};

struct pktconn {
	struct ev_io w_read, w_write;
	struct ev_idle w_update;
	int fd;
	ev_tstamp last_send_time;
	ev_tstamp last_recv_time;
	struct pktqueue *queue;
	ev_tstamp inflight_ping;
};

#define MAX_SESSIONS 65535

struct server {
	struct config *conf;
	struct ev_loop *loop;
	struct listener listener;
	struct pktconn pkt;
	struct hashtable *sessions;
	struct ev_timer w_kcp_update;
	struct ev_timer w_keepalive;
	struct ev_timer w_resolve;
	struct ev_timer w_timeout;
	double interval;
	double dial_timeout;
	double session_timeout, session_keepalive;
	double linger, time_wait;
	double keepalive, timeout;
	double ping_timeout;
	struct link_stats stats, last_stats;
	uint32_t m_conv;
	ev_tstamp started;
	ev_tstamp last_stats_time;
	ev_tstamp last_resolve_time;
	clock_t clock, last_clock;
};

struct server *server_new(struct ev_loop *loop, struct config *conf);
bool server_start(struct server *s);
void server_ping(struct server *s);
struct vbuffer *
server_stats_const(const struct server *s, struct vbuffer *buf, int level);
struct vbuffer *server_stats(struct server *s, struct vbuffer *buf, int level);
bool server_resolve(struct server *s);
void server_stop(struct server *s);
void server_free(struct server *s);

uint32_t conv_new(struct server *s, const struct sockaddr *sa);

#endif /* SERVER_H */
