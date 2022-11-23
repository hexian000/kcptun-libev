#ifndef SERVER_H
#define SERVER_H

#include "conf.h"
#include "hashtable.h"
#include "session.h"
#include "util.h"
#include "strbuilder.h"

#include "kcp/ikcp.h"

#include <ev.h>

#include <stdint.h>

struct aead;

struct listener {
	struct ev_io w_accept;
	int fd;

	struct ev_io w_accept_http;
	int fd_http;
};

struct pktconn {
	struct ev_io w_read, w_write;
	int fd;
	ev_tstamp last_send_time;
	ev_tstamp last_recv_time;
	struct pktqueue *queue;
	ev_tstamp inflight_ping;
};

#define MAX_SESSIONS 65536

struct server {
	struct config *conf;
	struct ev_loop *loop;
	struct listener listener;
	struct pktconn pkt;
	struct hashtable *sessions;
	struct ev_timer w_kcp_update;
	struct ev_timer w_timer;
	double interval;
	double dial_timeout;
	double session_timeout, session_keepalive;
	double linger, time_wait;
	double keepalive;
	struct link_stats stats, last_stats;
	ev_tstamp last_stats_time;
	uint32_t m_conv;
	double last_resolve_time;
};

struct server *server_new(struct ev_loop *loop, struct config *conf);
bool server_start(struct server *s);
void server_sample(struct server *s);
void server_stats(struct server *s, struct strbuilder *sb);
bool server_resolve(struct server *s);
void server_stop(struct server *s);
void server_free(struct server *s);

uint32_t conv_new(struct server *s, const struct sockaddr *sa);

#endif /* SERVER_H */
