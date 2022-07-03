#ifndef SERVER_H
#define SERVER_H

#include "conf.h"
#include "hashtable.h"
#include "session.h"
#include "util.h"
#include "kcp/ikcp.h"
#include <stdint.h>

struct aead;
struct ev_timer;

struct listener {
	struct ev_io *w_accept;
	int fd;
};

struct udp_conn {
	struct ev_io *w_read, *w_write;
	int fd;
	double last_send_time;
	double last_recv_time;
	struct packet *packets;
};

struct server {
	struct config *conf;
	struct ev_loop *loop;
	struct listener listener;
	struct udp_conn udp;
	struct hashtable *sessions;
	struct ev_timer *w_kcp_update;
	struct ev_timer *w_timer;
	double interval;
	double dial_timeout;
	double session_timeout, session_keepalive;
	double linger, time_wait;
	double keepalive;
	struct link_stats stats;
	uint32_t m_conv;
	double last_resolve_time;
};

struct server *
server_start(struct ev_loop * /*loop*/, struct config * /*conf*/);
void server_shutdown(struct server * /*s*/);

uint32_t conv_new(struct server *s);

#endif /* SERVER_H */
