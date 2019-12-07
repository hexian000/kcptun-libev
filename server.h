#ifndef SERVER_H
#define SERVER_H

#include "conf.h"
#include "conv.h"
#include "session.h"
#include "util.h"
#include "queue.h"

struct aead;
struct ev_timer;

struct listener {
	struct ev_io *w_accept;
	int fd;
};

struct udp_conn {
	struct ev_io *w_read, *w_write;
	slice_t rbuf, wbuf;
	int fd;
	double last_sent;
	struct queue *udp_output;
};

struct server {
	struct config *conf;
	struct ev_loop *loop;
	size_t n_listener;
	struct listener *listeners;
	struct udp_conn udp;
	struct conv_table *conv;
	struct ev_timer *w_kcp_update;
	struct ev_timer *w_keepalive;
	struct aead *crypto;
	double timeout, linger, keepalive;
	struct link_stats stats;
};

struct server *server_start(struct ev_loop * /*loop*/,
			    struct config * /*conf*/);
void server_shutdown(struct server * /*s*/);

#endif /* SERVER_H */
