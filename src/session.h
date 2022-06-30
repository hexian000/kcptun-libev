#ifndef SESSION_H
#define SESSION_H

#include "conf.h"
#include "hashtable.h"
#include "sockutil.h"
#include "util.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

struct ev_io;
struct ev_loop;

struct server;

typedef enum {
	STATE_CLOSED,
	STATE_CONNECT,
	STATE_CONNECTED,
	STATE_LINGER,
	STATE_TIME_WAIT,

	STATE_MAX,
} state_t;

struct link_stats {
	size_t tcp_in, tcp_out;
	size_t kcp_in, kcp_out;
	size_t udp_in, udp_out;
};

struct IKCPCB;

#define SESSION_BUF_SIZE 16384

struct session {
	bool is_accepted;
	state_t state;
	int tcp_fd;
	struct ev_io *w_read, *w_write;
	struct server *server;
	unsigned char *rbuf, *wbuf;
	size_t rbuf_len;
	size_t wbuf_len, wbuf_navail, wbuf_flush;
	sockaddr_max_t udp_remote;
	uint32_t conv;
	double last_send, last_recv;
	struct link_stats stats;
	struct IKCPCB *kcp;
	bool kcp_checked, kcp_closed;
	uint32_t kcp_next;
};

struct session *
session_new(struct server *s, int fd, struct sockaddr *addr, uint32_t conv);
struct session *session_new_dummy(struct server * /*s*/);
void session_free(struct session * /*s*/);

void session_start(struct session * /*session*/);
void session_shutdown(struct session * /*session*/);

void session_close_all(struct hashtable *t);

struct tlv_header {
	uint16_t msg;
	uint16_t len;
};

#define TLV_HEADER_SIZE (sizeof(struct tlv_header))

#endif /* SESSION_H */
