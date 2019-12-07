#ifndef SESSION_H
#define SESSION_H

#include "conf.h"
#include "conv.h"
#include "slice.h"
#include "util.h"

#include "kcp/ikcp.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

struct session {
	state_t state;
	int tcp_fd;
	ikcpcb *kcp;
	bool kcp_blocked, kcp_checked;
	uint32_t kcp_next;
	struct ev_io *w_read, *w_write;
	struct server *server;
	slice_t rbuf, wbuf;
	size_t wbuf_flush;
	struct endpoint udp_remote;
	double last_seen;
	struct link_stats stats;
};

struct session *session_new(struct server * /*s*/, int /*fd*/,
			    uint32_t /*conv*/, struct endpoint /*udp_remote*/);
struct session *session_new_dummy();
void session_free(struct session * /*s*/);

void session_start(struct session * /*session*/);
void session_shutdown(struct session * /*session*/);

void session_close_all(struct conv_table * /*table*/);

struct tlv_header {
	uint16_t msg;
	uint16_t len;
};

#define TLV_HEADER_SIZE (sizeof(uint16_t) * 2)

#endif /* SESSION_H */
