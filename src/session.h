/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SESSION_H
#define SESSION_H

#include "conf.h"
#include "utils/buffer.h"
#include "utils/serialize.h"
#include "algo/hashtable.h"
#include "sockutil.h"
#include "util.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct server;
struct msgframe;

struct tlv_header {
	uint16_t msg;
	uint16_t len;
};

#define TLV_HEADER_SIZE (sizeof(struct tlv_header))
/* reserve space for one more kcp segment */
#define TLV_MAX_LENGTH (SESSION_BUF_SIZE - MAX_PACKET_SIZE)

static inline struct tlv_header tlv_header_read(const unsigned char *d)
{
	return (struct tlv_header){
		.msg = read_uint16(d),
		.len = read_uint16(d + sizeof(uint16_t)),
	};
}

static inline void tlv_header_write(unsigned char *d, struct tlv_header header)
{
	write_uint16(d, header.msg);
	write_uint16(d + sizeof(uint16_t), header.len);
}

/* session messages */
enum session_messages {
	SMSG_DIAL = 0x0000,
	SMSG_PUSH = 0x0001,
	SMSG_EOF = 0x0002,
	SMSG_KEEPALIVE = 0x0003,

	SMSG_MAX,
};

enum session_state {
	STATE_INIT,
	STATE_CONNECT,
	STATE_CONNECTED,
	STATE_LINGER,
	STATE_TIME_WAIT,

	STATE_MAX,
};

extern const char session_state_char[STATE_MAX];

struct link_stats {
	uintmax_t tcp_rx, tcp_tx;
	uintmax_t kcp_rx, kcp_tx;
	uintmax_t pkt_rx, pkt_tx;
};

struct IKCPCB;

#define SESSION_BUF_SIZE 16384

#define SESSION_KEY_SIZE (sizeof(uint32_t) + sizeof(sockaddr_max_t))

struct session_key {
	BUFFER_HDR;
	unsigned char data[SESSION_KEY_SIZE];
};

#define SESSION_MAKE_KEY(key, sa, conv)                                        \
	do {                                                                   \
		const size_t n = getsocklen(sa);                               \
		BUF_INIT(key, sizeof(uint32_t) + n);                           \
		write_uint32((key).data, conv);                                \
		memcpy((key).data + sizeof(uint32_t), (sa), n);                \
	} while (0)

struct session {
	struct session_key key;
	struct server *server;
	struct IKCPCB *kcp;
	int tcp_state, kcp_state;
	int tcp_fd;
	int kcp_flush;
	uint32_t conv;
	sockaddr_max_t raddr;
	struct {
		struct ev_io w_read, w_write;
		struct ev_idle w_flush;
	};
	struct {
		ev_tstamp created;
		ev_tstamp last_reset;
		ev_tstamp last_send, last_recv;
	};
	struct {
		bool is_accepted : 1;
	};
	struct vbuffer *rbuf, *wbuf;
	size_t wbuf_flush, wbuf_next;

	struct link_stats stats;
};

struct session *
session_new(struct server *s, const struct sockaddr *addr, uint32_t conv);
void session_free(struct session *ss);

void session_start(struct session *ss, int fd);
void session_tcp_stop(struct session *ss);
void session_kcp_stop(struct session *ss);

bool session_kcp_send(struct session *ss);
void session_kcp_close(struct session *ss);

void session_read_cb(struct session *ss);
void session_notify(struct session *ss);

/* session 0 messages */
enum session0_messages {
	S0MSG_PING = 0x0000,
	S0MSG_PONG = 0x0001,
	S0MSG_RESET = 0x0002,
};

bool ss0_send(
	struct server *s, const struct sockaddr *sa, uint16_t what,
	const unsigned char *b, size_t n);
void ss0_reset(struct server *s, const struct sockaddr *sa, uint32_t conv);

void session0(struct server *restrict s, struct msgframe *restrict msg);

#endif /* SESSION_H */
