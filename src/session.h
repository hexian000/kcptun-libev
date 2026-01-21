/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SESSION_H
#define SESSION_H

#include "server.h"
#include "sockutil.h"

#include "utils/buffer.h"
#include "utils/serialize.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct sockaddr;
struct server;
struct msgframe;

/* type-length-value pattern */
struct tlv_header {
	uint16_t msg;
	uint16_t len;
};

#define TLV_HEADER_SIZE (sizeof(uint16_t) + sizeof(uint16_t))
/* reserve space for one more kcp segment */
#define TLV_MAX_LENGTH (SESSION_BUF_SIZE - MAX_PACKET_SIZE)

static inline struct tlv_header tlv_header_read(const unsigned char *d)
{
	return (struct tlv_header){
		.msg = read_uint16(d),
		.len = read_uint16(d + sizeof(uint16_t)),
	};
}

static inline void
tlv_header_write(unsigned char *d, const struct tlv_header header)
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

struct IKCPCB;

#define SESSION_BUF_SIZE 16384
#define SESSION_KEY_SIZE (sizeof(uint32_t) + sizeof(union sockaddr_max))

struct session {
	unsigned char key[SESSION_KEY_SIZE];
	struct server *server;
	struct IKCPCB *kcp;
	int tcp_state, kcp_state;
	int kcp_flush;
	uint32_t conv;
	union sockaddr_max raddr;
	struct {
		ev_io w_socket;
		ev_idle w_flush;
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

#define SESSION_GETKEY(ss)                                                     \
	((struct hashkey){                                                     \
		.len = SESSION_KEY_SIZE,                                       \
		.data = (ss)->key,                                             \
	})

#define SESSION_MAKEKEY(key, sa, conv)                                         \
	do {                                                                   \
		unsigned char *restrict p = (key);                             \
		size_t size = SESSION_KEY_SIZE;                                \
		const size_t n = getsocklen(sa);                               \
		write_uint32(p, conv);                                         \
		p += sizeof(uint32_t), size -= sizeof(uint32_t);               \
		memcpy(p, (sa), n);                                            \
		p += n, size -= n;                                             \
		memset(p, 0, size);                                            \
	} while (0)

struct session *
session_new(struct server *s, const union sockaddr_max *addr, uint32_t conv);
void session_free(struct session *ss);

void session_tcp_start(struct session *ss, int fd);
void session_tcp_stop(struct session *ss);
void session_kcp_stop(struct session *ss);

bool session_kcp_send(struct session *ss);
void session_kcp_flush(struct session *ss);
void session_kcp_close(struct session *ss);

void session_read_cb(struct session *ss);

/* session 0 messages */
enum session0_messages {
	S0MSG_PING = 0x0000,
	S0MSG_PONG = 0x0001,
	S0MSG_RESET = 0x0002,
	/* for rendezvous mode */
	S0MSG_LISTEN = 0x0003,
	S0MSG_CONNECT = 0x0004,
	S0MSG_PUNCH = 0x0005,
};

enum inetaddr_type {
	ATYP_INET,
	ATYP_INET6,
};
#define INETADDR_LENGTH                                                        \
	(sizeof(uint8_t) + sizeof(struct in_addr) + sizeof(in_port_t))
#define INET6ADDR_LENGTH                                                       \
	(sizeof(uint8_t) + sizeof(struct in6_addr) + sizeof(in_port_t))
size_t inetaddr_read(union sockaddr_max *addr, const void *b, size_t n);
size_t inetaddr_write(void *b, size_t n, const struct sockaddr *sa);

bool ss0_send(
	struct server *s, const struct sockaddr *sa, uint16_t what,
	const unsigned char *b, size_t n);
void ss0_reset(struct server *s, const struct sockaddr *sa, uint32_t conv);

void session0(struct server *restrict s, struct msgframe *restrict msg);

#endif /* SESSION_H */
