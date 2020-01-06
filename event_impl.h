
#ifndef EVENT_IMPL_H
#define EVENT_IMPL_H

#include "aead.h"
#include "conv.h"
#include "event.h"
#include "server.h"
#include "session.h"
#include "slice.h"
#include "util.h"

#include "kcp/ikcp.h"
#include <ev.h>

#include <assert.h>
#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <unistd.h>

#define TCP_PER_PACKET_LOG 0
#define KCP_PER_PACKET_LOG 0
#define UDP_PER_PACKET_LOG 0

#define CHECK_EV_ERROR(revents)                                                \
	do {                                                                   \
		if ((unsigned)(revents) & (unsigned)EV_ERROR) {                \
			LOG_PERROR("got error event");                         \
			return;                                                \
		}                                                              \
	} while (0)

void session0(struct server * /*server*/, struct endpoint /*addr*/,
	      const char * /*data*/, size_t n);

static inline bool is_server(struct server *restrict s)
{
	return s->n_listener == 0;
}

char *get_udp_send_buf(struct server * /*s*/, size_t * /*n*/);
size_t udp_send(struct server * /*s*/, struct endpoint /*addr*/,
		const char * /*buf*/, size_t /*n*/);
char *udp_recv(struct server * /*s*/, struct endpoint * /*addr*/,
	       size_t * /*size*/);

void kcp_recv(struct session * /*session*/, ev_tstamp /*now*/);

void kcp_close(struct session * /*session*/, ev_tstamp /*now*/);

static inline uint32_t tstamp2ms(const ev_tstamp t)
{
	return (uint32_t)fmod(t * 1e+3, UINT32_MAX + 1.0);
}

static inline void kcp_flush(struct session *restrict s, ev_tstamp now)
{
	ikcp_flush(s->kcp);
	const uint32_t now_ms = tstamp2ms(now);
	s->kcp_next = ikcp_check(s->kcp, now_ms);
	s->kcp_checked = true;
	if (!queue_empty(s->server->udp.udp_output)) {
		ev_io_start(s->server->loop, s->server->udp.w_write);
	}
}

static inline void kcp_forceupdate(struct session *restrict s)
{
	s->kcp_checked = false;
}

static inline struct tlv_header tlv_header_read(const char *d)
{
	return (struct tlv_header){
		.msg = read_uint16((const uint8_t *)d),
		.len = read_uint16((const uint8_t *)d + sizeof(uint16_t)),
	};
}

static inline void tlv_header_write(char *d, struct tlv_header header)
{
	write_uint16((uint8_t *)d, header.msg);
	write_uint16((uint8_t *)d + sizeof(uint16_t), header.len);
}

static inline int timecomp(const uint32_t t0, const uint32_t t1)
{
	if (t0 == t1) {
		return 0;
	}
	return ((t0 - t1) > (UINT32_MAX >> 1u)) ? -1 : 1;
}

/* session messages */
#define SMSG_DATA UINT16_C(0x0000)
#define SMSG_CLOSE UINT16_C(0x0001)
#define SMSG_ECHO UINT16_C(0x0002)

/* session 0 messages */
#define S0MSG_KEEPALIVE UINT16_C(0x0000)
#define S0MSG_DIAL UINT16_C(0x0001)
#define S0MSG_CONV UINT16_C(0x0002)

#endif /* EVENT_IMPL_H */
