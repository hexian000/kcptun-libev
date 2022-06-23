#ifndef PACKET_H
#define PACKET_H

#include "aead.h"
#include "conf.h"
#include "leakypool.h"
#include "slog.h"
#include "sockutil.h"

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

#define MAX_PACKET_SIZE 1500

struct msgframe {
	struct msghdr hdr;
	sockaddr_max_t addr;
	struct iovec iov;
	size_t len;
	unsigned char buf[MAX_PACKET_SIZE];
};

#define MQ_SEND_SIZE 2048
#define MQ_RECV_SIZE 256

struct packet {
	bool is_server;
	struct leakypool msgpool;
	struct msgframe *mq_send[MQ_SEND_SIZE];
	size_t mq_send_len;
	struct msgframe *mq_recv[MQ_RECV_SIZE];
	size_t mq_recv_len;
#if WITH_CRYPTO
	unsigned char *nonce_send;
	unsigned char *nonce_recv;
	struct aead *crypto;
#endif
};

struct packet *packet_create(struct config *cfg);
void packet_free(struct packet *p);

struct msgframe *msgframe_new(struct packet *p, struct sockaddr *sa);
void msgframe_delete(struct packet *p, struct msgframe *msg);

struct server;

/* session 0 messages */
#define S0MSG_KEEPALIVE UINT16_C(0x0000)
#define S0MSG_DIAL UINT16_C(0x0001)
#define S0MSG_CONV UINT16_C(0x0002)

struct session0_header {
	uint32_t zero;
	uint16_t what;
};

#define SESSION0_HEADER_SIZE (sizeof(uint32_t) + sizeof(uint16_t))

bool send_ss0(
	struct server *s, struct sockaddr *sa, uint16_t what,
	const unsigned char *b, size_t n);

/* process mq_recv */
void packet_recv(struct packet *p, struct server *s);

/* send a plain packet */
bool packet_send(struct packet *p, struct server *s, struct msgframe *msg);

#endif /* PACKET_H */
