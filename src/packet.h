#ifndef PACKET_H
#define PACKET_H

#include "aead.h"
#include "nonce.h"
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

#define MQ_SEND_SIZE 256
#define MQ_RECV_SIZE 256

struct packet {
	struct leakypool msgpool;
	struct msgframe *mq_send[MQ_SEND_SIZE];
	size_t mq_send_len;
	struct msgframe *mq_recv[MQ_RECV_SIZE];
	size_t mq_recv_len;
#if WITH_CRYPTO
	struct aead *crypto;
	struct noncegen *noncegen;
#endif
};

struct packet *packet_create(struct config *cfg);
void packet_free(struct packet *p);

struct msgframe *msgframe_new(struct packet *p, struct sockaddr *sa);
void msgframe_delete(struct packet *p, struct msgframe *msg);

struct server;

/* session 0 messages */
enum session0_messages {
	S0MSG_PING = 0x0000,
	S0MSG_PONG = 0x0001,
	S0MSG_RESET = 0x0002,
};

struct session0_header {
	uint32_t zero;
	uint16_t what;
};

#define SESSION0_HEADER_SIZE (sizeof(uint32_t) + sizeof(uint16_t))

bool ss0_send(
	struct server *s, struct sockaddr *sa, uint16_t what,
	const unsigned char *b, size_t n);
void ss0_reset(struct server *s, struct sockaddr *sa, uint32_t conv);

/* process mq_recv */
void packet_recv(struct packet *p, struct server *s);

/* send a plain packet */
bool packet_send(struct packet *p, struct server *s, struct msgframe *msg);

#endif /* PACKET_H */
