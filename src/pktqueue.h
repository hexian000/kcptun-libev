#ifndef PACKET_H
#define PACKET_H

#include "aead.h"
#include "nonce.h"
#include "conf.h"
#include "leakypool.h"
#include "slog.h"
#include "sockutil.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 1500

struct msgframe {
	struct msghdr hdr;
	struct iovec iov;
	sockaddr_max_t addr;
	uint16_t len;
	uint16_t off;
	ev_tstamp ts;
	unsigned char buf[MAX_PACKET_SIZE];
};

#define MQ_SEND_SIZE 256
#define MQ_RECV_SIZE 256

struct pktqueue {
	struct leakypool msgpool;
	struct msgframe *mq_send[MQ_SEND_SIZE];
	size_t mq_send_len;
	struct msgframe *mq_recv[MQ_RECV_SIZE];
	size_t mq_recv_len;
	uint16_t pkt_offset;
#if WITH_CRYPTO
	struct aead *crypto;
	struct noncegen *noncegen;
#endif
#if WITH_OBFS
	struct obfs *obfs;
#endif
};

struct server;

struct pktqueue *pktqueue_new(struct server *s);
void pktqueue_free(struct pktqueue *q);

struct msgframe *msgframe_new(struct pktqueue *q, struct sockaddr *sa);
void msgframe_delete(struct pktqueue *q, struct msgframe *msg);

/* process mq_recv */
size_t packet_recv(struct pktqueue *q, struct server *s);

/* send a plain packet */
bool packet_send(struct pktqueue *q, struct server *s, struct msgframe *msg);

#endif /* PACKET_H */
