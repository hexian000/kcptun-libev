#ifndef PACKET_H
#define PACKET_H

#include "leakypool.h"
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

struct pktqueue {
	struct leakypool msgpool;
	struct msgframe **mq_send;
	size_t mq_send_len, mq_send_cap;
	struct msgframe **mq_recv;
	size_t mq_recv_len, mq_recv_cap;
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

struct pktqueue *queue_new(struct server *s);
void queue_free(struct pktqueue *q);

struct msgframe *msgframe_new(struct pktqueue *q, struct sockaddr *sa);
void msgframe_delete(struct pktqueue *q, struct msgframe *msg);

/* process mq_recv */
size_t queue_recv(struct pktqueue *q, struct server *s);

/* send a plain packet */
bool queue_send(struct pktqueue *q, struct server *s, struct msgframe *msg);

#endif /* PACKET_H */
