/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef PACKET_H
#define PACKET_H

#include "sockutil.h"
#include "util.h"

#include "utils/mcache.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 1500
#define MMSG_BATCH_SIZE 128

struct msgframe {
	union sockaddr_max addr;
	uint16_t len;
	uint16_t off;
	ev_tstamp ts;
	unsigned char buf[MAX_PACKET_SIZE];
};

struct pktqueue {
	struct msgframe **mq_send;
	size_t mq_send_len, mq_send_cap;
	struct msgframe **mq_recv;
	size_t mq_recv_len, mq_recv_cap;
	uint16_t msg_offset;
	uint16_t mss;
#if WITH_CRYPTO
	struct crypto *crypto;
	struct noncegen *noncegen;
#endif
#if WITH_OBFS
	struct obfs *obfs;
#endif
};

struct server;

struct pktqueue *queue_new(struct server *s);
void queue_free(struct pktqueue *q);

static inline struct msgframe *msgframe_new(struct pktqueue *restrict q)
{
	struct msgframe *restrict msg = mcache_get(msgpool);
	if (msg == NULL) {
		return NULL;
	}
	msg->off = q->msg_offset;
	return msg;
}

static inline void msgframe_delete(struct pktqueue *q, struct msgframe *msg)
{
	UNUSED(q);
	mcache_put(msgpool, msg);
}

/* process mq_recv */
size_t queue_dispatch(struct server *s);

/* send a plain packet */
bool queue_send(struct server *s, struct msgframe *msg);

#endif /* PACKET_H */
