/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "nonce.h"

#include "conf.h"
#include "pktqueue.h"
#include "server.h"
#include "session.h"
#include "util.h"

#include "binary/serialize.h"
#include "meta/arraysize.h"
#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>
#include <sodium.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static void test_rotation(const bool strict)
{
	struct noncegen *g = noncegen_new(noncegen_counter, 24, strict);
	CHECK(g != NULL);
	struct ppbloom *b = &g->ppbloom;
	const size_t entries = strict ? 1u << 20u : 1u << 14u;
	const int bytes = strict ? 3781939 : 88640;
	CHECK(b->entries == entries);
	for (size_t i = 0; i < ARRAY_SIZE(b->bloom); i++) {
		CHECK(b->bloom[i].entries == (int)entries);
		CHECK(b->bloom[i].error == (strict ? 0x1p-20 : 0x1p-30));
		CHECK(b->bloom[i].bytes == bytes);
	}
	memset(g->buf.data, 0, g->buf.len);
	unsigned char sent[24];
	memcpy(sent, noncegen_next(g), sizeof(sent));
	CHECK(b->bloom_count[0] == 1);
	CHECK(!noncegen_verify(g, sent));
	CHECK(b->bloom_count[0] == 1);

	/* Reach each rotation boundary without filling a million-entry filter. */
	b->bloom_count[0] = entries - 2;
	(void)noncegen_next(g);
	CHECK(b->bloom_count[0] == entries - 1);
	const unsigned char received[24] = { 0xF0 };
	CHECK(noncegen_verify(g, received));
	CHECK(b->current == 1);
	CHECK(b->bloom_count[0] == entries);
	CHECK(b->bloom_count[1] == 0);
	CHECK(!noncegen_verify(g, sent));
	CHECK(!noncegen_verify(g, received));
	CHECK(b->bloom_count[1] == 0);

	b->bloom_count[1] = entries - 1;
	unsigned char fresh[24];
	memcpy(fresh, noncegen_next(g), sizeof(fresh));
	CHECK(b->current == 0);
	CHECK(b->bloom_count[0] == 0);
	CHECK(b->bloom_count[1] == entries);
	CHECK(!noncegen_verify(g, fresh));
	/* Both outbound and inbound history ages out after its filter is reset. */
	CHECK(noncegen_verify(g, sent));
	CHECK(noncegen_verify(g, received));
	CHECK(b->bloom_count[0] == 2);
	noncegen_init(g);
	CHECK(!noncegen_verify(g, sent));
	CHECK(!noncegen_verify(g, fresh));
	noncegen_free(g);
}

static void dispatch_copy(struct server *s, const struct msgframe *packet)
{
	struct pktqueue *q = s->pkt.queue;
	CHECK(q->mq_recv_len == 0);
	struct msgframe *msg = msgframe_new(q);
	CHECK(msg != NULL);
	*msg = *packet;
	q->mq_recv[q->mq_recv_len++] = msg;
	s->pkt.last_recv_time = TSTAMP_NIL;
	queue_dispatch(s);
	CHECK(q->mq_recv_len == 0);
}

static void test_packets(const char *method, const int mode)
{
	/* Peers share a PSK but independently generate and track their nonces. */
	char psk[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
	struct config conf = {
		.mode = mode,
		.kcp_sndwnd = 32,
		.kcp_rcvwnd = 32,
		.method = (char *)method,
		.psk = psk,
	};
	struct ev_loop *loop = ev_loop_new(0);
	CHECK(loop != NULL);
	struct server sender = { .conf = &conf, .loop = loop };
	sender.pkt.w_write.fd = -1;
	sender.pkt.queue = queue_new(&sender);
	CHECK(sender.pkt.queue != NULL);
	memcpy(psk,
	       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", sizeof(psk));
	struct server peer = { .conf = &conf, .loop = loop };
	peer.pkt.w_write.fd = -1;
	peer.pkt.queue = queue_new(&peer);
	CHECK(peer.pkt.queue != NULL);
	struct pktqueue *sq = sender.pkt.queue;
	struct pktqueue *pq = peer.pkt.queue;
	sq->mss = pq->mss = 1000;
	union sockaddr_max addr = { .in = { .sin_family = AF_INET } };
	unsigned char timestamp[sizeof(uint32_t)];
	write_uint32(timestamp, tstamp2ms(ev_now(loop)));
	CHECK(ss0_send(
		&sender, &addr.sa, S0MSG_PING, timestamp, sizeof(timestamp)));
	CHECK(sq->mq_send_len == 1);
	const struct msgframe packet = *sq->mq_send[0];
	dispatch_copy(&sender, &packet);
	CHECK(sender.pkt.last_recv_time == TSTAMP_NIL);
	CHECK(sq->noncegen->ppbloom.bloom_count[0] == 1);
	/* Reflections never dispatch a PING reply. */
	CHECK(sq->mq_send_len == 1);
	dispatch_copy(&peer, &packet);
	CHECK(peer.pkt.last_recv_time == ev_now(loop));
	/* The intended peer dispatches and replies. */
	CHECK(pq->mq_send_len == 1);
	CHECK(pq->noncegen->ppbloom.bloom_count[0] == 2);
	dispatch_copy(&peer, &packet);
	CHECK(peer.pkt.last_recv_time == TSTAMP_NIL);
	CHECK(pq->mq_send_len == 1);
	CHECK(pq->noncegen->ppbloom.bloom_count[0] == 2);
	dispatch_copy(&sender, pq->mq_send[0]);
	CHECK(sender.pkt.last_recv_time == ev_now(loop));
	CHECK(sq->noncegen->ppbloom.bloom_count[0] == 2);

	CHECK(ss0_send(
		&sender, &addr.sa, S0MSG_PING, timestamp, sizeof(timestamp)));
	const struct msgframe next = *sq->mq_send[1];
	struct msgframe tampered = next;
	tampered.buf[tampered.off] ^= 1;
	dispatch_copy(&peer, &tampered);
	CHECK(peer.pkt.last_recv_time == TSTAMP_NIL);
	CHECK(pq->noncegen->ppbloom.bloom_count[0] == 2);
	dispatch_copy(&peer, &next);
	CHECK(peer.pkt.last_recv_time == ev_now(loop));
	CHECK(pq->mq_send_len == 2);
	CHECK(pq->noncegen->ppbloom.bloom_count[0] == 4);
	queue_free(pq);
	queue_free(sq);
	ev_loop_destroy(loop);
	LOGI_F("reflection, replay and authentication passed: %s, mode=%d",
	       method, mode);
}

int main(void)
{
	init();
	loadlibs();
	const char *methods[] = {
		"xchacha20poly1305_ietf",
		"xsalsa20poly1305",
		"chacha20poly1305_ietf",
		"aes256gcm",
	};
	const int modes[] = {
		0, /* Rendezvous broker. */
		MODE_CLIENT,
		MODE_SERVER,
		MODE_RENDEZVOUS,
		MODE_CLIENT | MODE_RENDEZVOUS,
		MODE_SERVER | MODE_RENDEZVOUS,
	};
	for (size_t i = 0; i < ARRAY_SIZE(methods); i++) {
		if (strcmp(methods[i], "aes256gcm") == 0 &&
		    !crypto_aead_aes256gcm_is_available()) {
			LOGI("AES-GCM unavailable on this hardware; skipped");
			continue;
		}
		for (size_t j = 0; j < ARRAY_SIZE(modes); j++) {
			test_packets(methods[i], modes[j]);
		}
	}
	test_rotation(false);
	test_rotation(true);
	LOGI("shared rotation, aging and memory limits passed");
	unloadlibs();
	return EXIT_SUCCESS;
}
