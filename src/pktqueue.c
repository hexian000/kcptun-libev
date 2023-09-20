/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "pktqueue.h"
#include "algo/hashtable.h"
#include "math/rand.h"
#include "utils/check.h"
#include "utils/slog.h"
#include "conf.h"
#include "event.h"
#include "event_impl.h"
#include "crypto.h"
#include "nonce.h"
#include "obfs.h"
#include "server.h"
#include "session.h"
#include "util.h"
#include "sockutil.h"
#include "kcp/ikcp.h"

#include <ev.h>
#include <sys/socket.h>

#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#if WITH_CRYPTO

static bool crypto_open_inplace(
	struct pktqueue *restrict q, unsigned char *data, size_t *restrict len,
	const size_t size)
{
	struct crypto *restrict crypto = q->crypto;
	assert(crypto != NULL);
	const size_t src_len = *len;
	assert(size >= src_len);
	const size_t nonce_size = crypto->nonce_size;
	const size_t overhead = crypto->overhead;
	if (src_len <= nonce_size + overhead) {
		return false;
	}
	const unsigned char *nonce = data + src_len - nonce_size;
	const size_t cipher_len = src_len - nonce_size;
	const size_t dst_len =
		crypto_open(crypto, data, size, nonce, data, cipher_len);
	if (dst_len + overhead + nonce_size != src_len) {
		LOGV("failed to open packet");
		return false;
	}
	if (!noncegen_verify(q->noncegen, nonce)) {
		LOG_BIN(LOG_LEVEL_VERBOSE, nonce, nonce_size,
			"nonce reuse detected");
		return false;
	}
	*len = dst_len;
	return true;
}

/* caller should ensure the buffer is large enough */
static bool crypto_seal_inplace(
	struct pktqueue *restrict q, unsigned char *data, size_t *restrict len,
	const size_t size, const size_t pad)
{
	struct crypto *restrict crypto = q->crypto;
	const size_t src_len = *len;
	const size_t nonce_size = crypto->nonce_size;
	const size_t overhead = crypto->overhead;
	assert(size >= src_len + overhead + nonce_size);
	const size_t npad = MIN(size - (src_len + overhead + nonce_size), pad);
	if (!crypto_pad(data, src_len, npad)) {
		LOGE("failed to pad packet");
		return false;
	}
	const size_t plain_len = src_len + pad;
	const unsigned char *nonce = noncegen_next(q->noncegen);
	const size_t dst_size = size - nonce_size;
	size_t dst_len =
		crypto_seal(crypto, data, dst_size, nonce, data, plain_len);
	if (dst_len != plain_len + overhead) {
		LOGE("failed to seal packet");
		return false;
	}
	memcpy(data + dst_len, nonce, nonce_size);
	*len = dst_len + nonce_size;
	return true;
}
#endif /* WITH_CRYPTO */

static void queue_recv(struct server *restrict s, struct msgframe *restrict msg)
{
	const unsigned char *kcp_packet = msg->buf + msg->off;
	uint32_t conv = ikcp_getconv(kcp_packet);
	if (conv == UINT32_C(0)) {
		session0(s, msg);
		return;
	}

	const struct sockaddr *sa = &msg->addr.sa;
	struct session_key sskey;
	SESSION_MAKE_KEY(sskey, sa, conv);
	struct session *restrict ss =
		table_find(s->sessions, (hashkey_t *)&sskey);
	if (ss == NULL) {
		if ((s->conf->mode & MODE_SERVER) == 0) {
			if (LOGLEVEL(LOG_LEVEL_WARNING)) {
				LOG_RATELIMITED_F(
					LOG_LEVEL_WARNING, ev_now(s->loop), 1.0,
					"* session %08" PRIX32 " not found",
					conv);
			}
			ss0_reset(s, sa, conv);
			return;
		}
		/* accept new kcp session */
		ss = session_new(s, sa, conv);
		if (ss == NULL) {
			LOGE("out of memory");
			return;
		}
		ss->is_accepted = true;
		table_set(s->sessions, (hashkey_t *)&ss->key, ss);
		if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
			char addr_str[64];
			format_sa(sa, addr_str, sizeof(addr_str));
			LOG_F(LOG_LEVEL_DEBUG,
			      "session [%08" PRIX32 "] kcp: accepted %s", conv,
			      addr_str);
		}
		ss->kcp_state = STATE_CONNECT;
	}

	const ev_tstamp now = ev_now(s->loop);
	if (!sa_equals(sa, &ss->raddr.sa)) {
		if (ss->last_reset == TSTAMP_NIL ||
		    now - ss->last_reset > 1.0) {
			char oaddr_str[64];
			format_sa(&ss->raddr.sa, oaddr_str, sizeof(oaddr_str));
			char addr_str[64];
			format_sa(sa, addr_str, sizeof(addr_str));
			LOGW_F("session [%08" PRIX32 "] conflict: "
			       "existing %s, refusing %s",
			       conv, oaddr_str, addr_str);
			ss0_reset(s, sa, conv);
			ss->last_reset = now;
		}
		return;
	}
	switch (ss->kcp_state) {
	case STATE_CONNECT:
		ss->kcp_state = STATE_CONNECTED;
		break;
	case STATE_TIME_WAIT:
		if (ss->last_reset == TSTAMP_NIL ||
		    now - ss->last_reset > 1.0) {
			ss0_reset(s, sa, conv);
			ss->last_reset = now;
		}
		return;
	}

	const int r =
		ikcp_input(ss->kcp, (const char *)kcp_packet, (long)msg->len);
	if (r < 0) {
		LOGW_F("ikcp_input: %d", r);
		return;
	}
	ss->stats.kcp_rx += msg->len;
	s->stats.kcp_rx += msg->len;
	if (ss->kcp_flush >= 2) {
		/* flush acks */
		session_kcp_flush(ss);
	}
	session_read_cb(ss);
}

size_t queue_dispatch(struct server *restrict s)
{
	struct pktqueue *restrict q = s->pkt.queue;
	if (q->mq_recv_len == 0) {
		return 0;
	}
	s->pkt.last_recv_time = ev_now(s->loop);
	size_t nbrecv = 0;
	for (size_t i = 0; i < q->mq_recv_len; i++) {
		struct msgframe *restrict msg = q->mq_recv[i];
		s->stats.pkt_rx += msg->len;
#if WITH_OBFS
		struct obfs_ctx *ctx = NULL;
		if (q->obfs != NULL) {
			ctx = obfs_open_inplace(q->obfs, msg);
			if (ctx == NULL) {
				msgframe_delete(q, msg);
				continue;
			}
		}
#endif
#if WITH_CRYPTO
		if (q->crypto != NULL) {
			size_t cap = MAX_PACKET_SIZE - msg->off;
			size_t len = msg->len;
			if (!crypto_open_inplace(
				    q, msg->buf + msg->off, &len, cap)) {
				msgframe_delete(q, msg);
				continue;
			}
			assert(len <= UINT16_MAX);
			msg->len = len;
		}
#endif
#if WITH_OBFS
		if (ctx != NULL) {
			obfs_ctx_auth(ctx, true);
		}
#endif
		queue_recv(s, msg);
		nbrecv += msg->len;
		msgframe_delete(q, msg);
	}
	q->mq_recv_len = 0;
	return nbrecv;
}

bool queue_send(struct server *restrict s, struct msgframe *restrict msg)
{
	struct pktqueue *restrict q = s->pkt.queue;
#if WITH_CRYPTO
	if (q->crypto != NULL) {
		const size_t cap = q->mss;
		assert(cap <= MAX_PACKET_SIZE - msg->off);
		size_t len = msg->len;
		assert(len <= cap);
		const size_t pad = rand64n(15);
		if (!crypto_seal_inplace(
			    q, msg->buf + msg->off, &len, cap, pad)) {
			return false;
		}
		msg->len = len;
	}
#endif
#if WITH_OBFS
	if (q->obfs != NULL) {
		const bool obfs_seal_ok = obfs_seal_inplace(q->obfs, msg);
		if (!obfs_seal_ok) {
			msgframe_delete(q, msg);
			return false;
		}
	}
#endif

	const ev_tstamp now = ev_now(s->loop);
	if (q->mq_send_len >= q->mq_send_cap) {
		if (LOGLEVEL(LOG_LEVEL_WARNING)) {
			LOG_RATELIMITED_F(
				LOG_LEVEL_WARNING, now, 1.0,
				"* mq_send is full, %" PRIu16
				" bytes discarded",
				msg->len);
		}
		msgframe_delete(q, msg);
		return false;
	}
	msg->ts = now;
	q->mq_send[q->mq_send_len++] = msg;
	pkt_notify_send(s);
	return true;
}

#if WITH_CRYPTO
static bool queue_new_crypto(
	struct pktqueue *restrict q, const struct config *restrict conf)
{
	if (conf->method == NULL) {
		return true;
	}
	q->crypto = crypto_new(conf->method);
	if (q->crypto == NULL) {
		return false;
	}
	if (conf->psk) {
		if (!crypto_b64psk(q->crypto, conf->psk)) {
			crypto_free(q->crypto);
			q->crypto = NULL;
			return false;
		}
	} else if (conf->password) {
		if (!crypto_password(q->crypto, conf->password)) {
			crypto_free(q->crypto);
			q->crypto = NULL;
			return false;
		}
	}
	q->noncegen = noncegen_create(
		q->crypto->noncegen_method, q->crypto->nonce_size,
		(conf->mode & MODE_SERVER) != 0);
	if (q->noncegen == NULL) {
		crypto_free(q->crypto);
		return false;
	}
	return true;
}
#endif

struct pktqueue *queue_new(struct server *restrict s)
{
	const struct config *restrict conf = s->conf;
	struct pktqueue *q = malloc(sizeof(struct pktqueue));
	if (q == NULL) {
		return NULL;
	}
	const size_t send_cap = MAX(conf->kcp_sndwnd * 4, MMSG_BATCH_SIZE * 2);
	const size_t recv_cap = MAX(conf->kcp_rcvwnd, MMSG_BATCH_SIZE);
	*q = (struct pktqueue){
		.mq_send = malloc(send_cap * sizeof(struct msgframe *)),
		.mq_send_cap = send_cap,
		.mq_recv = malloc(recv_cap * sizeof(struct msgframe *)),
		.mq_recv_cap = recv_cap,
		.msg_offset = 0,
	};
	if (q->mq_send == NULL || q->mq_recv == NULL) {
		LOGOOM();
		queue_free(q);
		return NULL;
	}
#if WITH_CRYPTO
	if (!queue_new_crypto(q, conf)) {
		queue_free(q);
		return NULL;
	}
	if (q->crypto == NULL) {
		/* for now, protocol security relies on encryption */
		LOGW("packets will not be encrypted or authenticated. malformed packet may lead to crash, use at your own risk");
	}
#endif
#if WITH_OBFS
	if (conf->obfs != NULL) {
		if (q->crypto == NULL) {
			LOGE("encryption must be enabled to use obfs");
			queue_free(q);
			return NULL;
		}
		q->obfs = obfs_new(s);
		if (q->obfs == NULL) {
			LOGW_F("obfs init failed: %s", conf->obfs);
		}
	}
#endif
	return q;
}

void queue_free(struct pktqueue *restrict q)
{
	if (q->mq_send != NULL) {
		for (; q->mq_send_len > 0; q->mq_send_len--) {
			msgframe_delete(q, q->mq_send[q->mq_send_len]);
		}
		free(q->mq_send);
		q->mq_send = NULL;
	}
	if (q->mq_recv != NULL) {
		for (; q->mq_recv_len > 0; q->mq_recv_len--) {
			msgframe_delete(q, q->mq_recv[q->mq_recv_len]);
		}
		free(q->mq_recv);
		q->mq_recv = NULL;
	}
#if WITH_CRYPTO
	if (q->crypto != NULL) {
		crypto_free(q->crypto);
		q->crypto = NULL;
	}
	if (q->noncegen != NULL) {
		noncegen_free(q->noncegen);
		q->noncegen = NULL;
	}
#endif
#if WITH_OBFS
	if (q->obfs != NULL) {
		obfs_free(q->obfs);
		q->obfs = NULL;
	}
#endif
	free(q);
}
