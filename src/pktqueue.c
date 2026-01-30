/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "pktqueue.h"

#include "conf.h"
#include "crypto.h"
#include "event.h"
#include "nonce.h"
#include "obfs.h"
#include "server.h"
#include "session.h"
#include "sockutil.h"
#include "util.h"

#include "algo/hashtable.h"
#include "utils/debug.h"
#include "utils/minmax.h"
#include "utils/slog.h"

#include "ikcp.h"

#include <ev.h>
#include <sys/socket.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MSG_LOGVV(what, msg)                                                   \
	do {                                                                   \
		if (!LOGLEVEL(VERYVERBOSE)) {                                  \
			break;                                                 \
		}                                                              \
		char addr[64];                                                 \
		format_sa(addr, sizeof(addr), &(msg)->addr.sa);                \
		LOG_BIN_F(                                                     \
			VERYVERBOSE, (msg)->buf, (msg)->len, 0,                \
			what ": %" PRIu16 " bytes, addr=%s", (msg)->len,       \
			addr);                                                 \
	} while (0)

#if WITH_CRYPTO

static bool crypto_open_inplace(
	struct pktqueue *restrict q, unsigned char *data, size_t *restrict len,
	const size_t size)
{
	const struct crypto *restrict crypto = q->crypto;
	ASSERT(crypto != NULL);
	const size_t src_len = *len;
	ASSERT(size >= src_len);
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
		return false;
	}
	if (!noncegen_verify(q->noncegen, nonce)) {
		LOG_BIN(VERYVERBOSE, nonce, nonce_size, "nonce reuse detected");
		return false;
	}
	*len = dst_len;
	return true;
}

/* caller should ensure the buffer is large enough */
static bool crypto_seal_inplace(
	struct pktqueue *restrict q, unsigned char *data, size_t *restrict len,
	const size_t size)
{
	const struct crypto *restrict crypto = q->crypto;
	const size_t plain_len = *len;
	const size_t nonce_size = crypto->nonce_size;
	const size_t overhead = crypto->overhead;
	ASSERT(size >= plain_len + overhead + nonce_size);
	const unsigned char *nonce = noncegen_next(q->noncegen);
	const size_t dst_size = size - nonce_size;
	size_t dst_len =
		crypto_seal(crypto, data, dst_size, nonce, data, plain_len);
	if (dst_len != plain_len + overhead) {
		return false;
	}
	memcpy(data + dst_len, nonce, nonce_size);
	*len = dst_len + nonce_size;
	return true;
}
#endif /* WITH_CRYPTO */

static void queue_recv(struct server *restrict s, struct msgframe *restrict msg)
{
	MSG_LOGVV("queue_recv", msg);
	const unsigned char *kcp_packet = msg->buf + msg->off;
	uint32_t conv = ikcp_getconv(kcp_packet);
	if (conv == UINT32_C(0)) {
		session0(s, msg);
		return;
	}

	const struct sockaddr *sa = &msg->addr.sa;
	unsigned char sskey[SESSION_KEY_SIZE];
	SESSION_MAKEKEY(sskey, sa, conv);
	const struct hashkey hkey = {
		.len = sizeof(sskey),
		.data = sskey,
	};
	struct session *restrict ss;
	if (!table_find(s->sessions, hkey, (void **)&ss)) {
		if ((s->conf->mode & MODE_SERVER) == 0) {
			if (LOGLEVEL(WARNING)) {
				LOG_RATELIMITED_F(
					WARNING, ev_now(s->loop), 1.0,
					"* session %08" PRIX32 " not found",
					conv);
			}
			ss0_reset(s, sa, conv);
			return;
		}
		/* accept new kcp session */
		ss = session_new(s, &msg->addr, conv);
		if (ss == NULL) {
			LOGOOM();
			return;
		}
		ss->is_accepted = true;
		void *elem = ss;
		s->sessions = table_set(s->sessions, SESSION_GETKEY(ss), &elem);
		ASSERT(elem == NULL);
		if (LOGLEVEL(DEBUG)) {
			char addr_str[64];
			format_sa(addr_str, sizeof(addr_str), sa);
			LOG_F(DEBUG, "[session:%08" PRIX32 "] kcp: accepted %s",
			      conv, addr_str);
		}
		ss->kcp_state = KCP_STATE_CONNECT;
	}

	const ev_tstamp now = ev_now(s->loop);
	if (!sa_equals(sa, &ss->raddr.sa)) {
		if (ss->last_reset == TSTAMP_NIL ||
		    now - ss->last_reset > 1.0) {
			char oaddr_str[64];
			format_sa(oaddr_str, sizeof(oaddr_str), &ss->raddr.sa);
			char addr_str[64];
			format_sa(addr_str, sizeof(addr_str), sa);
			LOGW_F("[session:%08" PRIX32 "] conflict: "
			       "existing %s, refusing %s",
			       conv, oaddr_str, addr_str);
			ss0_reset(s, sa, conv);
			ss->last_reset = now;
		}
		return;
	}
	switch (ss->kcp_state) {
	case KCP_STATE_CONNECT:
		ss->kcp_state = KCP_STATE_ESTABLISHED;
		/* fallthrough */
	case KCP_STATE_ESTABLISHED:
	case KCP_STATE_LINGER:
		break;
	case KCP_STATE_TIME_WAIT:
		if (ss->last_reset == TSTAMP_NIL ||
		    now - ss->last_reset > 1.0) {
			ss0_reset(s, sa, conv);
			ss->last_reset = now;
		}
		return;
	default:
		FAILMSGF("invalid session state: %d", ss->kcp_state);
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
			const size_t cap = MAX_PACKET_SIZE - msg->off;
			size_t len = msg->len;
			if (!crypto_open_inplace(
				    q, msg->buf + msg->off, &len, cap)) {
				msgframe_delete(q, msg);
				continue;
			}
			ASSERT(len <= UINT16_MAX);
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
	MSG_LOGVV("queue_send", msg);
#if WITH_CRYPTO
	if (q->crypto != NULL) {
		const size_t cap = MAX_PACKET_SIZE - (size_t)msg->off;
		size_t len = msg->len;
		ASSERT(len <= cap);
		if (!crypto_seal_inplace(q, msg->buf + msg->off, &len, cap)) {
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
		if (LOGLEVEL(WARNING)) {
			LOG_RATELIMITED_F(
				WARNING, now, 1.0,
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
	q->noncegen = noncegen_new(
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
		LOGOOM();
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
		LOGW("packets will not be encrypted or authenticated");
	}
#endif
#if WITH_OBFS
	if (conf->obfs != NULL) {
		if ((conf->mode & (MODE_SERVER | MODE_CLIENT)) == 0 ||
		    (conf->mode & MODE_RENDEZVOUS) != 0) {
			LOGE("current mode is not compatible with obfs");
			queue_free(q);
			return NULL;
		}
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
