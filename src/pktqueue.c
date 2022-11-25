#include "pktqueue.h"
#include "conf.h"
#include "event.h"
#include "event_impl.h"
#include "hashtable.h"
#include "leakypool.h"
#include "aead.h"
#include "nonce.h"
#include "obfs.h"
#include "server.h"
#include "session.h"
#include "slog.h"
#include "util.h"
#include "sockutil.h"

#include "kcp/ikcp.h"
#include <ev.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#if WITH_CRYPTO
static const char crypto_tag[] = PROJECT_NAME;
static const size_t crypto_tag_size = sizeof(crypto_tag);

static bool crypto_open_inplace(
	struct pktqueue *restrict q, unsigned char *data, size_t *restrict len,
	const size_t size)
{
	struct aead *restrict crypto = q->crypto;
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
	const size_t dst_len = aead_open(
		crypto, data, size, nonce, data, cipher_len,
		(const unsigned char *)crypto_tag, crypto_tag_size);
	if (dst_len + overhead + nonce_size != src_len) {
		LOGV("failed to open packet");
		return false;
	}
	if (!noncegen_verify(q->noncegen, nonce)) {
		LOGV("nonce reuse detected");
		return false;
	}
	*len = dst_len;
	return true;
}

/* caller should ensure buffer is large enough */
static bool crypto_seal_inplace(
	struct pktqueue *restrict q, unsigned char *data, size_t *restrict len,
	const size_t size)
{
	struct aead *restrict crypto = q->crypto;
	const size_t src_len = *len;
	const size_t nonce_size = crypto->nonce_size;
	const size_t overhead = crypto->overhead;
	assert(size >= src_len + overhead + nonce_size);
	const unsigned char *nonce = noncegen_next(q->noncegen);
	const size_t dst_size = size - nonce_size;
	size_t dst_len = aead_seal(
		crypto, data, dst_size, nonce, data, src_len,
		(const unsigned char *)crypto_tag, crypto_tag_size);
	if (dst_len != src_len + overhead) {
		LOGE("failed to seal packet");
		return false;
	}
	memcpy(data + dst_len, nonce, nonce_size);
	*len = dst_len + nonce_size;
	return true;
}
#endif /* WITH_CRYPTO */

struct msgframe *msgframe_new(struct pktqueue *q, struct sockaddr *sa)
{
	struct msgframe *restrict msg = pool_get(&q->msgpool);
	if (msg == NULL) {
		LOGOOM();
		return NULL;
	}
	msg->hdr = (struct msghdr){
		.msg_name = &msg->addr,
		.msg_namelen = sizeof(msg->addr),
		.msg_iov = &msg->iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};
	msg->iov = (struct iovec){
		.iov_base = msg->buf,
		.iov_len = sizeof(msg->buf),
	};
	memset(&msg->addr, 0, sizeof(msg->addr));
	if (sa != NULL) {
		const socklen_t len = getsocklen(sa);
		memcpy(&msg->addr, sa, len);
		msg->hdr.msg_namelen = len;
	}
	msg->off = 0;
#if WITH_OBFS
	if (q->obfs != NULL) {
		msg->off = obfs_offset(q->obfs);
	}
#endif
	return msg;
}

void msgframe_delete(struct pktqueue *q, struct msgframe *msg)
{
	if (msg != NULL) {
		pool_put(&q->msgpool, msg);
	}
}

static void
queue_recv_one(struct server *restrict s, struct msgframe *restrict msg)
{
	unsigned char *kcp_packet = msg->buf + msg->off;
	uint32_t conv = ikcp_getconv(kcp_packet);
	if (conv == UINT32_C(0)) {
		session0(s, msg);
		return;
	}
	hashkey_t sskey;
	struct sockaddr *sa = &msg->addr.sa;
	conv_make_key(&sskey, sa, conv);
	struct session *restrict ss;
	const bool is_accept = !table_find(s->sessions, &sskey, (void **)&ss);
	if (is_accept) {
		if ((s->conf->mode & MODE_SERVER) == 0) {
			LOGW_F("session [%08" PRIX32 "] not found", conv);
			ss0_reset(s, sa, conv);
			return;
		}
		/* serve new kcp session */
		ss = session_new(s, sa, conv);
		if (ss == NULL) {
			LOGOOM();
			return;
		}
		ss->is_accepted = true;
		table_set(s->sessions, &sskey, ss);
		if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
			char addr_str[64];
			format_sa(sa, addr_str, sizeof(addr_str));
			LOGD_F("session [%08" PRIX32 "] accepted from: %s",
			       conv, addr_str);
		}
		ss->kcp_state = STATE_CONNECT;
	}
	if (!sa_equals(sa, &ss->raddr.sa)) {
		char oaddr_str[64];
		format_sa(&ss->raddr.sa, oaddr_str, sizeof(oaddr_str));
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOGW_F("session [%08" PRIX32 "] conv conflict: "
		       "existing %s, refusing %s",
		       conv, oaddr_str, addr_str);
		ss0_reset(s, sa, conv);
		return;
	}
	const ev_tstamp now = ev_now(s->loop);
	switch (ss->kcp_state) {
	case STATE_CONNECT:
		ss->kcp_state = STATE_CONNECTED;
		break;
	case STATE_TIME_WAIT: {
		if (ss->last_send == TSTAMP_NIL || now - ss->last_send > 1.0) {
			ss0_reset(s, sa, conv);
			ss->last_send = now;
		}
		return;
	}
	}

	int r = ikcp_input(ss->kcp, (const char *)kcp_packet, (long)msg->len);
	if (r < 0) {
		LOGW_F("ikcp_input: %d", r);
		return;
	}
	ss->last_recv = now;
	ss->stats.kcp_rx += msg->len;
	s->stats.kcp_rx += msg->len;
	if (is_accept) {
		return;
	}
	ss->pkt_arrived++;
	if (ss->kcp_flush >= 2 || ss->pkt_arrived >= ss->kcp->rcv_wnd) {
		/* flush acks */
		kcp_flush(ss);
	}
}

size_t queue_recv(struct pktqueue *restrict q, struct server *s)
{
	if (q->mq_recv_len == 0) {
		return 0;
	}
	size_t nbrecv = 0;
	for (size_t i = 0; i < q->mq_recv_len; i++) {
		struct msgframe *msg = q->mq_recv[i];
#if WITH_OBFS
		if (q->obfs != NULL) {
			if (!obfs_open_inplace(q->obfs, msg)) {
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
		queue_recv_one(s, msg);
		nbrecv += msg->len;
		msgframe_delete(q, msg);
	}
	if (nbrecv > 0) {
		s->stats.pkt_rx += nbrecv;
		s->pkt.last_recv_time = ev_now(s->loop);
	}
	q->mq_recv_len = 0;
	return nbrecv;
}

bool queue_send(
	struct pktqueue *restrict q, struct server *s,
	struct msgframe *restrict msg)
{
#if WITH_CRYPTO
	if (q->crypto != NULL) {
		size_t cap = MAX_PACKET_SIZE - msg->off;
		size_t len = msg->len;
		const bool pkt_seal_ok =
			crypto_seal_inplace(q, msg->buf + msg->off, &len, cap);
		CHECK(pkt_seal_ok);
		assert(len <= UINT16_MAX);
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

	if (q->mq_send_len >= q->mq_send_cap) {
		LOG_RATELIMITEDF(
			LOG_LEVEL_WARNING, s->loop, 1.0,
			"* mq_send is full, %" PRIu16 " bytes discarded",
			msg->len);
		msgframe_delete(q, msg);
		return false;
	}
	msg->ts = ev_now(s->loop);
	msg->hdr.msg_namelen = getsocklen(msg->hdr.msg_name);
	msg->iov.iov_len = msg->len;
	q->mq_send[q->mq_send_len++] = msg;
	if (q->mq_send_len < q->mq_send_cap) {
		struct ev_io *restrict w_write = &s->pkt.w_write;
		if (!ev_is_active(w_write)) {
			ev_io_start(s->loop, w_write);
		}
	} else {
		pkt_flush(s);
	}
	return true;
}

#if WITH_CRYPTO
static bool
queue_new_crypto(struct pktqueue *restrict q, struct config *restrict conf)
{
	if (conf->method == NULL) {
		return true;
	}
	q->crypto = aead_create(conf->method);
	if (q->crypto == NULL) {
		return false;
	}
	if (conf->psk) {
		if (conf->psklen != q->crypto->key_size) {
			LOGE("wrong psk length");
			aead_free(q->crypto);
			q->crypto = NULL;
			return false;
		}
		aead_psk(q->crypto, conf->psk);
		UTIL_SAFE_FREE(conf->psk);
	} else if (conf->password) {
		aead_password(q->crypto, conf->password);
		UTIL_SAFE_FREE(conf->password);
	}
	q->noncegen = noncegen_create(
		q->crypto->noncegen_method, q->crypto->nonce_size,
		!!(conf->mode & MODE_SERVER));
	if (q->noncegen == NULL) {
		aead_free(q->crypto);
		return false;
	}
	return true;
}
#endif

struct pktqueue *queue_new(struct server *restrict s)
{
	struct config *restrict conf = s->conf;
	struct pktqueue *q = util_malloc(sizeof(struct pktqueue));
	if (q == NULL) {
		return NULL;
	}
	const size_t send_cap = conf->kcp_sndwnd < 256 ? 256 : conf->kcp_sndwnd;
	const size_t recv_cap = conf->kcp_rcvwnd < 256 ? 256 : conf->kcp_rcvwnd;
	*q = (struct pktqueue){
		.msgpool = pool_create(256, sizeof(struct msgframe)),
		.mq_send = util_malloc(send_cap * sizeof(struct msgframe *)),
		.mq_send_cap = send_cap,
		.mq_recv = util_malloc(recv_cap * sizeof(struct msgframe *)),
		.mq_recv_cap = recv_cap,
	};
	if (q->mq_send == NULL || q->mq_recv == NULL ||
	    q->msgpool.pool == NULL) {
		queue_free(q);
		return NULL;
	}
	q->pkt_offset = 0;
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
		util_free(q->mq_send);
		q->mq_send = NULL;
	}
	if (q->mq_recv != NULL) {
		for (; q->mq_recv_len > 0; q->mq_recv_len--) {
			msgframe_delete(q, q->mq_recv[q->mq_recv_len]);
		}
		util_free(q->mq_recv);
		q->mq_recv = NULL;
	}
	pool_free(&q->msgpool);
#if WITH_CRYPTO
	if (q->crypto != NULL) {
		aead_free(q->crypto);
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
	util_free(q);
}
