#include "session.h"
#include "aead.h"
#include "event.h"
#include "hashtable.h"
#include "server.h"
#include "proxy.h"
#include "packet.h"
#include "sockutil.h"
#include "util.h"

#include <ev.h>

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <inttypes.h>
#include <stdint.h>

static ikcpcb *
kcp_new(struct session *restrict ss, struct config *restrict cfg, uint32_t conv)
{
	ikcpcb *kcp = ikcp_create(conv, ss);
	if (kcp == NULL) {
		return NULL;
	}
	ikcp_wndsize(kcp, cfg->kcp_sndwnd, cfg->kcp_rcvwnd);
	size_t mtu = cfg->kcp_mtu;
#if WITH_CRYPTO
	struct aead *crypto = ss->server->udp.packets->crypto;
	if (crypto != NULL) {
		mtu -= crypto->overhead + crypto->nonce_size;
	}
#endif
	ikcp_setmtu(kcp, mtu);
	ikcp_nodelay(
		kcp, cfg->kcp_nodelay, cfg->kcp_interval, cfg->kcp_resend,
		cfg->kcp_nc);
	ikcp_setoutput(kcp, udp_output);
	return kcp;
}

struct session *session_new(
	struct server *restrict s, struct sockaddr *addr, const uint32_t conv)
{
	struct session *restrict ss =
		(struct session *)util_malloc(sizeof(struct session));
	if (ss == NULL) {
		return NULL;
	}
	const ev_tstamp now = ev_now(s->loop);
	*ss = (struct session){
		.state = STATE_HALFOPEN,
		.server = s,
		.tcp_fd = -1,
		.conv = conv,
		.kcp_checked = false,
		.last_send = now,
		.last_recv = now,
	};
	ss->kcp = kcp_new(ss, s->conf, conv);
	if (ss->kcp == NULL) {
		session_free(ss);
		return NULL;
	}
	ss->rbuf = util_malloc(SESSION_BUF_SIZE);
	if (ss->rbuf == NULL) {
		session_free(ss);
		return NULL;
	}
	ss->wbuf = util_malloc(SESSION_BUF_SIZE);
	if (ss->wbuf == NULL) {
		session_free(ss);
		return NULL;
	}
	ss->w_read = util_malloc(sizeof(struct ev_io));
	if (ss->w_read == NULL) {
		session_free(ss);
		return NULL;
	}
	ss->w_write = util_malloc(sizeof(struct ev_io));
	if (ss->w_write == NULL) {
		session_free(ss);
		return NULL;
	}
	memset(&ss->udp_remote, 0, sizeof(ss->udp_remote));
	memcpy(&ss->udp_remote, addr, getsocklen(addr));
	LOGD_F("session [%08" PRIX32 "] new: %p", conv, (void *)ss);
	return ss;
}

void session_free(struct session *restrict ss)
{
	LOGD_F("session free: %p", (void *)ss);
	if (ss->tcp_fd != -1) {
		ev_io_stop(ss->server->loop, ss->w_read);
		UTIL_SAFE_FREE(ss->w_read);
		ev_io_stop(ss->server->loop, ss->w_write);
		UTIL_SAFE_FREE(ss->w_write);
		close(ss->tcp_fd);
		ss->tcp_fd = -1;
	}
	if (ss->kcp != NULL) {
		ikcp_release(ss->kcp);
		ss->kcp = NULL;
	}
	UTIL_SAFE_FREE(ss->rbuf);
	UTIL_SAFE_FREE(ss->wbuf);
	util_free(ss);
}

void session_start(struct session *restrict ss, const int fd)
{
	LOGD_F("session [%08" PRIX32 "] start, fd: %d", ss->conv, fd);
	ss->tcp_fd = fd;
	// Initialize and start watchers to transfer data
	ev_io_init(ss->w_read, read_cb, fd, EV_READ);
	ss->w_read->data = ss;
	if (ss->state == STATE_CONNECTED) {
		ev_io_start(ss->server->loop, ss->w_read);
	}
	ev_io_init(ss->w_write, write_cb, fd, EV_WRITE);
	ss->w_write->data = ss;
	ev_io_start(ss->server->loop, ss->w_write);
}

void session_shutdown(struct session *restrict ss)
{
	LOGD_F("session [%08" PRIX32 "] shutdown", ss->conv);
	if (ss->tcp_fd != -1) {
		ev_io_stop(ss->server->loop, ss->w_read);
		ev_io_stop(ss->server->loop, ss->w_write);
		close(ss->tcp_fd);
		ss->tcp_fd = -1;
	}
}

static void consume_wbuf(struct session *restrict ss, size_t len)
{
	ss->wbuf_len -= len;
	if (ss->wbuf_len > 0) {
		memmove(ss->wbuf, ss->wbuf + len, ss->wbuf_len);
	}
}

void session_on_msg(struct session *restrict ss, struct tlv_header *restrict hdr)
{
	switch (hdr->msg) {
	case SMSG_DIAL: {
		UTIL_ASSERT(hdr->len == TLV_HEADER_SIZE);
		LOGD_F("session [%08" PRIX32 "] msg: dial", ss->conv);
		if (ss->tcp_fd != -1) {
			break;
		}
		if (!proxy_dial(ss, ss->server->conf->connect.sa)) {
			break;
		}
		consume_wbuf(ss, hdr->len);
		return;
	} break;
	case SMSG_PUSH: {
		/* tcp connection is lost, discard packet */
		if (ss->tcp_fd == -1) {
			break;
		}
		ss->wbuf_navail = (size_t)hdr->len - TLV_HEADER_SIZE;
		return;
	} break;
	case SMSG_EOF: {
		UTIL_ASSERT(hdr->len == TLV_HEADER_SIZE);
		LOGD_F("session [%08" PRIX32 "] msg: eof", ss->conv);
		ss->wbuf_len = 0;
		session_shutdown(ss);
		ss->state = STATE_LINGER;
		return;
	} break;
	case SMSG_KEEPALIVE: {
		UTIL_ASSERT(hdr->len == TLV_HEADER_SIZE);
		consume_wbuf(ss, hdr->len);
		return;
	} break;
	}
	LOGE_F("smsg error: %04" PRIX16 ", %04" PRIX16, hdr->msg, hdr->len);
	kcp_reset(ss);
	ss->state = STATE_LINGER;
}

bool shutdown_filt(
	struct hashtable *t, const hashkey_t *key, void *ss, void *user)
{
	UNUSED(t);
	UNUSED(key);
	UNUSED(user);
	session_free((struct session *)ss);
	return false;
}

void session_close_all(struct hashtable *t)
{
	table_filter(t, shutdown_filt, NULL);
}
