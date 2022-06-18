#include "session.h"
#include "aead.h"
#include "event.h"
#include "hashtable.h"
#include "server.h"
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
	ikcp_setmtu(kcp, cfg->kcp_mtu);
	ikcp_nodelay(
		kcp, cfg->kcp_nodelay, cfg->kcp_interval, cfg->kcp_resend,
		cfg->kcp_nc);
	ikcp_setoutput(kcp, udp_output);
	return kcp;
}

struct session *session_new_dummy(struct server *s)
{
	struct session *restrict ss =
		(struct session *)util_malloc(sizeof(struct session));
	if (ss == NULL) {
		return NULL;
	}
	*ss = (struct session){
		.server = s,
		.state = STATE_TIME_WAIT,
		.tcp_fd = -1,
		.last_seen = ev_now(s->loop),
	};
	LOGD_F("session new dummy: %p", (void *)ss);
	return ss;
}

struct session *session_new(
	struct server *restrict s, const int fd, struct sockaddr *addr,
	const uint32_t conv)
{
	struct session *restrict ss =
		(struct session *)util_malloc(sizeof(struct session));
	if (ss == NULL) {
		return NULL;
	}
	*ss = (struct session){
		.wbuf_len = 0,
		.state = STATE_CLOSED,
		.server = s,
		.tcp_fd = fd,
		.conv = conv,
		.kcp_checked = false,
		.kcp_closed = false,
		.last_seen = ev_now(s->loop),
	};
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
	ss->w_read = (struct ev_io *)util_malloc(sizeof(struct ev_io));
	if (ss->w_read == NULL) {
		session_free(ss);
		return NULL;
	}
	ss->w_write = (struct ev_io *)util_malloc(sizeof(struct ev_io));
	if (ss->w_write == NULL) {
		session_free(ss);
		return NULL;
	}
	ss->kcp = kcp_new(ss, s->conf, conv);
	if (ss->kcp == NULL) {
		session_free(ss);
		return NULL;
	}
	memset(&ss->udp_remote, 0, sizeof(ss->udp_remote));
	memcpy(&ss->udp_remote, addr, getsocklen(addr));
	LOGD_F("session new: %p", (void *)ss);
	return ss;
}

void session_free(struct session *restrict ss)
{
	LOGD_F("session free: %p", (void *)ss);
	if (ss->w_read != NULL) {
		ev_io_stop(ss->server->loop, ss->w_read);
		util_free(ss->w_read);
		ss->w_read = NULL;
	}
	if (ss->w_write != NULL) {
		ev_io_stop(ss->server->loop, ss->w_write);
		util_free(ss->w_write);
		ss->w_write = NULL;
	}
	if (ss->tcp_fd != -1) {
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

void session_start(struct session *restrict ss)
{
	LOGI_F("session [%08" PRIX32 "] start", ss->kcp->conv);
	// Initialize and start watchers to transfer data
	ev_io_init(ss->w_read, read_cb, ss->tcp_fd, EV_READ);
	ss->w_read->data = ss;
	ev_io_start(ss->server->loop, ss->w_read);
	ev_io_init(ss->w_write, write_cb, ss->tcp_fd, EV_WRITE);
	ss->w_write->data = ss;
	ev_io_start(ss->server->loop, ss->w_write);
}

void session_shutdown(struct session *restrict ss)
{
	LOGD_F("session [%08" PRIX32 "] shutdown", ss->kcp->conv);
	shutdown(ss->tcp_fd, SHUT_RD);
	if (ss->w_read != NULL) {
		ev_io_stop(ss->server->loop, ss->w_read);
		util_free(ss->w_read);
		ss->w_read = NULL;
	}
	if (ss->w_write != NULL) {
		ev_io_stop(ss->server->loop, ss->w_write);
		util_free(ss->w_write);
		ss->w_write = NULL;
	}
	UTIL_SAFE_FREE(ss->rbuf);
	UTIL_SAFE_FREE(ss->wbuf);
	if (ss->tcp_fd != -1) {
		close(ss->tcp_fd);
		ss->tcp_fd = -1;
	}
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
