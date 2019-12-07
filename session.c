#include "session.h"
#include "aead.h"
#include "event.h"
#include "server.h"
#include "slice.h"
#include "util.h"

#include <ev.h>

#include <netinet/in.h>
#include <unistd.h>

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>

#define BUFFER_CAPACITY 16384

static inline ikcpcb *kcp_new(struct session *restrict session,
			      struct config *restrict cfg, uint32_t conv)
{
	ikcpcb *kcp = ikcp_create(conv, session);
	if (kcp == NULL) {
		return NULL;
	}
	ikcp_wndsize(kcp, cfg->kcp_sndwnd, cfg->kcp_rcvwnd);
	ikcp_setmtu(kcp, cfg->kcp_mtu);
	ikcp_nodelay(kcp, cfg->kcp_nodelay, cfg->kcp_interval, cfg->kcp_resend,
		     cfg->kcp_nc);
	ikcp_setoutput(kcp, udp_output);
	return kcp;
}

static inline void clone_addr(struct endpoint *dst, const struct endpoint src)
{
	void *s = util_malloc(src.len);
	*dst = (struct endpoint){ .sa = s, .len = src.len };
	if (s != NULL) {
		memcpy(s, src.sa, src.len);
	}
}

struct session *session_new_dummy()
{
	struct session *restrict session =
		(struct session *)util_malloc(sizeof(struct session));
	if (session == NULL) {
		return NULL;
	}
	*session = (struct session){
		.state = STATE_TIME_WAIT,
		.tcp_fd = -1,
	};
	LOGF_D("session new dummy: %p", (void *)session);
	return session;
}

struct session *session_new(struct server *restrict s, int fd, uint32_t conv,
			    struct endpoint udp_remote)
{
	struct session *restrict session =
		(struct session *)util_malloc(sizeof(struct session));
	if (session == NULL) {
		return NULL;
	}
	*session = (struct session){
		.wbuf_flush = 0,
		.state = STATE_CLOSED,
		.server = s,
		.tcp_fd = fd,
		.kcp_blocked = false,
		.kcp_checked = false,
	};
	session->rbuf = slice_make(BUFFER_CAPACITY);
	if (session->rbuf.data == NULL) {
		session_free(session);
		return NULL;
	}
	session->wbuf = slice_make(BUFFER_CAPACITY + s->conf->kcp_mtu);
	if (session->wbuf.data == NULL) {
		session_free(session);
		return NULL;
	}
	session->w_read = (struct ev_io *)util_malloc(sizeof(struct ev_io));
	if (session->w_read == NULL) {
		session_free(session);
		return NULL;
	}
	session->w_write = (struct ev_io *)util_malloc(sizeof(struct ev_io));
	if (session->w_write == NULL) {
		session_free(session);
		return NULL;
	}
	session->kcp = kcp_new(session, s->conf, conv);
	if (session->kcp == NULL) {
		session_free(session);
		return NULL;
	}
	clone_addr(&session->udp_remote, udp_remote);
	if (session->udp_remote.sa == NULL) {
		session_free(session);
		return NULL;
	}
	LOGF_D("session new: %p", (void *)session);
	return session;
}

void session_free(struct session *restrict s)
{
	LOGF_D("session free: %p", (void *)s);
	if (s->w_read != NULL) {
		ev_io_stop(s->server->loop, s->w_read);
		util_free(s->w_read);
		s->w_read = NULL;
	}
	if (s->w_write != NULL) {
		ev_io_stop(s->server->loop, s->w_write);
		util_free(s->w_write);
		s->w_write = NULL;
	}
	if (s->tcp_fd != -1) {
		if (close(s->tcp_fd) == -1) {
			LOG_PERROR("close fd");
		}
		s->tcp_fd = -1;
	}
	if (s->kcp != NULL) {
		ikcp_release(s->kcp);
		s->kcp = NULL;
	}
	if (s->rbuf.data != NULL) {
		s->rbuf = slice_free(s->rbuf);
	}
	if (s->wbuf.data != NULL) {
		s->rbuf = slice_free(s->wbuf);
	}
	if (s->udp_remote.sa != NULL) {
		util_free(s->udp_remote.sa);
		s->udp_remote.sa = NULL;
	}
	util_free(s);
}

void session_start(struct session *restrict s)
{
	LOGF_I("session [%08" PRIX32 "] start", (uint32_t)s->kcp->conv);
	// Initialize and start watchers to transfer data
	ev_io_init(s->w_read, read_cb, s->tcp_fd, EV_READ);
	s->w_read->data = s;
	ev_io_start(s->server->loop, s->w_read);
	ev_io_init(s->w_write, write_cb, s->tcp_fd, EV_WRITE);
	s->w_write->data = s;
	ev_io_start(s->server->loop, s->w_write);
}

void session_shutdown(struct session *restrict s)
{
	LOGF_V("session [%08" PRIX32 "] shutdown", (uint32_t)s->kcp->conv);
	if (s->w_read != NULL) {
		ev_io_stop(s->server->loop, s->w_read);
		util_free(s->w_read);
		s->w_read = NULL;
	}
	if (s->w_write != NULL) {
		ev_io_stop(s->server->loop, s->w_write);
		util_free(s->w_write);
		s->w_write = NULL;
	}
	if (s->tcp_fd != -1) {
		if (close(s->tcp_fd) == -1) {
			LOG_PERROR("close fd");
		}
		s->tcp_fd = -1;
	}
}

bool shutdown_iter(struct conv_table *restrict table, uint32_t conv,
		   void *session, void *restrict user, bool *delete)
{
	UNUSED(table);
	UNUSED(conv);
	UNUSED(user);
	session_free((struct session *)session);
	*delete = true;
	return true;
}

void session_close_all(struct conv_table *table)
{
	conv_iterate(table, shutdown_iter, NULL);
}
