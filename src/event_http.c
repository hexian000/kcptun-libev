#include "event.h"
#include "event_impl.h"
#include "session.h"
#include "slog.h"
#include "util.h"
#include "strbuilder.h"
#include "server.h"
#include "pktqueue.h"
#include "serialize.h"
#include "nonce.h"
#include "http.h"
#include "obfs.h"

#include <ev.h>

#include <unistd.h>
#include <sys/socket.h>

#include <assert.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static void
http_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
http_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
http_timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);

#define HTTP_MAX_REQUEST 4096

struct http_ctx {
	struct server *server;
	int fd;
	ev_tstamp created;
	struct ev_io w_read, w_write;
	struct ev_timer w_timeout;
	unsigned char rbuf[HTTP_MAX_REQUEST];
	size_t rlen, rcap;
	unsigned char *wbuf;
	size_t wlen, wcap;
};

static void http_ctx_free(struct http_ctx *restrict ctx)
{
	struct ev_loop *loop = ctx->server->loop;
	struct ev_io *restrict w_read = &ctx->w_read;
	ev_io_stop(loop, w_read);
	struct ev_io *restrict w_write = &ctx->w_write;
	ev_io_stop(loop, w_write);
	(void)close(ctx->fd);
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_stop(loop, w_timeout);
	util_free(ctx->wbuf);
	util_free(ctx);
}

void http_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct server *restrict s = watcher->data;
	sockaddr_max_t m_sa;
	socklen_t len = sizeof(m_sa);
	const int fd = accept(watcher->fd, &m_sa.sa, &len);
	if (socket_setup(fd)) {
		LOGE_PERROR("fcntl");
		if (close(fd) != 0) {
			LOGW_PERROR("close");
		}
		return;
	}
	struct http_ctx *restrict ctx = util_malloc(sizeof(struct http_ctx));
	if (ctx == NULL) {
		LOGOOM();
		if (close(fd) != 0) {
			LOGW_PERROR("close");
		}
		return;
	}
	*ctx = (struct http_ctx){
		.server = s,
		.fd = fd,
		.created = ev_now(loop),
		.rcap = HTTP_MAX_REQUEST,
	};
	struct ev_io *restrict w_read = &ctx->w_read;
	ev_io_init(w_read, http_read_cb, fd, EV_READ);
	w_read->data = ctx;
	ev_io_start(loop, w_read);
	struct ev_io *restrict w_write = &ctx->w_write;
	ev_io_init(w_write, http_write_cb, fd, EV_WRITE);
	w_write->data = ctx;
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_init(w_timeout, http_timeout_cb, 15.0, 0.0);
	w_timeout->data = ctx;
	ev_timer_start(loop, w_timeout);
	if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
		char addr_str[64];
		format_sa(&m_sa.sa, addr_str, sizeof(addr_str));
		LOGV_F("http: accept %s", addr_str);
	}
}

static void http_serve(struct http_ctx *ctx, struct http_header *hdr);

void http_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct http_ctx *restrict ctx = watcher->data;
	unsigned char *buf = ctx->rbuf + ctx->rlen;
	size_t cap = ctx->rcap - ctx->rlen - 1; /* for null-terminator */
	const ssize_t nrecv = recv(watcher->fd, buf, cap, 0);
	if (nrecv < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ||
		    errno == ENOMEM) {
			return;
		}
		LOGE_PERROR("http");
		http_ctx_free(ctx);
		return;
	} else if (nrecv == 0) {
		http_ctx_free(ctx);
		return;
	}
	ctx->rlen += nrecv;
	cap -= nrecv;

	const size_t peek = http_peek((char *)ctx->rbuf, ctx->rlen);
	if (peek == 0) {
		if (cap == 0) {
			LOGE("http: request too large");
			http_ctx_free(ctx);
		}
		return;
	}
	ctx->rbuf[ctx->rlen] = '\0';
	struct http_header hdr;
	const size_t n = http_parse((char *)ctx->rbuf, &hdr, NULL, NULL);
	if (n == 0 || strncmp(hdr.field3, "HTTP/1.", 7) != 0) {
		LOGE("http: failed parsing request");
		http_ctx_free(ctx);
		return;
	}
	/* HTTP/1.0 only, close after serve */
	ev_io_stop(loop, watcher);
	http_serve(ctx, &hdr);
}

static void http_ctx_write(struct http_ctx *restrict ctx)
{
	unsigned char *buf = ctx->wbuf;
	size_t nbsend = 0;
	size_t len = ctx->wlen;
	while (len > 0) {
		const ssize_t nsend = send(ctx->fd, buf, len, 0);
		if (nsend < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == EINTR || errno == ENOMEM) {
				break;
			}
			LOGE_PERROR("http");
			http_ctx_free(ctx);
			return;
		}
		len -= nsend;
		nbsend += nsend;
	}
	ctx->wlen = len;
	if (len > 0) {
		memmove(buf, buf + nbsend, len);
		struct ev_io *restrict w_write = &ctx->w_write;
		if (!ev_is_active(w_write)) {
			ev_io_start(ctx->server->loop, w_write);
		}
		return;
	}
	http_ctx_free(ctx);
}

void http_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	UNUSED(loop);
	CHECK_EV_ERROR(revents);
	http_ctx_write(watcher->data);
}

void http_timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	UNUSED(loop);
	UNUSED(revents);
	http_ctx_free(watcher->data);
}

static void http_write_error(struct http_ctx *restrict ctx, const uint16_t code)
{
	const size_t cap = 4096;
	unsigned char *buf = util_malloc(4096);
	if (buf == NULL) {
		http_ctx_free(ctx);
		return;
	}
	const size_t len = http_error((char *)buf, cap, code);
	ctx->wbuf = buf;
	ctx->wcap = cap;
	ctx->wlen = len;
	http_ctx_write(ctx);
}

static void http_serve_stats(struct http_ctx *restrict ctx)
{
	struct strbuilder sb = { 0 };
	strbuilder_reserve(&sb, 16384);
	char date_str[32];
	size_t date_len = http_date(date_str, sizeof(date_str));
	strbuilder_appendf(
		&sb, 4096,
		"HTTP/1.0 %" PRIu16 " %s\r\n"
		"Date: %*s\r\n"
		"Connection: close\r\n"
		"Content-type: text/plain\r\n\r\n",
		HTTP_OK, http_status(HTTP_OK), (int)date_len, date_str);

	struct server *restrict s = ctx->server;
	server_stats(ctx->server, &sb);
#if WITH_OBFS
	struct obfs *restrict obfs = s->pkt.queue->obfs;
	if (obfs != NULL) {
		obfs_stats(obfs, &sb);
	}
#endif
	strbuilder_appendch(&sb, '\n');

	ctx->wlen = sb.len;
	ctx->wcap = sb.cap;
	ctx->wbuf = (unsigned char *)sb.buf;
	http_ctx_write(ctx);
}

void http_serve(struct http_ctx *restrict ctx, struct http_header *restrict hdr)
{
	if (strcasecmp(hdr->field1, "GET") != 0) {
		http_write_error(ctx, HTTP_NOT_IMPLEMENTED);
		return;
	}
	if (strcmp(hdr->field2, "/stats") == 0) {
		http_serve_stats(ctx);
		return;
	}
	if (strcmp(hdr->field2, "/healthy") == 0) {
		char date_str[32];
		const size_t date_len = http_date(date_str, sizeof(date_str));
		ctx->wlen = snprintf(
			(char *)ctx->wbuf, ctx->wcap,
			"HTTP/1.0 %" PRIu16 " %s\r\n"
			"Date: %*s\r\n"
			"Connection: close\r\n"
			"Content-type: text/plain\r\n\r\n"
			"%s",
			HTTP_OK, http_status(HTTP_OK), (int)date_len, date_str,
			"OK");
		http_ctx_write(ctx);
		return;
	}
	http_write_error(ctx, HTTP_NOT_FOUND);
}
