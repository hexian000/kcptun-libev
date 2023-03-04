/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "event.h"
#include "event_impl.h"
#include "utils/slog.h"
#include "utils/strbuilder.h"
#include "net/http.h"
#include "util.h"
#include "server.h"
#include "pktqueue.h"
#include "nonce.h"
#include "obfs.h"

#include <ev.h>

#include <unistd.h>
#include <strings.h>
#include <sys/socket.h>

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
	struct ev_loop *loop;
	void *data;
	int fd;
	struct ev_io w_read, w_write;
	struct ev_timer w_timeout;
	unsigned char rbuf[HTTP_MAX_REQUEST];
	size_t rlen, rcap;
	unsigned char *wbuf;
	size_t wlen, wcap;
	struct http_message http_msg;
	char *http_nxt;
};

static void http_ctx_free(struct http_ctx *restrict ctx)
{
	struct ev_loop *loop = ctx->loop;
	struct ev_io *restrict w_read = &ctx->w_read;
	ev_io_stop(loop, w_read);
	struct ev_io *restrict w_write = &ctx->w_write;
	ev_io_stop(loop, w_write);
	(void)close(ctx->fd);
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_stop(loop, w_timeout);
	UTIL_SAFE_FREE(ctx->wbuf);
	free(ctx);
}

void http_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct server *restrict s = watcher->data;
	sockaddr_max_t m_sa;
	socklen_t len = sizeof(m_sa);
	const int fd = accept(watcher->fd, &m_sa.sa, &len);
	if (!socket_set_nonblock(fd)) {
		const int err = errno;
		LOGE_F("fcntl: %s", strerror(err));
		(void)close(fd);
		return;
	}
	struct http_ctx *restrict ctx = malloc(sizeof(struct http_ctx));
	if (ctx == NULL) {
		LOGOOM();
		if (close(fd) != 0) {
			const int err = errno;
			LOGE_F("close: %s", strerror(err));
		}
		return;
	}
	*ctx = (struct http_ctx){
		.loop = s->loop,
		.data = s,
		.fd = fd,
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

static void http_serve(struct http_ctx *ctx, struct http_message *hdr);

void http_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct http_ctx *restrict ctx = watcher->data;
	unsigned char *buf = ctx->rbuf + ctx->rlen;
	size_t cap = ctx->rcap - ctx->rlen - 1; /* for null-terminator */
	const ssize_t nrecv = recv(watcher->fd, buf, cap, 0);
	if (nrecv < 0) {
		const int err = errno;
		if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR ||
		    err == ENOMEM) {
			return;
		}
		LOGE_F("recv: %s", strerror(err));
		http_ctx_free(ctx);
		return;
	} else if (nrecv == 0) {
		http_ctx_free(ctx);
		return;
	}
	ctx->rlen += nrecv;
	cap -= nrecv;

	ctx->rbuf[ctx->rlen] = '\0';
	char *next = ctx->http_nxt;
	if (next == NULL) {
		next = (char *)ctx->rbuf;
		ctx->http_nxt = next;
	}
	struct http_message *restrict hdr = &ctx->http_msg;
	if (hdr->any.field1 == NULL) {
		next = http_parse(next, hdr);
		if (next == NULL) {
			LOGE("http: invalid request");
			http_ctx_free(ctx);
			return;
		} else if (next == ctx->http_nxt) {
			if (cap == 0) {
				LOGE("http: request too large");
				http_ctx_free(ctx);
				return;
			}
			return;
		}
		if (strncmp(hdr->req.version, "HTTP/1.", 7) != 0) {
			LOGE_F("http: unsupported protocol %s",
			       hdr->req.version);
			http_ctx_free(ctx);
			return;
		}
		LOGV_F("http: request %s %s %s", hdr->req.method, hdr->req.url,
		       hdr->req.version);
		ctx->http_nxt = next;
	}
	for (;;) {
		char *key, *value;
		next = http_parsehdr(next, &key, &value);
		if (next == NULL) {
			LOGE("http: invalid header");
			http_ctx_free(ctx);
			return;
		} else if (next == ctx->http_nxt) {
			return;
		}
		ctx->http_nxt = next;
		if (key == NULL) {
			break;
		}
		LOGV_F("http: header %s: %s", key, value);
	}
	/* HTTP/1.0 only, close after serve */
	ev_io_stop(loop, watcher);
	http_serve(ctx, hdr);
}

static void http_ctx_write(struct http_ctx *restrict ctx)
{
	unsigned char *buf = ctx->wbuf;
	size_t len = ctx->wlen;
	while (len > 0) {
		const ssize_t nsend = send(ctx->fd, buf, len, 0);
		if (nsend < 0) {
			const int err = errno;
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == EINTR || err == ENOMEM) {
				break;
			}
			LOGE_F("send: %s", strerror(err));
			http_ctx_free(ctx);
			return;
		}
		buf += nsend;
		len -= nsend;
	}
	ctx->wlen = len;
	if (len > 0) {
		memmove(ctx->wbuf, buf, len);
		struct ev_io *restrict w_write = &ctx->w_write;
		if (!ev_is_active(w_write)) {
			ev_io_start(ctx->loop, w_write);
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

static void http_set_wbuf(
	struct http_ctx *restrict ctx, unsigned char *buf, const size_t len,
	const size_t cap)
{
	UTIL_SAFE_FREE(ctx->wbuf);
	ctx->wbuf = buf;
	ctx->wcap = cap;
	ctx->wlen = len;
}

static void http_write_error(struct http_ctx *restrict ctx, const uint16_t code)
{
	const size_t cap = 512;
	unsigned char *buf = malloc(cap);
	if (buf == NULL) {
		http_ctx_free(ctx);
		return;
	}
	const size_t len = http_error((char *)buf, cap, code);
	http_set_wbuf(ctx, buf, len, cap);
	http_ctx_write(ctx);
}

static struct strbuilder http_resp_txt(const uint16_t code)
{
	struct strbuilder sb = { 0 };
	char date_str[32];
	size_t date_len = http_date(date_str, sizeof(date_str));
	strbuilder_appendf(
		&sb, 4096,
		"HTTP/1.0 %" PRIu16 " %s\r\n"
		"Date: %.*s\r\n"
		"Connection: close\r\n"
		"Content-type: text/plain\r\n\r\n",
		code, http_status(code), (int)date_len, date_str);
	return sb;
}

static void http_serve_stats(struct http_ctx *restrict ctx)
{
	struct strbuilder sb = http_resp_txt(HTTP_OK);

	struct server *restrict s = ctx->data;
	server_stats(s, &sb);
	server_sample(s);
#if WITH_OBFS
	struct obfs *restrict obfs = s->pkt.queue->obfs;
	if (obfs != NULL) {
		obfs_stats(obfs, &sb);
		obfs_sample(obfs);
	}
#endif
#if MCACHE_STATS
	if (msgpool != NULL) {
		static size_t last_hit = 0;
		static size_t last_query = 0;
		const size_t hit = msgpool->hit - last_hit;
		const size_t query = msgpool->query - last_query;
		strbuilder_appendf(
			&sb, 256,
			"msgpool: %zu/%zu; %zu hit, %zu miss (%.1lf%%); total %zu hit, %zu miss (%.1lf%%)\n",
			msgpool->n, msgpool->cache_size, hit, query - hit,
			(double)hit / ((double)query) * 100.0, msgpool->hit,
			msgpool->query - msgpool->hit,
			(double)msgpool->hit / ((double)msgpool->query) *
				100.0);
		last_hit = msgpool->hit;
		last_query = msgpool->query;
	}
#endif

	http_set_wbuf(ctx, (unsigned char *)sb.buf, sb.len, sb.cap);
	http_ctx_write(ctx);
}

void http_serve(struct http_ctx *restrict ctx, struct http_message *restrict hdr)
{
	if (strcasecmp(hdr->req.method, "GET") != 0) {
		http_write_error(ctx, HTTP_BAD_REQUEST);
		return;
	}
	char *url = hdr->req.url;
	if (strcmp(url, "/stats") == 0) {
		LOGV("http: serve /stats");
		http_serve_stats(ctx);
		return;
	}
	if (strcmp(url, "/healthy") == 0) {
		LOGV("http: serve /healthy");
		struct strbuilder sb = http_resp_txt(HTTP_OK);
		http_set_wbuf(ctx, (unsigned char *)sb.buf, sb.len, sb.cap);
		http_ctx_write(ctx);
		return;
	}
	http_write_error(ctx, HTTP_NOT_FOUND);
}
