/* kcptun-libev (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "event.h"
#include "obfs.h"
#include "pktqueue.h"
#include "server.h"
#include "session.h"
#include "sockutil.h"
#include "util.h"

#include "net/http.h"
#include "net/url.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
	struct http_message http_msg;
	char *http_nxt;
	struct ev_io w_read, w_write;
	struct ev_timer w_timeout;
	struct vbuffer *wbuf;
	struct {
		BUFFER_HDR;
		unsigned char data[HTTP_MAX_REQUEST];
	} rbuf;
};

static void http_ctx_free(struct http_ctx *restrict ctx)
{
	struct ev_loop *loop = ctx->loop;
	struct ev_io *restrict w_read = &ctx->w_read;
	ev_io_stop(loop, w_read);
	struct ev_io *restrict w_write = &ctx->w_write;
	ev_io_stop(loop, w_write);
	CLOSE_FD(ctx->fd);
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_stop(loop, w_timeout);
	UTIL_SAFE_FREE(ctx->wbuf);
	free(ctx);
}

void http_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_READ);

	struct server *restrict s = watcher->data;
	union sockaddr_max addr;
	socklen_t addrlen = sizeof(addr);
	const int fd = accept(watcher->fd, &addr.sa, &addrlen);
	if (fd < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return;
		}
		LOGE_F("accept: %s", strerror(err));
		/* sleep for a while, see listener_cb */
		ev_io_stop(loop, watcher);
		struct ev_timer *restrict w_timer = &s->listener.w_timer;
		if (!ev_is_active(w_timer)) {
			ev_timer_start(loop, w_timer);
		}
		return;
	}
	if (!socket_set_nonblock(fd)) {
		const int err = errno;
		LOGE_F("fcntl: %s", strerror(err));
		CLOSE_FD(fd);
		return;
	}
	struct http_ctx *restrict ctx = malloc(sizeof(struct http_ctx));
	if (ctx == NULL) {
		LOGOOM();
		CLOSE_FD(fd);
		return;
	}
	ctx->loop = loop;
	ctx->data = s;
	ctx->fd = fd;
	ctx->http_msg = (struct http_message){ 0 };
	ctx->http_nxt = NULL;
	BUF_INIT(ctx->rbuf, 0);
	ctx->wbuf = NULL;

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
	if (LOGLEVEL(VERBOSE)) {
		char addr_str[64];
		format_sa(&addr.sa, addr_str, sizeof(addr_str));
		LOG_F(VERBOSE, "http: accept %s", addr_str);
	}
}

static void http_serve(struct http_ctx *ctx);

void http_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_READ);

	struct http_ctx *restrict ctx = watcher->data;
	unsigned char *data = ctx->rbuf.data + ctx->rbuf.len;
	size_t cap = ctx->rbuf.cap - ctx->rbuf.len -
		     (size_t)1; /* for null-terminator */
	const ssize_t nrecv = recv(watcher->fd, data, cap, 0);
	if (nrecv < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return;
		}
		LOGE_F("recv: %s", strerror(err));
		http_ctx_free(ctx);
		return;
	}
	if (nrecv == 0) {
		http_ctx_free(ctx);
		return;
	}
	ctx->rbuf.len += nrecv;
	cap -= nrecv;

	ctx->rbuf.data[ctx->rbuf.len] = '\0';
	char *next = ctx->http_nxt;
	if (next == NULL) {
		next = (char *)ctx->rbuf.data;
		ctx->http_nxt = next;
	}
	struct http_message *restrict hdr = &ctx->http_msg;
	if (hdr->any.field1 == NULL) {
		next = http_parse(next, hdr);
		if (next == NULL) {
			LOGE("http: invalid request");
			http_ctx_free(ctx);
			return;
		}
		if (next == ctx->http_nxt) {
			if (cap == 0) {
				LOGE("http: request too large");
				http_ctx_free(ctx);
				return;
			}
			return;
		}
		const char http1[] = "HTTP/1.";
		if (strncmp(hdr->req.version, http1, sizeof(http1) - 1) != 0) {
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
		}
		if (next == ctx->http_nxt) {
			return;
		}
		ctx->http_nxt = next;
		if (key == NULL) {
			break;
		}
		LOGV_F("http: header %s: %s", key, value);
	}
	/* Connection: close */
	ev_io_stop(loop, watcher);
	http_serve(ctx);
}

static void http_ctx_write(struct http_ctx *restrict ctx)
{
	struct vbuffer *restrict wbuf = ctx->wbuf;
	unsigned char *data = wbuf->data;
	size_t nbsend = 0;
	size_t len = wbuf->len;
	while (len > 0) {
		const ssize_t nsend = send(ctx->fd, data, len, 0);
		if (nsend < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			LOGE_F("send: %s", strerror(err));
			http_ctx_free(ctx);
			return;
		}
		data += nsend;
		len -= nsend;
		nbsend += nsend;
	}
	wbuf->len -= nbsend;
	if (len > 0) {
		VBUF_CONSUME(wbuf, nbsend);
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
	CHECK_REVENTS(revents, EV_WRITE);
	http_ctx_write(watcher->data);
}

void http_timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	UNUSED(loop);
	CHECK_REVENTS(revents, EV_TIMER);
	http_ctx_free(watcher->data);
}

static void http_set_wbuf(struct http_ctx *restrict ctx, struct vbuffer *buf)
{
	VBUF_FREE(ctx->wbuf);
	ctx->wbuf = buf;
}

#define RESPHDR_WRITE(buf, code, hdr)                                          \
	do {                                                                   \
		char date_str[32];                                             \
		const size_t date_len = http_date(date_str, sizeof(date_str)); \
		const char *status = http_status((code));                      \
		if ((buf) != NULL) {                                           \
			(buf)->len = 0;                                        \
		}                                                              \
		(buf) = VBUF_APPENDF(                                          \
			(buf),                                                 \
			"HTTP/1.1 %" PRIu16 " %s\r\n"                          \
			"Date: %.*s\r\n"                                       \
			"Connection: close\r\n"                                \
			"%s\r\n",                                              \
			code, status ? status : "", (int)date_len, date_str,   \
			(hdr));                                                \
	} while (0)

#define RESPHDR_CODE(buf, code) RESPHDR_WRITE((buf), (code), "")

#define RESPHDR_POST(buf, code)                                                \
	RESPHDR_WRITE(                                                         \
		(buf), (code),                                                 \
		"Content-Type: text/plain; charset=utf-8\r\n"                  \
		"X-Content-Type-Options: nosniff\r\n")

#define RESPHDR_GET(buf, code)                                                 \
	RESPHDR_WRITE(                                                         \
		(buf), (code),                                                 \
		"Content-Type: text/plain; charset=utf-8\r\n"                  \
		"X-Content-Type-Options: nosniff\r\n"                          \
		"Cache-Control: no-store\r\n")

static void
http_resp_errpage(struct http_ctx *restrict ctx, const uint16_t code)
{
	struct vbuffer *restrict buf = VBUF_NEW(512);
	if (buf == NULL) {
		LOGOOM();
		return;
	}
	const int len = http_error((char *)buf->data, buf->cap, code);
	if (len <= 0) {
		/* can't generate error page, reply with code only */
		RESPHDR_CODE(buf, code);
		http_set_wbuf(ctx, buf);
		return;
	}
	buf->len = len;
	http_set_wbuf(ctx, buf);
}

static void
http_serve_stats(struct http_ctx *restrict ctx, struct url *restrict uri)
{
	if (uri->path != NULL) {
		http_resp_errpage(ctx, HTTP_NOT_FOUND);
		return;
	}
	const struct http_message *restrict hdr = &ctx->http_msg;
	bool banner = true;
	int state_level = STATE_CONNECTED;
	while (uri->query != NULL) {
		char *key, *value;
		if (!url_query_component(&uri->query, &key, &value)) {
			http_resp_errpage(ctx, HTTP_BAD_REQUEST);
			return;
		}
		if (strcmp(key, "banner") == 0) {
			if (strcmp(value, "no") == 0) {
				banner = false;
			}
		} else if (strcmp(key, "sessions") == 0) {
			if (strcmp(value, "0") == 0 ||
			    strcmp(value, "none") == 0) {
				state_level = -1;
			} else if (
				strcmp(value, "1") == 0 ||
				strcmp(value, "connected") == 0) {
				state_level = STATE_CONNECTED;
			} else if (
				strcmp(value, "2") == 0 ||
				strcmp(value, "active") == 0) {
				state_level = STATE_LINGER;
			} else if (
				strcmp(value, "3") == 0 ||
				strcmp(value, "all") == 0) {
				state_level = STATE_MAX;
			}
		}
	}

	struct vbuffer *restrict buf = VBUF_NEW(4000);
	if (buf == NULL) {
		LOGOOM();
		return;
	}
	bool stateless;
	if (strcmp(hdr->req.method, "GET") == 0) {
		RESPHDR_GET(buf, HTTP_OK);
		stateless = true;
	} else if (strcmp(hdr->req.method, "POST") == 0) {
		RESPHDR_POST(buf, HTTP_OK);
		stateless = false;
	} else {
		http_resp_errpage(ctx, HTTP_METHOD_NOT_ALLOWED);
		return;
	}

	if (banner) {
		buf = VBUF_APPENDSTR(
			buf, "" PROJECT_NAME " " PROJECT_VER "\n"
			     "  " PROJECT_HOMEPAGE "\n\n");
	}
	{
		const time_t server_time = time(NULL);
		char timestamp[32];
		(void)strftime(
			timestamp, sizeof(timestamp), "%FT%T%z",
			localtime(&server_time));
		buf = VBUF_APPENDF(buf, "server time: %s\n\n", timestamp);
	}

	struct server *restrict s = ctx->data;
	if (stateless) {
		buf = server_stats_const(s, buf, state_level);
	} else {
		buf = server_stats(s, buf, state_level);
	}

#if WITH_OBFS
	struct obfs *restrict obfs = s->pkt.queue->obfs;
	if (obfs != NULL) {
		buf = VBUF_APPENDSTR(buf, "\n");
		if (stateless) {
			buf = obfs_stats_const(obfs, buf);
		} else {
			buf = obfs_stats(obfs, buf);
		}
	}
#endif
#if MCACHE_STATS
	if (msgpool != NULL) {
		static size_t last_hit = 0;
		static size_t last_query = 0;
		const size_t hit = msgpool->hit - last_hit;
		const size_t query = msgpool->query - last_query;
		buf = VBUF_APPENDF(
			buf,
			"msgpool: %zu/%zu; %zu hit, %zu miss (%.1lf%%); total %zu hit, %zu miss (%.1lf%%)\n",
			msgpool->num_elem, msgpool->cache_size, hit,
			query - hit, (double)hit / ((double)query) * 100.0,
			msgpool->hit, msgpool->query - msgpool->hit,
			(double)msgpool->hit / ((double)msgpool->query) *
				100.0);
		last_hit = msgpool->hit;
		last_query = msgpool->query;
	}
#endif

	http_set_wbuf(ctx, buf);
}

static void http_handle_request(struct http_ctx *restrict ctx)
{
	const struct http_message *restrict hdr = &ctx->http_msg;
	struct url uri;
	LOGV_F("api: serve uri `%s'", hdr->req.url);
	if (!url_parse(hdr->req.url, &uri)) {
		LOGW("api: failed parsing url");
		http_resp_errpage(ctx, HTTP_BAD_REQUEST);
		return;
	}
	char *segment;
	if (!url_path_segment(&uri.path, &segment)) {
		http_resp_errpage(ctx, HTTP_BAD_REQUEST);
		return;
	}
	if (strcmp(segment, "stats") == 0) {
		http_serve_stats(ctx, &uri);
		return;
	}
	if (strcmp(segment, "healthy") == 0) {
		if (uri.path != NULL) {
			http_resp_errpage(ctx, HTTP_NOT_FOUND);
			return;
		}
		struct vbuffer *restrict buf = VBUF_NEW(512);
		if (buf == NULL) {
			LOGOOM();
			return;
		}
		RESPHDR_CODE(buf, HTTP_OK);
		http_set_wbuf(ctx, buf);
		return;
	}
	http_resp_errpage(ctx, HTTP_NOT_FOUND);
}

void http_serve(struct http_ctx *restrict ctx)
{
	http_handle_request(ctx);
	if (ctx->wbuf == NULL) {
		http_ctx_free(ctx);
		return;
	}
	http_ctx_write(ctx);
}
