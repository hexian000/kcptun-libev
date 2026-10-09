/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"
#include "event.h"
#include "pktqueue.h"
#include "server.h"
#include "session.h"
#include "util.h"

#include "algo/hashtable.h"
#include "os/socket.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#if MCACHE_STATS
#include "utils/mcache.h"
#endif
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

static bool fail_alloc, fail_setup, fail_read, fail_write;
static size_t allocations;
static void *contexts[128];

#define TEST_HTTP_LIMIT 32

static void *test_malloc(const size_t size)
{
	allocations++;
	if (fail_alloc) {
		fail_alloc = false;
		return NULL;
	}
	void *ptr = malloc(size);
	if (ptr != NULL) {
		for (size_t i = 0; i < 128; i++) {
			if (contexts[i] == NULL) {
				contexts[i] = ptr;
				return ptr;
			}
		}
		FAILMSG("test context registry full");
	}
	return ptr;
}

static void test_free(void *ptr)
{
	for (size_t i = 0; i < 128; i++) {
		if (contexts[i] == ptr) {
			contexts[i] = NULL;
			break;
		}
	}
	free(ptr);
}

static bool test_nonblock(const int fd)
{
	if (fail_setup) {
		fail_setup = false;
		socket_close(fd);
		return false;
	}
	return socket_nonblock_or_close(fd);
}

static ssize_t test_recv(int fd, void *buf, size_t len, int flags)
{
	if (fail_read) {
		fail_read = false;
		errno = EIO;
		return -1;
	}
	return recv(fd, buf, len, flags);
}

static ssize_t test_send(int fd, const void *buf, size_t len, int flags)
{
	if (fail_write) {
		fail_write = false;
		errno = EIO;
		return -1;
	}
	return send(fd, buf, len, flags);
}

#define malloc test_malloc
#define free test_free
#define socket_nonblock_or_close test_nonblock
#define recv test_recv
#define send test_send
#include "event_http.c"
#undef malloc
#undef free
#undef socket_nonblock_or_close
#undef recv
#undef send

struct fixture {
	struct server server;
	struct sockaddr_in addr;
};

static void fixture_init(struct fixture *f, struct ev_loop *loop)
{
	*f = (struct fixture){ .server.loop = loop };
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(fd >= 0);
	CHECK(socket_nonblock_or_close(fd));
	f->addr = (struct sockaddr_in){ .sin_family = AF_INET,
					.sin_addr.s_addr =
						htonl(INADDR_LOOPBACK) };
	CHECK(bind(fd, (struct sockaddr *)&f->addr, sizeof(f->addr)) == 0);
	CHECK(listen(fd, SOMAXCONN) == 0);
	socklen_t len = sizeof(f->addr);
	CHECK(getsockname(fd, (struct sockaddr *)&f->addr, &len) == 0);
	f->server.listener.fd_http = fd;
	ev_io *w = &f->server.listener.w_accept_http;
	ev_io_init(w, http_accept_cb, fd, EV_READ);
	w->data = &f->server;
}

static size_t active(const struct fixture *f)
{
	size_t count = 0;
	for (size_t i = 0; i < 128; i++) {
		const struct http_ctx *ctx = contexts[i];
		count += ctx != NULL && ctx->data == &f->server;
	}
	return count;
}

static struct http_ctx *first_context(const struct fixture *f)
{
	for (size_t i = 0; i < 128; i++) {
		struct http_ctx *ctx = contexts[i];
		if (ctx != NULL && ctx->data == &f->server) {
			return ctx;
		}
	}
	FAILMSG("missing test context");
}

static void stop_contexts(struct fixture *f)
{
#ifdef HTTP_MAX_CONNECTIONS
	http_stop(&f->server);
#else
	/* Keep the admission regression buildable against the pre-limit code. */
	for (size_t i = 0; i < 128; i++) {
		struct http_ctx *ctx = contexts[i];
		if (ctx != NULL && ctx->data == &f->server) {
			http_ctx_free(ctx);
		}
	}
#endif /* HTTP_MAX_CONNECTIONS */
}

static int connect_client(struct fixture *f)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(fd >= 0);
	CHECK(connect(fd, (struct sockaddr *)&f->addr, sizeof(f->addr)) == 0);
	http_accept_cb(
		f->server.loop, &f->server.listener.w_accept_http, EV_READ);
	return fd;
}

static void assert_closed(const int fd)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	CHECK(poll(&pfd, 1, 100) == 1);
	char byte;
	CHECK(recv(fd, &byte, 1, 0) == 0);
}

static void admission_limit(struct ev_loop *loop)
{
	struct fixture first, second;
	fixture_init(&first, loop);
	fixture_init(&second, loop);
	int clients[TEST_HTTP_LIMIT];
	for (size_t i = 0; i < TEST_HTTP_LIMIT; i++) {
		clients[i] = connect_client(&first);
		CHECK(active(&first) == i + 1);
	}
	const size_t before = allocations;
	const int excess = connect_client(&first);
	assert_closed(excess);
	CHECK(allocations == before);
	CHECK(active(&first) == TEST_HTTP_LIMIT);
	const int independent = connect_client(&second);
	CHECK(active(&second) == 1);
	CHECK(active(&first) == TEST_HTTP_LIMIT);

	/* An expired context restores admission while the other slots stay busy. */
	struct http_ctx *ctx = first_context(&first);
	ev_feed_event(loop, &ctx->w_timeout, EV_TIMER);
	ev_run(loop, EVRUN_NOWAIT);
	CHECK(active(&first) == TEST_HTTP_LIMIT - 1);
	assert_closed(clients[0]);
	const int replacement = connect_client(&first);
	CHECK(active(&first) == TEST_HTTP_LIMIT);
	stop_contexts(&first);
	stop_contexts(&first);
	CHECK(active(&first) == 0);
	for (size_t i = 0; i < TEST_HTTP_LIMIT; i++) {
		assert_closed(clients[i]);
		socket_close(clients[i]);
	}
	assert_closed(replacement);
	stop_contexts(&second);
	CHECK(active(&second) == 0);
	assert_closed(independent);
	socket_close(first.server.listener.fd_http);
	socket_close(second.server.listener.fd_http);
	socket_close(excess);
	socket_close(independent);
	socket_close(replacement);
	puts("admission_limit: 32 admitted, excess closed without allocation, independent server, timeout/repeated teardown release passed");
}

static void cleanup_paths(struct ev_loop *loop)
{
	struct fixture f;
	fixture_init(&f, loop);
	const char request[] = "GET /missing HTTP/1.0\r\n\r\n";
	int fd = connect_client(&f);
	CHECK(send(fd, request, sizeof(request) - 1, 0) == sizeof(request) - 1);
	struct http_ctx *ctx = first_context(&f);
	http_read_cb(loop, &ctx->w_read, EV_READ);
	CHECK(active(&f) == 0);
	char response[512];
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	CHECK(poll(&pfd, 1, 100) == 1);
	const ssize_t n = recv(fd, response, sizeof(response) - 1, 0);
	CHECK(n > 0);
	response[n] = '\0';
	CHECK(strncmp(response, "HTTP/1.1 404", 12) == 0);
	socket_close(fd);

	socket_close(f.server.listener.fd_http);
	puts("completion: normal HTTP response releases capacity passed");
}

static void cleanup_errors(struct ev_loop *loop)
{
	struct fixture f;
	fixture_init(&f, loop);
	int fd = connect_client(&f);
	struct http_ctx *ctx = first_context(&f);
	fail_read = true;
	http_read_cb(loop, &ctx->w_read, EV_READ);
	CHECK(active(&f) == 0);
	assert_closed(fd);
	socket_close(fd);

	fd = connect_client(&f);
	ctx = first_context(&f);
	ctx->wbuf = VBUF_NEW(16);
	CHECK(ctx->wbuf != NULL);
	VBUF_APPENDSTR(ctx->wbuf, "response");
	fail_write = true;
	http_ctx_write(ctx);
	CHECK(active(&f) == 0);
	assert_closed(fd);
	socket_close(fd);

	fd = connect_client(&f);
	ctx = first_context(&f);
	CHECK(shutdown(fd, SHUT_WR) == 0);
	http_read_cb(loop, &ctx->w_read, EV_READ);
	CHECK(active(&f) == 0);
	assert_closed(fd);
	socket_close(fd);

	fd = connect_client(&f);
	ctx = first_context(&f);
	const char invalid[] = "invalid request\r\n";
	CHECK(send(fd, invalid, sizeof(invalid) - 1, 0) == sizeof(invalid) - 1);
	http_read_cb(loop, &ctx->w_read, EV_READ);
	CHECK(active(&f) == 0);
	socket_close(fd);

	fd = connect_client(&f);
	CHECK(active(&f) == 1);
	stop_contexts(&f);
	assert_closed(fd);
	socket_close(fd);
	socket_close(f.server.listener.fd_http);
	puts("cleanup_errors: read/write errors, EOF, malformed request and resumed admission passed");
}

static void setup_failures(struct ev_loop *loop)
{
	struct fixture f;
	fixture_init(&f, loop);
	fail_setup = true;
	int fd = connect_client(&f);
	assert_closed(fd);
	CHECK(active(&f) == 0);
	socket_close(fd);
	fail_alloc = true;
	fd = connect_client(&f);
	assert_closed(fd);
	CHECK(active(&f) == 0);
	socket_close(fd);
	fd = connect_client(&f);
	CHECK(active(&f) == 1);
	stop_contexts(&f);
	assert_closed(fd);
	socket_close(fd);
	socket_close(f.server.listener.fd_http);
	puts("setup_failures: nonblocking setup and allocation failures reserve no capacity, resumed admission passed");
}

static void check_date(const char *response)
{
	const char *date = strstr(response, "\r\nDate: ");
	CHECK(date != NULL);
	date += strlen("\r\nDate: ");
	const char *end = strstr(date, "\r\n");
	CHECK(end != NULL && end - date == 29);
	CHECK(date[3] == ',' && date[4] == ' ' && date[7] == ' ' &&
	      date[11] == ' ' && date[16] == ' ' && date[19] == ':' &&
	      date[22] == ':' && memcmp(date + 25, " GMT", 4) == 0);
	const size_t digits[] = { 5, 6, 12, 13, 14, 15, 17, 18, 20, 21, 23, 24 };
	for (size_t i = 0; i < sizeof(digits) / sizeof(digits[0]); i++) {
		CHECK(date[digits[i]] >= '0' && date[digits[i]] <= '9');
	}
}

static void read_response(const int fd, char *response, const size_t capacity)
{
	size_t used = 0;
	for (;;) {
		CHECK(used < capacity - 1);
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		CHECK(poll(&pfd, 1, 100) == 1);
		const ssize_t nr =
			recv(fd, response + used, capacity - 1 - used, 0);
		CHECK(nr >= 0);
		if (nr == 0) {
			break;
		}
		used += (size_t)nr;
	}
	response[used] = '\0';
	CHECK(strlen(response) == used);
}

/* Read to EOF so a HEAD assertion also detects bytes after the header. */
static char *request_response(
	struct fixture *f, const char *method, const char *target,
	const char *status, char *response, const size_t capacity)
{
	char request[256];
	const int n = snprintf(
		request, sizeof(request),
		"%s %s HTTP/1.1\r\nHost: localhost\r\n\r\n", method, target);
	CHECK(n > 0 && (size_t)n < sizeof(request));
	const int fd = connect_client(f);
	CHECK(send(fd, request, (size_t)n, 0) == n);
	struct http_ctx *ctx = first_context(f);
	http_read_cb(f->server.loop, &ctx->w_read, EV_READ);
	CHECK(active(f) == 0);
	read_response(fd, response, capacity);
	socket_close(fd);
	CHECK(strncmp(response, status, strlen(status)) == 0);
	char *body = strstr(response, "\r\n\r\n");
	CHECK(body != NULL);
	const char *connection = strstr(response, "\r\nConnection: close\r\n");
	CHECK(connection != NULL && connection < body);
	check_date(response);
	return body + 4;
}

static void check_plain_response(const char *response, const bool cache)
{
	CHECK(strstr(response,
		     "\r\nContent-Type: text/plain; charset=utf-8\r\n") !=
	      NULL);
	CHECK(strstr(response, "\r\nX-Content-Type-Options: nosniff\r\n") !=
	      NULL);
	CHECK((strstr(response, "\r\nCache-Control: no-store\r\n") != NULL) ==
	      cache);
}

static void health_responses(struct ev_loop *loop)
{
	struct fixture f;
	fixture_init(&f, loop);
	struct config conf = { .mode = MODE_SERVER };
	f.server.conf = &conf;
	f.server.timeout = 10;
	const ev_tstamp now = ev_now(loop);
	const struct {
		int mode;
		bool connected;
		ev_tstamp last;
		const char *status, *body;
	} cases[] = {
		{ MODE_SERVER, false, TSTAMP_NIL, "HTTP/1.1 200 OK\r\n",
		  "healthy\n" },
		{ MODE_RENDEZVOUS, false, TSTAMP_NIL, "HTTP/1.1 200 OK\r\n",
		  "healthy\n" },
		{ MODE_CLIENT, false, TSTAMP_NIL,
		  "HTTP/1.1 503 Service Unavailable\r\n",
		  "peer unreachable\n" },
		{ MODE_CLIENT | MODE_RENDEZVOUS, false, now,
		  "HTTP/1.1 503 Service Unavailable\r\n",
		  "rendezvous pending\n" },
		{ MODE_CLIENT | MODE_RENDEZVOUS, true, TSTAMP_NIL,
		  "HTTP/1.1 503 Service Unavailable\r\n",
		  "peer unreachable\n" },
		{ MODE_CLIENT, true, now - 11,
		  "HTTP/1.1 503 Service Unavailable\r\n",
		  "peer not responding (11s)\n" },
		{ MODE_CLIENT, true, now - 10, "HTTP/1.1 200 OK\r\n",
		  "healthy (peer seen 10s ago)\n" },
		{ MODE_CLIENT | MODE_RENDEZVOUS, true, now,
		  "HTTP/1.1 200 OK\r\n", "healthy (peer seen 0s ago)\n" },
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		conf.mode = cases[i].mode;
		f.server.pkt.connected = cases[i].connected;
		f.server.pkt.last_recv_time = cases[i].last;
		char response[2048];
		const char *body = request_response(
			&f, "GET", "/healthy", cases[i].status, response,
			sizeof(response));
		check_plain_response(response, true);
		CHECK(strcmp(body, cases[i].body) == 0);
		body = request_response(
			&f, "HEAD", "/healthy", cases[i].status, response,
			sizeof(response));
		check_plain_response(response, true);
		CHECK(*body == '\0');
	}
	socket_close(f.server.listener.fd_http);
	puts("health_responses: GET/HEAD server, broker, unreachable, pending, stale and timeout boundary passed");
}

static void rejected_routes(struct ev_loop *loop)
{
	struct fixture f;
	fixture_init(&f, loop);
	const struct {
		const char *method, *target, *status, *allow;
	} cases[] = {
		{ "POST", "/healthy", "HTTP/1.1 405 Method Not Allowed\r\n",
		  "GET, HEAD" },
		{ "OPTIONS", "/healthy", "HTTP/1.1 405 Method Not Allowed\r\n",
		  "GET, HEAD" },
		{ "PUT", "/stats", "HTTP/1.1 405 Method Not Allowed\r\n",
		  "GET, POST" },
		{ "HEAD", "/stats", "HTTP/1.1 405 Method Not Allowed\r\n",
		  "GET, POST" },
		{ "GET", "/missing", "HTTP/1.1 404 Not Found\r\n", NULL },
		{ "HEAD", "/missing", "HTTP/1.1 404 Not Found\r\n", NULL },
		{ "GET", "/healthy/details", "HTTP/1.1 404 Not Found\r\n",
		  NULL },
		{ "HEAD", "/healthy/details", "HTTP/1.1 404 Not Found\r\n",
		  NULL },
		{ "GET", "/stats/", "HTTP/1.1 404 Not Found\r\n", NULL },
		{ "GET", "/stats/details", "HTTP/1.1 404 Not Found\r\n", NULL },
		{ "HEAD", "/stats/details", "HTTP/1.1 404 Not Found\r\n",
		  NULL },
		{ "GET", "/%zz", "HTTP/1.1 400 Bad Request\r\n", NULL },
		{ "HEAD", "/%zz", "HTTP/1.1 400 Bad Request\r\n", NULL },
		{ "GET", "/stats?%zz=1", "HTTP/1.1 400 Bad Request\r\n", NULL },
		{ "GET", "/stats?nobanner=%zz", "HTTP/1.1 400 Bad Request\r\n",
		  NULL },
		{ "HEAD", "/stats?nobanner=%zz", "HTTP/1.1 400 Bad Request\r\n",
		  NULL },
		{ "GET", "/stats#%zz", "HTTP/1.1 400 Bad Request\r\n", NULL },
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		char response[2048];
		const char *body = request_response(
			&f, cases[i].method, cases[i].target, cases[i].status,
			response, sizeof(response));
		if (cases[i].allow != NULL) {
			char allow[64];
			(void)snprintf(
				allow, sizeof(allow), "\r\nAllow: %s\r\n",
				cases[i].allow);
			CHECK(strstr(response, allow) != NULL);
			CHECK(*body == '\0');
		} else if (strcmp(cases[i].method, "HEAD") == 0) {
			CHECK(*body == '\0');
		} else {
			CHECK(strstr(body, "<HTML>") == body);
			CHECK(strstr(body, "</BODY></HTML>\n") != NULL);
		}
	}
	socket_close(f.server.listener.fd_http);
	puts("rejected_routes: Allow, HEAD 400/404/405, nested paths and malformed path/query/fragment passed");
}

static void stats_get(struct fixture *f)
{
	const struct link_stats snapshot = f->server.last_stats;
	const ev_tstamp snapshot_time = f->server.last_stats_time;
	char response[4096];
	for (size_t i = 0; i < 2; i++) {
		const char *body = request_response(
			f, "GET", "/stats", "HTTP/1.1 200 OK\r\n", response,
			sizeof(response));
		check_plain_response(response, true);
		CHECK(strncmp(body, "server time: ", 13) == 0);
		CHECK(strstr(body, "  = 0 sessions:") != NULL);
		CHECK(strstr(body,
			     "[total] tcp: 100B, 200B; kcp: 300B, 400B; pkt: 500B, 600B\n") !=
		      NULL);
		CHECK(strstr(body, "[rx,tx]") == NULL);
		CHECK(memcmp(&f->server.last_stats, &snapshot,
			     sizeof(snapshot)) == 0);
		CHECK(f->server.last_stats_time == snapshot_time);
	}
}

static void stats_post(struct fixture *f)
{
	char response[4096];
	const char *body = request_response(
		f, "POST", "/stats", "HTTP/1.1 200 OK\r\n", response,
		sizeof(response));
	check_plain_response(response, false);
	CHECK(strstr(body, "[rx,tx] tcp:") != NULL);
	CHECK(strstr(body, "efficiency: 66.7%, 25.0%\n") != NULL);
	CHECK(memcmp(&f->server.last_stats, &f->server.stats,
		     sizeof(f->server.stats)) == 0);
	CHECK(f->server.last_stats_time == ev_now(f->server.loop));
	/* No clock advance: neither a zero interval nor idle KCP may emit NaNs. */
	body = request_response(
		f, "POST", "/stats", "HTTP/1.1 200 OK\r\n", response,
		sizeof(response));
	CHECK(strstr(body, "[rx,tx]") == NULL);
	CHECK(strstr(body, "pkt: (unknown)/s, (unknown)/s;") != NULL);
	f->server.last_stats_time = ev_now(f->server.loop) - 1;
	body = request_response(
		f, "POST", "/stats", "HTTP/1.1 200 OK\r\n", response,
		sizeof(response));
	CHECK(strstr(body, "efficiency: 0.0%, 0.0%\n") != NULL);
	CHECK(strstr(body, "nan") == NULL && strstr(body, "inf") == NULL);
}

static void stats_responses(struct ev_loop *loop)
{
	struct fixture f;
	fixture_init(&f, loop);
	struct pktqueue queue = { 0 };
	f.server.pkt.queue = &queue;
	f.server.started = ev_now(loop) - 100;
	f.server.last_stats_time = ev_now(loop) - 5;
	f.server.stats = (struct link_stats){ 100, 200, 300, 400, 500, 600 };
	f.server.last_stats = (struct link_stats){ 1, 2, 3, 4, 5, 6 };
	stats_get(&f);
	stats_post(&f);
	socket_close(f.server.listener.fd_http);
	puts("stats_responses: repeated GET preserves snapshots, POST advances snapshots, zero interval and idle counters passed");
}

static void stats_queries(struct ev_loop *loop)
{
	struct fixture f;
	fixture_init(&f, loop);
	struct pktqueue queue = { 0 };
	f.server.pkt.queue = &queue;
	f.server.started = ev_now(loop);
	f.server.sessions = table_new(NULL);
	CHECK(f.server.sessions != NULL);
	struct session sessions[KCP_STATE_MAX];
	for (size_t i = 0; i < KCP_STATE_MAX; i++) {
		struct session *ss = &sessions[i];
		*ss = (struct session){ .conv = (uint32_t)(i + 1),
					.kcp_state = (enum kcp_state)i,
					.created = ev_now(loop),
					.raddr.in.sin_family = AF_INET };
		ss->key[0] = (unsigned char)i;
		ss->hkey = (struct hashkey){ .len = sizeof(ss->key),
					     .data = ss->key };
		void *element = ss;
		f.server.sessions =
			table_set(f.server.sessions, &ss->hkey, &element);
		CHECK(element == NULL);
	}
	const struct {
		const char *query;
		bool banner;
		int level;
	} cases[] = {
		{ "", false, KCP_STATE_ESTABLISHED },
		{ "?nobanner", false, KCP_STATE_ESTABLISHED },
		{ "?nobanner=0", true, KCP_STATE_ESTABLISHED },
		{ "?nobanner=false", true, KCP_STATE_ESTABLISHED },
		{ "?nobanner=", true, KCP_STATE_ESTABLISHED },
		{ "?nobanner=1", false, KCP_STATE_ESTABLISHED },
		{ "?nobanner=y", false, KCP_STATE_ESTABLISHED },
		{ "?nobanner=yes", false, KCP_STATE_ESTABLISHED },
		{ "?nobanner=on", false, KCP_STATE_ESTABLISHED },
		{ "?nobanner=t", false, KCP_STATE_ESTABLISHED },
		{ "?nobanner=true", false, KCP_STATE_ESTABLISHED },
		{ "?sessions", false, KCP_STATE_ESTABLISHED },
		{ "?sessions=invalid", false, KCP_STATE_ESTABLISHED },
		{ "?sessions=0", false, -1 },
		{ "?sessions=none", false, -1 },
		{ "?sessions=1", false, KCP_STATE_ESTABLISHED },
		{ "?sessions=connected", false, KCP_STATE_ESTABLISHED },
		{ "?sessions=2", false, KCP_STATE_LINGER },
		{ "?sessions=active", false, KCP_STATE_LINGER },
		{ "?sessions=3", false, KCP_STATE_MAX },
		{ "?sessions=all", false, KCP_STATE_MAX },
		{ "?nobanner=0&nobanner&sessions=all&sessions", false,
		  KCP_STATE_MAX },
		{ "?sessions=all&sessions=none&unknown=1", false, -1 },
		{ "?%6Eobanner=0&sessions=%61ll", true, KCP_STATE_MAX },
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		char target[128], response[4096];
		(void)snprintf(
			target, sizeof(target), "/stats%s", cases[i].query);
		const char *body = request_response(
			&f, "GET", target, "HTTP/1.1 200 OK\r\n", response,
			sizeof(response));
		CHECK((strncmp(body, PROJECT_NAME " ", sizeof(PROJECT_NAME)) ==
		       0) == cases[i].banner);
		CHECK(strstr(body,
			     "  = 5 sessions: 1 halfopen, 1 connected, 1 linger, 1 time_wait;") !=
		      NULL);
		for (size_t j = 0; j < KCP_STATE_MAX; j++) {
			char prefix[16];
			(void)snprintf(
				prefix, sizeof(prefix), "[%08X]",
				(unsigned int)sessions[j].conv);
			CHECK((strstr(body, prefix) != NULL) ==
			      ((int)j <= cases[i].level));
		}
	}
	table_free(f.server.sessions);
	socket_close(f.server.listener.fd_http);
	puts("stats_queries: banner flags, every sessions alias, bare/unknown/repeated/escaped queries and state filtering passed");
}

#if MCACHE_STATS
static void stats_cache(struct ev_loop *loop)
{
	struct fixture f;
	fixture_init(&f, loop);
	struct pktqueue queue = { 0 };
	f.server.pkt.queue = &queue;
	f.server.started = ev_now(loop);
	f.server.last_stats_time = ev_now(loop);
	CHECK(msgpool == NULL);
	msgpool = mcache_new(1, 16);
	CHECK(msgpool != NULL);
	char response[4096];
	const char *body = request_response(
		&f, "GET", "/stats", "HTTP/1.1 200 OK\r\n", response,
		sizeof(response));
	CHECK(strstr(body,
		     "msgpool: 0/1; 0 hit, 0 miss (0.0%); total 0 hit, 0 miss (0.0%)\n") !=
	      NULL);
	void *item = mcache_get(msgpool);
	CHECK(item != NULL);
	mcache_put(msgpool, item);
	item = mcache_get(msgpool);
	CHECK(item != NULL);
	mcache_put(msgpool, item);
	const struct {
		const char *method, *counts;
	} cases[] = {
		{ "GET", "1 hit, 1 miss (50.0%)" },
		{ "GET", "1 hit, 1 miss (50.0%)" },
		{ "POST", "1 hit, 1 miss (50.0%)" },
		{ "GET", "0 hit, 0 miss (0.0%)" },
		{ "POST", "0 hit, 0 miss (0.0%)" },
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		body = request_response(
			&f, cases[i].method, "/stats", "HTTP/1.1 200 OK\r\n",
			response, sizeof(response));
		char counts[128];
		(void)snprintf(
			counts, sizeof(counts),
			"msgpool: 1/1; %s; total 1 hit, 1 miss (50.0%%)\n",
			cases[i].counts);
		CHECK(strstr(body, counts) != NULL);
	}
	mcache_free(msgpool);
	msgpool = NULL;
	socket_close(f.server.listener.fd_http);
	puts("stats_cache: zero counters, repeated GET, POST rotation and hit/miss totals passed");
}
#endif /* MCACHE_STATS */

int main(void)
{
	slog_setoutput(SLOG_OUTPUT_STREAM, log_filewriter(stderr));
	slog_setlevel(LOG_LEVEL_NOTICE);
	struct ev_loop *loop = ev_loop_new(EVFLAG_NOENV);
	CHECK(loop != NULL);
	admission_limit(loop);
	cleanup_paths(loop);
	cleanup_errors(loop);
	setup_failures(loop);
	health_responses(loop);
	rejected_routes(loop);
	stats_responses(loop);
	stats_queries(loop);
#if MCACHE_STATS
	stats_cache(loop);
#endif
	ev_loop_destroy(loop);
	return EXIT_SUCCESS;
}
