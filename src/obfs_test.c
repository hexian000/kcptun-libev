/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"
#include "obfs.c"
#include "pktqueue.h"
#include "server.h"
#include "session.h"
#include "util.h"

#include "algo/hashtable.h"
#include "meta/minmax.h"
#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>
#include <linux/if_packet.h>

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

static bool fail_netdev, tracking_probe, intercept_raw;
static size_t send_budget = SIZE_MAX;
static int recv_error;
static unsigned int raw_sends, pings;
static unsigned char raw_packet[128];
static size_t raw_packet_len;
static int probe_fd = -1;
static unsigned int device_calls, connect_calls, name_calls, close_calls;

bool test_bind_netdev(int fd, const char *netdev) __asm__(
	"__wrap_socket_bind_netdev");
bool test_bind_netdev(int fd, const char *netdev)
{
	if (tracking_probe) {
		CHECK(fd == probe_fd);
	}
	CHECK(strcmp(netdev, "test-device") == 0);
	device_calls++;
	return !fail_netdev;
}

int real_socket(int domain, int type, int protocol) __asm__("__real_socket");
int test_socket(int domain, int type, int protocol) __asm__("__wrap_socket");
int test_socket(int domain, int type, int protocol)
{
	const int fd = real_socket(domain, type, protocol);
	if (tracking_probe) {
		CHECK(probe_fd == -1);
		probe_fd = fd;
	}
	return fd;
}

int real_close(int fd) __asm__("__real_close");
int test_close(int fd) __asm__("__wrap_close");
int test_close(int fd)
{
	if (tracking_probe) {
		CHECK(fd == probe_fd);
	}
	close_calls++;
	return real_close(fd);
}

int real_connect(int fd, const struct sockaddr *sa, socklen_t len) __asm__(
	"__real_connect");
int test_connect(int fd, const struct sockaddr *sa, socklen_t len) __asm__(
	"__wrap_connect");
int test_connect(int fd, const struct sockaddr *sa, socklen_t len)
{
	if (tracking_probe) {
		CHECK(fd == probe_fd);
	}
	connect_calls++;
	return real_connect(fd, sa, len);
}

int real_getsockname(int fd, struct sockaddr *sa, socklen_t *len) __asm__(
	"__real_getsockname");
int test_getsockname(int fd, struct sockaddr *sa, socklen_t *len) __asm__(
	"__wrap_getsockname");
int test_getsockname(int fd, struct sockaddr *sa, socklen_t *len)
{
	if (tracking_probe) {
		CHECK(fd == probe_fd);
	}
	name_calls++;
	return real_getsockname(fd, sa, len);
}

static void
test_resolve_local(const bool failure, const bool device, char *source)
{
	tracking_probe = true;
	fail_netdev = failure;
	probe_fd = -1;
	device_calls = connect_calls = name_calls = close_calls = 0;
	const struct config conf = { .netdev = device ? "test-device" : NULL,
				     .kcp_bind = source };
	struct server server = { .conf = &conf };
	struct obfs obfs = { .server = &server, .domain = AF_INET };
	const union sockaddr_max remote = {
		.in.sin_family = AF_INET,
		.in.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.in.sin_port = htons(9),
	};
	union sockaddr_max local = { 0 };
	CHECK(obfs_resolve_local(&obfs, &local, &remote.sa) == !failure);
	CHECK(probe_fd >= 0);
	CHECK(device_calls == (device ? 1u : 0u));
	CHECK(connect_calls == (failure ? 0u : 1u));
	CHECK(name_calls == (failure ? 0u : 1u));
	CHECK(close_calls == 1);
	CHECK(fcntl(probe_fd, F_GETFD) == -1 && errno == EBADF);
	if (!failure) {
		CHECK(local.in.sin_family == AF_INET);
		CHECK(local.in.sin_addr.s_addr ==
		      htonl(source ? 0x7f000002 : INADDR_LOOPBACK));
		CHECK(local.in.sin_port == 0);
	}
}

ssize_t real_sendto(
	int fd, const void *data, size_t len, int flags,
	const struct sockaddr *sa, socklen_t salen) __asm__("__real_sendto");
ssize_t test_sendto(
	int fd, const void *data, size_t len, int flags,
	const struct sockaddr *sa, socklen_t salen) __asm__("__wrap_sendto");
ssize_t test_sendto(
	int fd, const void *data, size_t len, int flags,
	const struct sockaddr *sa, socklen_t salen)
{
	if (!intercept_raw) {
		return real_sendto(fd, data, len, flags, sa, salen);
	}
	CHECK(len <= sizeof(raw_packet));
	memcpy(raw_packet, data, len);
	raw_packet_len = len;
	raw_sends++;
	return (ssize_t)len;
}

ssize_t real_send(int fd, const void *data, size_t len, int flags) __asm__(
	"__real_send");
ssize_t test_send(int fd, const void *data, size_t len, int flags) __asm__(
	"__wrap_send");
ssize_t test_send(int fd, const void *data, size_t len, int flags)
{
	if (send_budget == 0) {
		errno = EAGAIN;
		return -1;
	}
	const size_t n = MIN(len, send_budget);
	const ssize_t sent = real_send(fd, data, n, flags);
	if (sent > 0 && send_budget != SIZE_MAX) {
		send_budget -= (size_t)sent;
	}
	return sent;
}

ssize_t
real_recv(int fd, void *data, size_t len, int flags) __asm__("__real_recv");
ssize_t
test_recv(int fd, void *data, size_t len, int flags) __asm__("__wrap_recv");
ssize_t test_recv(int fd, void *data, size_t len, int flags)
{
	if (recv_error != 0) {
		errno = recv_error;
		recv_error = 0;
		return -1;
	}
	return real_recv(fd, data, len, flags);
}

void test_ping(struct server *s) __asm__("__wrap_server_ping");
void test_ping(struct server *s)
{
	CHECK(s->pkt.connected);
	pings++;
}

struct fixture {
	struct pktqueue queue;
	struct config conf;
	struct server server;
	struct obfs *obfs;
};

static void fixture_open(
	struct fixture *f, const bool client, const int domain, const bool raw)
{
	*f = (struct fixture){
		.conf = { .mode = client ? MODE_CLIENT : MODE_SERVER,
			  .obfs = raw ? "dpi/tcp" : "dpi/tcp-wnd" }
	};
	f->queue.mss = 1400;
	f->server.pkt.queue = &f->queue;
	f->server.conf = &f->conf;
	f->server.loop = ev_loop_new(0);
	CHECK(f->server.loop != NULL);
	f->server.dial_timeout = 10;
	f->server.timeout = 60;
	f->server.sessions = table_new(&(struct table_opts){ 0 });
	CHECK(f->server.sessions != NULL);
	f->obfs = obfs_new(&f->server);
	CHECK(f->obfs != NULL);
	f->obfs->domain = domain;
	ev_timer_init(&f->obfs->w_syn, obfs_syn_cb, 0, 1);
	f->obfs->w_syn.data = f->obfs;
	ev_timer_init(&f->obfs->w_redial, obfs_redial_cb, 0, 0);
	f->obfs->w_redial.data = f->obfs;
	ev_timer_init(&f->obfs->w_timeout, obfs_timeout_cb, 0, 1);
	f->obfs->w_timeout.data = f->obfs;
	ev_timer_init(&f->obfs->w_listener, obfs_listener_cb, 0, 1);
	tracking_probe = false;
	fail_netdev = false;
	intercept_raw = true;
}

static void fixture_close(struct fixture *f)
{
	obfs_stop(f->obfs, &f->server);
	CHECK(table_size(f->obfs->contexts) == 0);
	CHECK(!ev_is_active(&f->obfs->w_syn));
	CHECK(!ev_is_active(&f->obfs->w_redial));
	obfs_free(f->obfs);
	CHECK(table_size(f->server.sessions) == 0);
	table_free(f->server.sessions);
	CHECK(ev_run(f->server.loop, EVRUN_NOWAIT) == 0);
	ev_loop_destroy(f->server.loop);
}

static union sockaddr_max
endpoint(const int domain, const bool peer, const bool scoped)
{
	union sockaddr_max sa = { 0 };
	if (domain == AF_INET) {
		sa.in.sin_family = AF_INET;
		sa.in.sin_addr.s_addr = htonl(peer ? 0xc0000202 : 0xc0000201);
		sa.in.sin_port = htons(peer ? 4321 : 1234);
	} else {
		sa.in6.sin6_family = AF_INET6;
		sa.in6.sin6_addr.s6_addr[0] = scoped ? 0xfe : 0x20;
		sa.in6.sin6_addr.s6_addr[1] = scoped ? 0x80 : 0x01;
		sa.in6.sin6_addr.s6_addr[15] = peer ? 2 : 1;
		sa.in6.sin6_port = htons(peer ? 4321 : 1234);
		sa.in6.sin6_scope_id = scoped ? 7 : 0;
	}
	return sa;
}

static struct obfs_ctx *
register_ctx(struct fixture *f, const bool reverse, const bool scoped)
{
	struct obfs_ctx *ctx = obfs_ctx_new(f->obfs);
	CHECK(ctx != NULL);
	ctx->laddr = endpoint(f->obfs->domain, reverse, scoped);
	ctx->raddr = endpoint(f->obfs->domain, !reverse, scoped);
	ctx->created = ctx->last_seen = ev_now(f->server.loop);
	ctx->tcp_state = OBFS_TCP_ESTABLISHED;
	ctx->captured = true;
	ctx->local_seq = 100;
	ctx->remote_seq = 200;
	obfs_ctx_setkey(ctx->key, &ctx->raddr.sa);
	CHECK(obfs_ctx_register(f->obfs, ctx));
	f->obfs->bind_addr = ctx->laddr;
	return ctx;
}

/* Independent byte-order checksum oracle, including the pseudo header. */
static uint32_t checksum_words(const unsigned char *b, const size_t n)
{
	uint32_t sum = 0;
	for (size_t i = 0; i < n; i += 2) {
		sum += (uint32_t)b[i] << 8;
		if (i + 1 < n) {
			sum += b[i + 1];
		}
	}
	return sum;
}

static void check_wire_checksum(const struct msgframe *msg, const int domain)
{
	const size_t ihl = domain == AF_INET ? sizeof(struct iphdr) :
					       sizeof(struct ip6_hdr);
	const size_t plen = msg->len - ihl;
	uint32_t sum = IPPROTO_TCP + (uint32_t)plen;
	if (domain == AF_INET) {
		sum += checksum_words(msg->buf + 12, 8);
	} else {
		sum += checksum_words(msg->buf + 8, 32);
	}
	sum += checksum_words(msg->buf + ihl, plen);
	while (sum >> 16) {
		sum = (sum & 0xffffu) + (sum >> 16);
	}
	CHECK(sum == 0xffffu);
}

static void test_packets(
	const int domain, const bool raw, const bool scoped,
	const uint16_t payload_len)
{
	struct fixture tx, rx;
	fixture_open(&tx, false, domain, raw);
	fixture_open(&rx, false, domain, raw);
	struct obfs_ctx *out = register_ctx(&tx, false, scoped);
	struct obfs_ctx *in = register_ctx(&rx, true, scoped);
	struct msgframe msg = { .addr = out->raddr,
				.off = (uint16_t)obfs_overhead(tx.obfs),
				.len = payload_len };
	for (uint16_t i = 0; i < payload_len; i++) {
		msg.buf[msg.off + i] = (unsigned char)(i + 17);
	}
	CHECK(obfs_seal_inplace(tx.obfs, &msg));
	check_wire_checksum(&msg, domain);
	const struct msgframe sealed = msg;
	msg.ts = ev_now(rx.server.loop);
	if (scoped) {
		const struct sockaddr_ll cap = { .sll_family = AF_PACKET,
						 .sll_ifindex = 7 };
		memcpy(&msg.addr, &cap, sizeof(cap));
	}
	CHECK(obfs_open_inplace(rx.obfs, &msg) == in);
	CHECK(msg.len == payload_len);
	CHECK(sa_equals(&msg.addr.sa, &in->raddr.sa));
	for (uint16_t i = 0; i < payload_len; i++) {
		CHECK(msg.buf[msg.off + i] == (unsigned char)(i + 17));
	}
	const size_t ihl = obfs_overhead(tx.obfs) - sizeof(struct tcphdr);
	msg = sealed;
	msg.buf[msg.len - 1] ^= 1;
	CHECK(obfs_open_inplace(rx.obfs, &msg) == NULL);
	for (uint16_t n = 0; n < sealed.len; n++) {
		msg = sealed;
		msg.len = n;
		CHECK(obfs_open_inplace(rx.obfs, &msg) == NULL);
	}
	msg = sealed;
	msg.buf[0] ^= 0x10;
	CHECK(obfs_open_inplace(rx.obfs, &msg) == NULL);
	msg = sealed;
	msg.buf[domain == AF_INET ? 9 : 6] = IPPROTO_UDP;
	CHECK(obfs_open_inplace(rx.obfs, &msg) == NULL);
	msg = sealed;
	msg.buf[ihl + 12] = 0x40;
	CHECK(obfs_open_inplace(rx.obfs, &msg) == NULL);
	msg = sealed;
	msg.buf[ihl + 12] = 0xf0;
	CHECK(obfs_open_inplace(rx.obfs, &msg) == NULL);
	msg = sealed;
	msg.buf[ihl + 2] ^= 1;
	CHECK(obfs_open_inplace(rx.obfs, &msg) == NULL);
	msg = sealed;
	msg.buf[ihl] ^= 1;
	CHECK(obfs_open_inplace(rx.obfs, &msg) == NULL);
	if (scoped) {
		union sockaddr_max wrong = in->raddr;
		wrong.in6.sin6_scope_id++;
		CHECK(obfs_find_ctx(rx.obfs, &wrong.sa) == NULL);
		const struct sockaddr_ll cap = { .sll_family = AF_PACKET,
						 .sll_ifindex = 8 };
		msg = sealed;
		memcpy(&msg.addr, &cap, sizeof(cap));
		CHECK(obfs_open_inplace(rx.obfs, &msg) == NULL);
	}
	fixture_close(&rx);
	fixture_close(&tx);
}

static void add_session(struct fixture *f, const union sockaddr_max *remote)
{
	struct session *ss = session_new(&f->server, remote, 1);
	CHECK(ss != NULL);
	void *element = ss;
	f->server.sessions = table_set(f->server.sessions, &ss->hkey, &element);
	CHECK(element == NULL);
}

static void test_raw_lifecycle(void)
{
	struct fixture f;
	fixture_open(&f, true, AF_INET, true);
	struct obfs_ctx *ctx = register_ctx(&f, false, false);
	f.obfs->client = ctx;
	raw_sends = 0;
	CHECK(obfs_tcp_dial(f.obfs, ctx));
	CHECK(raw_sends == 1 && ctx->syn_pending &&
	      ev_is_active(&f.obfs->w_syn));
	unsigned char initial[sizeof(raw_packet)];
	memcpy(initial, raw_packet, raw_packet_len);
	obfs_syn_cb(f.server.loop, &f.obfs->w_syn, EV_TIMER);
	CHECK(raw_sends == 2);
	/* IPv4 ID may change on a retry; the TCP SYN must not. */
	CHECK(memcmp(initial + sizeof(struct iphdr),
		     raw_packet + sizeof(struct iphdr),
		     sizeof(struct tcphdr)) == 0);
	struct tcphdr tcp;
	tcp_hdr_init(&tcp, 0, 0, 777, 0, TH_SYN | TH_ACK, 100);
	struct msgframe msg = { .ts = ev_now(f.server.loop) };
	struct obfs_tcp_packet pkt = { .ctx = ctx,
				       .tcp = &tcp,
				       .plen = sizeof(tcp),
				       .doff = sizeof(tcp) };
	pings = 0;
	CHECK(obfs_tcp_input(f.obfs, &msg, &pkt) == NULL);
	CHECK(ctx->remote_seq == 778 && !ctx->syn_pending);
	CHECK(!ev_is_active(&f.obfs->w_syn) && f.server.pkt.connected &&
	      pings == 1);
	obfs_syn_cb(f.server.loop, &f.obfs->w_syn, EV_TIMER);
	CHECK(raw_sends == 2);
	CHECK(obfs_tcp_dial(f.obfs, ctx));
	obfs_ctx_auth(ctx, true);
	CHECK(!ctx->syn_pending && !ev_is_active(&f.obfs->w_syn));
	CHECK(f.obfs->num_authenticated == 1 && pings == 2);
	obfs_ctx_auth(ctx, false);
	CHECK(obfs_tcp_dial(f.obfs, ctx));
	const unsigned int before_timeout = raw_sends;
	ctx->created = ev_now(f.server.loop) - f.server.dial_timeout;
	obfs_syn_cb(f.server.loop, &f.obfs->w_syn, EV_TIMER);
	CHECK(raw_sends == before_timeout && !ev_is_active(&f.obfs->w_syn));
	add_session(&f, &ctx->raddr);
	CHECK(table_size(f.server.sessions) == 1);
	ctx->created = ctx->last_seen =
		ev_now(f.server.loop) - f.server.dial_timeout;
	obfs_timeout_cb(f.server.loop, &f.obfs->w_timeout, EV_TIMER);
	CHECK(table_size(f.obfs->contexts) == 0 && f.obfs->client == NULL);
	CHECK(table_size(f.server.sessions) == 0);
	CHECK(!ev_is_active(&f.obfs->w_syn));
	fixture_close(&f);

	fixture_open(&f, false, AF_INET, true);
	f.obfs->bind_addr = endpoint(AF_INET, false, false);
	const struct obfs_ctx sender = {
		.obfs = f.obfs, .laddr = endpoint(AF_INET, true, false)
	};
	struct obfs_tcp_header syn = { .seq = 700,
				       .flags = TH_SYN,
				       .window = 100 };
	msg = (struct msgframe){ .ts = ev_now(f.server.loop) };
	msg.len = (uint16_t)obfs_build_header(
		&sender, &f.obfs->bind_addr, msg.buf, NULL, 0, &syn);
	CHECK(obfs_open_inplace(f.obfs, &msg) == NULL);
	ctx = obfs_find_ctx(f.obfs, &sender.laddr.sa);
	CHECK(ctx != NULL && ctx->tcp_state == OBFS_TCP_ESTABLISHED);
	CHECK(table_size(f.obfs->contexts) == 1);
	ctx->local_seq += 100;
	ctx->remote_seq += 100;
	const uint32_t local = ctx->local_seq, remote = ctx->remote_seq;
	CHECK(obfs_open_inplace(f.obfs, &msg) == NULL);
	CHECK(ctx->local_seq == local && ctx->remote_seq == remote);
	syn.seq = 800;
	msg.len = (uint16_t)obfs_build_header(
		&sender, &f.obfs->bind_addr, msg.buf, NULL, 0, &syn);
	CHECK(obfs_open_inplace(f.obfs, &msg) == NULL);
	CHECK(ctx->remote_seq == 801);
	struct obfs_ctx *replacement = register_ctx(&f, false, false);
	CHECK(obfs_find_ctx(f.obfs, &replacement->raddr.sa) == replacement);
	CHECK(table_size(f.obfs->contexts) == 1);
	fixture_close(&f);
}

static struct obfs_ctx *http_ctx(struct fixture *f, int *peer)
{
	int pair[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0);
	*peer = pair[1];
	struct obfs_ctx *ctx = obfs_ctx_new(f->obfs);
	CHECK(ctx != NULL);
	ctx->laddr = endpoint(AF_INET, false, false);
	ctx->raddr = endpoint(AF_INET, true, false);
	CHECK(obfs_ctx_start(f->obfs, ctx, pair[0]));
	if (f->conf.mode & MODE_CLIENT) {
		f->obfs->client = ctx;
	}
	return ctx;
}

static void read_http(struct fixture *f, struct obfs_ctx *ctx)
{
	ev_invoke(f->server.loop, &ctx->w_read, EV_READ);
}

static void test_http_success(const bool client)
{
	struct fixture f;
	fixture_open(&f, client, AF_INET, false);
	int peer;
	struct obfs_ctx *ctx = http_ctx(&f, &peer);
	const char *head =
		client ? "HTTP/1.1 204 No Content\r\nServer: nginx\r\n" :
			 "GET /generate_204 HTTP/1.1\r\nHost: test\r\n";
	for (size_t i = 0; i < strlen(head); i++) {
		CHECK(real_send(peer, head + i, 1, 0) == 1);
		read_http(&f, ctx);
		CHECK(table_size(f.obfs->contexts) == 1);
		CHECK(ev_cb(&ctx->w_read) != obfs_fail_cb);
	}
	send_budget = 7;
	CHECK(real_send(peer, "\r\n", 2, 0) == 2);
	read_http(&f, ctx);
	CHECK(ev_cb(&ctx->w_read) == obfs_fail_cb);
	if (client) {
		CHECK(f.server.pkt.connected && f.obfs->client == ctx);
	} else {
		CHECK(ev_is_active(&ctx->w_write));
		CHECK(ctx->wbuf.len > 7);
		send_budget = SIZE_MAX;
		ev_invoke(f.server.loop, &ctx->w_write, EV_WRITE);
		CHECK(!ev_is_active(&ctx->w_write));
		char response[512] = { 0 };
		const ssize_t n = recv(peer, response, sizeof(response) - 1, 0);
		CHECK(n > 0);
		CHECK(strstr(response, "HTTP/1.1 204 No Content\r\n") ==
		      response);
		CHECK(strstr(response, "Connection: keep-alive\r\n\r\n") !=
		      NULL);
	}
	send_budget = SIZE_MAX;
	CHECK(real_close(peer) == 0);
	fixture_close(&f);
}

static void test_http_failure(const bool client, const int kind)
{
	struct fixture f;
	fixture_open(&f, client, AF_INET, false);
	int peer;
	struct obfs_ctx *ctx = http_ctx(&f, &peer);
	if (kind == 0) {
		CHECK(real_close(peer) == 0);
		peer = -1;
	} else if (kind == 1) {
		recv_error = ECONNRESET;
	} else if (kind == 2) {
		const char *bad = "broken\r\n\r\n";
		CHECK(real_send(peer, bad, strlen(bad), 0) ==
		      (ssize_t)strlen(bad));
	} else if (kind == 3) {
		unsigned char huge[OBFS_MAX_REQUEST - 1];
		memset(huge, 'X', sizeof(huge));
		CHECK(real_send(peer, huge, sizeof(huge), 0) ==
		      (ssize_t)sizeof(huge));
	} else {
		const char *bad = client ?
					  "HTTP/1.1 200 OK\r\n\r\n" :
					  "POST /generate_204 HTTP/1.1\r\n\r\n";
		CHECK(real_send(peer, bad, strlen(bad), 0) ==
		      (ssize_t)strlen(bad));
	}
	read_http(&f, ctx);
	if (client && kind < 2) {
		CHECK(table_size(f.obfs->contexts) == 1);
		CHECK(f.obfs->client == NULL);
		CHECK(!ev_is_active(&ctx->w_read) &&
		      !ev_is_active(&ctx->w_write));
	} else {
		CHECK(table_size(f.obfs->contexts) == 0);
	}
	if (peer != -1) {
		CHECK(real_close(peer) == 0);
	}
	fixture_close(&f);
}

static void test_http_lifecycle(void)
{
	struct fixture f;
	fixture_open(&f, true, AF_INET, false);
	int peer;
	struct obfs_ctx *ctx = http_ctx(&f, &peer);
	const int old_fd = ctx->fd;
	add_session(&f, &ctx->raddr);
	struct obfs_ctx *replacement = register_ctx(&f, false, false);
	CHECK(table_size(f.obfs->contexts) == 1);
	CHECK(table_size(f.server.sessions) == 0);
	CHECK(obfs_find_ctx(f.obfs, &replacement->raddr.sa) == replacement);
	CHECK(fcntl(old_fd, F_GETFD) == -1 && errno == EBADF);
	CHECK(f.obfs->client == NULL);
	CHECK(real_close(peer) == 0);
	fixture_close(&f);

	fixture_open(&f, false, AF_INET, false);
	ctx = http_ctx(&f, &peer);
	const int timed_fd = ctx->fd;
	ctx->created = ctx->last_seen =
		ev_now(f.server.loop) - f.server.dial_timeout;
	obfs_timeout_cb(f.server.loop, &f.obfs->w_timeout, EV_TIMER);
	CHECK(table_size(f.obfs->contexts) == 0);
	CHECK(fcntl(timed_fd, F_GETFD) == -1 && errno == EBADF);
	CHECK(real_close(peer) == 0);
	fixture_close(&f);
}

struct dial_case {
	char *device, *source;
	bool fail_device, success;
};

static void test_tcp_wnd_constraints(const struct dial_case *test)
{
	struct fixture f;
	fixture_open(&f, true, AF_INET, false);
	const bool failure = !test->success;
	f.conf.netdev = test->device;
	f.conf.kcp_bind = test->source;
	const int listener =
		real_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	CHECK(listener >= 0);
	union sockaddr_max addr = { .in = { .sin_family = AF_INET,
					    .sin_addr.s_addr =
						    htonl(INADDR_LOOPBACK) } };
	CHECK(bind(listener, &addr.sa, sa_len(&addr.sa)) == 0);
	CHECK(listen(listener, 1) == 0);
	socklen_t len = sizeof(addr);
	CHECK(real_getsockname(listener, &addr.sa, &len) == 0);
	device_calls = connect_calls = name_calls = close_calls = 0;
	fail_netdev = test->fail_device;
	CHECK(obfs_ctx_dial(f.obfs, &addr.sa) == !failure);
	CHECK(device_calls == (test->device != NULL ? 1u : 0u));
	CHECK(connect_calls == (failure ? 0u : 1u));
	CHECK(table_size(f.obfs->contexts) == (failure ? 0u : 1u));
	if (failure) {
		CHECK(f.obfs->client == NULL && close_calls == 1);
	} else {
		CHECK(f.obfs->client->laddr.in.sin_addr.s_addr ==
		      htonl(0x7f000002));
		CHECK(sa_equals(
			&f.obfs->bind_addr.sa, &f.obfs->client->laddr.sa));
		const int accepted = accept(listener, &addr.sa, &len);
		CHECK(accepted >= 0);
		CHECK(addr.in.sin_addr.s_addr == htonl(0x7f000002));
		CHECK(real_close(accepted) == 0);
	}
	CHECK(real_close(listener) == 0);
	fixture_close(&f);
}

int main(int argc, char **argv)
{
	CHECK(argc == 2);
	slog_setoutput(SLOG_OUTPUT_STREAM, log_filewriter(stdout));
	slog_setlevel(LOG_LEVEL_WARNING);
	if (strcmp(argv[1], "resolve") == 0) {
		test_resolve_local(true, true, NULL);
		test_resolve_local(false, true, NULL);
		test_resolve_local(false, false, NULL);
		test_resolve_local(false, false, "127.0.0.2:1");
	} else if (strcmp(argv[1], "constraints") == 0) {
		tracking_probe = false;
		const struct dial_case cases[] = {
			{ .device = "test-device",
			  .source = "127.0.0.2:0",
			  .fail_device = true },
			{ .device = "test-device",
			  .source = "127.0.0.2:0",
			  .success = true },
			{ .device = "test-device", .source = "192.0.2.123:0" },
			{ .device = "test-device",
			  .source = "invalid-address" },
			{ .source = "127.0.0.2:0", .success = true },
		};
		for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
			test_tcp_wnd_constraints(&cases[i]);
		}
	} else if (strcmp(argv[1], "packets") == 0) {
		for (int raw = 0; raw < 2; raw++) {
			for (uint16_t n = 4; n <= 5; n++) {
				test_packets(AF_INET, raw, false, n);
				test_packets(AF_INET6, raw, false, n);
				test_packets(AF_INET6, raw, true, n);
			}
		}
	} else if (strcmp(argv[1], "lifecycle") == 0) {
		test_raw_lifecycle();
		test_http_lifecycle();
	} else {
		CHECK(strcmp(argv[1], "http") == 0);
		for (int client = 0; client < 2; client++) {
			test_http_success(client);
			for (int kind = 0; kind < 5; kind++) {
				test_http_failure(client, kind);
			}
		}
	}
	return EXIT_SUCCESS;
}
