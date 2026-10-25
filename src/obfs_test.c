/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "obfs.h"

#include "conf.h"
#include "crypto.h"
#include "nonce.h"
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
#include <unistd.h>

static bool fail_netdev, tracking_probe, intercept_raw;
static size_t send_budget = SIZE_MAX;
static int recv_error;
static unsigned int raw_sends, pings;
static unsigned char raw_packet[128];
static size_t raw_packet_len;
static bool fake_raw_sockets;
static int raw_output_fd = -1, bound_raw_fd = -1;
static struct hashtable *tracked_sessions;
static unsigned int session_passes;
static int probe_fd = -1;

static struct hashtable *
test_table_filter(struct hashtable *t, table_iterate_cb cb, void *data)
{
	const bool tracked = t == tracked_sessions && t != NULL;
	if (tracked) {
		session_passes++;
	}
	struct hashtable *result = table_filter(t, cb, data);
	if (tracked) {
		tracked_sessions = result;
	}
	return result;
}

static int
test_setsockopt(int fd, int level, int opt, const void *value, socklen_t len)
{
	if (fake_raw_sockets && fd == raw_output_fd &&
	    (opt == IP_HDRINCL || opt == IPV6_HDRINCL)) {
		return 0;
	}
	return setsockopt(fd, level, opt, value, len);
}
static unsigned int device_calls, connect_calls, name_calls, close_calls;

static bool test_bind_netdev(int fd, const char *netdev)
{
	if (tracking_probe) {
		CHECK(fd == probe_fd);
	}
	CHECK(strcmp(netdev, "test-device") == 0);
	if (fake_raw_sockets) {
		bound_raw_fd = fd;
	}
	device_calls++;
	return !fail_netdev;
}

static int test_socket(int domain, int type, int protocol)
{
	const bool fake =
		fake_raw_sockets && (domain == PF_PACKET || type == SOCK_RAW);
	const int fd = fake ? socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) :
			      socket(domain, type, protocol);
	if (fake && type == SOCK_RAW) {
		raw_output_fd = fd;
	}
	if (tracking_probe) {
		CHECK(probe_fd == -1);
		probe_fd = fd;
	}
	return fd;
}

static void test_socket_close(int fd)
{
	if (tracking_probe) {
		CHECK(fd == probe_fd);
	}
	close_calls++;
	socket_close(fd);
}

static int test_connect(int fd, const struct sockaddr *sa, socklen_t len)
{
	if (tracking_probe) {
		CHECK(fd == probe_fd);
	}
	connect_calls++;
	return connect(fd, sa, len);
}

static int test_getsockname(int fd, struct sockaddr *sa, socklen_t *len)
{
	if (tracking_probe) {
		CHECK(fd == probe_fd);
	}
	name_calls++;
	return getsockname(fd, sa, len);
}

static ssize_t test_sendto(
	int fd, const void *data, size_t len, int flags,
	const struct sockaddr *sa, socklen_t salen)
{
	if (!intercept_raw) {
		return sendto(fd, data, len, flags, sa, salen);
	}
	CHECK(len <= sizeof(raw_packet));
	memcpy(raw_packet, data, len);
	raw_packet_len = len;
	raw_sends++;
	return (ssize_t)len;
}

static ssize_t test_send(int fd, const void *data, size_t len, int flags)
{
	if (send_budget == 0) {
		errno = EAGAIN;
		return -1;
	}
	const size_t n = MIN(len, send_budget);
	const ssize_t sent = send(fd, data, n, flags);
	if (sent > 0 && send_budget != SIZE_MAX) {
		send_budget -= (size_t)sent;
	}
	return sent;
}

static ssize_t test_recv(int fd, void *data, size_t len, int flags)
{
	if (recv_error != 0) {
		errno = recv_error;
		recv_error = 0;
		return -1;
	}
	return recv(fd, data, len, flags);
}

static void test_ping(struct server *s)
{
	CHECK(s->pkt.connected);
	pings++;
}

#define socket_bind_netdev test_bind_netdev
#define socket test_socket
#define socket_close test_socket_close
#define connect(fd, addr, len) test_connect(fd, addr, len)
#define getsockname test_getsockname
#define sendto test_sendto
#define send test_send
#define recv test_recv
#define server_ping test_ping
#define table_filter test_table_filter
#define setsockopt test_setsockopt
#include "obfs.c"
#undef socket_bind_netdev
#undef socket
#undef socket_close
#undef connect
#undef getsockname
#undef sendto
#undef send
#undef recv
#undef server_ping
#undef table_filter
#undef setsockopt

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
		CHECK(send(peer, head + i, 1, 0) == 1);
		read_http(&f, ctx);
		CHECK(table_size(f.obfs->contexts) == 1);
		CHECK(ev_cb(&ctx->w_read) != obfs_fail_cb);
	}
	send_budget = 7;
	CHECK(send(peer, "\r\n", 2, 0) == 2);
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
	CHECK(close(peer) == 0);
	fixture_close(&f);
}

static void test_http_failure(const bool client, const int kind)
{
	struct fixture f;
	fixture_open(&f, client, AF_INET, false);
	int peer;
	struct obfs_ctx *ctx = http_ctx(&f, &peer);
	if (kind == 0) {
		CHECK(close(peer) == 0);
		peer = -1;
	} else if (kind == 1) {
		recv_error = ECONNRESET;
	} else if (kind == 2) {
		const char *bad = "broken\r\n\r\n";
		CHECK(send(peer, bad, strlen(bad), 0) == (ssize_t)strlen(bad));
	} else if (kind == 3) {
		unsigned char huge[OBFS_MAX_REQUEST - 1];
		memset(huge, 'X', sizeof(huge));
		CHECK(send(peer, huge, sizeof(huge), 0) ==
		      (ssize_t)sizeof(huge));
	} else {
		const char *bad = client ?
					  "HTTP/1.1 200 OK\r\n\r\n" :
					  "POST /generate_204 HTTP/1.1\r\n\r\n";
		CHECK(send(peer, bad, strlen(bad), 0) == (ssize_t)strlen(bad));
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
		CHECK(close(peer) == 0);
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
	CHECK(close(peer) == 0);
	fixture_close(&f);

	fixture_open(&f, false, AF_INET, false);
	ctx = http_ctx(&f, &peer);
	const int timed_fd = ctx->fd;
	ctx->created = ctx->last_seen =
		ev_now(f.server.loop) - f.server.dial_timeout;
	obfs_timeout_cb(f.server.loop, &f.obfs->w_timeout, EV_TIMER);
	CHECK(table_size(f.obfs->contexts) == 0);
	CHECK(fcntl(timed_fd, F_GETFD) == -1 && errno == EBADF);
	CHECK(close(peer) == 0);
	fixture_close(&f);
}

static void dispatch_frame(struct fixture *f, const struct msgframe *wire)
{
	struct msgframe *msg = msgframe_new(&f->queue);
	CHECK(msg != NULL);
	*msg = *wire;
	msg->ts = ev_now(f->server.loop);
	struct msgframe *batch[] = { msg };
	f->queue.mq_recv = batch;
	f->queue.mq_recv_len = 1;
	queue_dispatch(&f->server);
	CHECK(f->queue.mq_recv_len == 0);
	f->queue.mq_recv = NULL;
}

static struct msgframe encrypted_frame(
	struct fixture *tx, const struct crypto *crypto,
	const struct obfs_ctx *out, const unsigned char nonce_id,
	const bool tampered)
{
	struct msgframe msg = { .addr = out->raddr,
				.off = (uint16_t)obfs_overhead(tx->obfs) };
	unsigned char nonce[NONCE_MAX_LENGTH] = { 0 };
	nonce[0] = nonce_id;
	const unsigned char plain[] = { 1, 0 };
	const size_t len = crypto_seal(
		crypto, msg.buf + msg.off, MAX_PACKET_SIZE - msg.off, nonce,
		plain, sizeof(plain));
	CHECK(len == sizeof(plain) + crypto->overhead);
	if (tampered) {
		msg.buf[msg.off] ^= 1;
	}
	memcpy(msg.buf + msg.off + len, nonce, crypto->nonce_size);
	msg.len = (uint16_t)(len + crypto->nonce_size);
	CHECK(obfs_seal_inplace(tx->obfs, &msg));
	return msg;
}

static void test_authenticated_timeout(const bool raw, const bool replay)
{
	struct fixture tx, rx;
	fixture_open(&tx, false, AF_INET, raw);
	fixture_open(&rx, false, AF_INET, raw);
	struct obfs_ctx *out = register_ctx(&tx, true, false);
	int peer = -1;
	struct obfs_ctx *in =
		raw ? register_ctx(&rx, false, false) : http_ctx(&rx, &peer);
	in->tcp_state = OBFS_TCP_ESTABLISHED;
	in->captured = true;
	rx.obfs->bind_addr = in->laddr;
	const int context_fd = in->fd;
	rx.queue.obfs = rx.obfs;
	rx.queue.crypto = crypto_new("xchacha20poly1305_ietf");
	CHECK(rx.queue.crypto != NULL);
	char psk[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
	CHECK(crypto_b64psk(rx.queue.crypto, psk));
	rx.queue.noncegen = noncegen_new(
		rx.queue.crypto->noncegen_method, rx.queue.crypto->nonce_size,
		true);
	CHECK(rx.queue.noncegen != NULL);
	const struct msgframe accepted =
		encrypted_frame(&tx, rx.queue.crypto, out, 1, false);
	dispatch_frame(&rx, &accepted);
	CHECK(in->authenticated && rx.obfs->num_authenticated == 1);
	const ev_tstamp now = ev_now(rx.server.loop);
	in->created = in->last_seen = now - rx.server.timeout;
	const struct msgframe rejected =
		replay ? accepted :
			 encrypted_frame(&tx, rx.queue.crypto, out, 2, true);
	dispatch_frame(&rx, &rejected);
	CHECK(in->last_seen == now - rx.server.timeout);
	/* A fresh accepted nonce refreshes an already authenticated context. */
	const struct msgframe fresh =
		encrypted_frame(&tx, rx.queue.crypto, out, 3, false);
	dispatch_frame(&rx, &fresh);
	CHECK(in->last_seen == now);
	obfs_timeout_cb(rx.server.loop, &rx.obfs->w_timeout, EV_TIMER);
	CHECK(table_size(rx.obfs->contexts) == 1);
	in->last_seen = now - rx.server.timeout;
	for (int i = 0; i < 3; i++) {
		dispatch_frame(&rx, &rejected);
	}
	obfs_timeout_cb(rx.server.loop, &rx.obfs->w_timeout, EV_TIMER);
	CHECK(table_size(rx.obfs->contexts) == 0 &&
	      rx.obfs->num_authenticated == 0);
	if (!raw) {
		CHECK(fcntl(context_fd, F_GETFD) == -1 && errno == EBADF);
		CHECK(close(peer) == 0);
	}
	noncegen_free(rx.queue.noncegen);
	crypto_free(rx.queue.crypto);
	fixture_close(&rx);
	fixture_close(&tx);
}

static void test_batch_expiry(void)
{
	struct fixture f;
	fixture_open(&f, false, AF_INET, true);
	const ev_tstamp now = ev_now(f.server.loop);
	for (unsigned int i = 0; i < 32; i++) {
		struct obfs_ctx *ctx = obfs_ctx_new(f.obfs);
		CHECK(ctx != NULL);
		ctx->laddr = endpoint(AF_INET, false, false);
		ctx->raddr = endpoint(AF_INET, true, false);
		ctx->raddr.in.sin_port = htons((uint16_t)(5000 + i));
		ctx->created = ctx->last_seen = now;
		obfs_ctx_setkey(ctx->key, &ctx->raddr.sa);
		CHECK(obfs_ctx_register(f.obfs, ctx));
		if (i % 2 == 0) {
			obfs_ctx_auth(ctx, true);
		}
		if (i != 31) {
			ctx->created = ctx->last_seen = now - f.server.timeout;
		}
		struct session *ss = session_new(&f.server, &ctx->raddr, i + 1);
		CHECK(ss != NULL);
		void *element = ss;
		f.server.sessions =
			table_set(f.server.sessions, &ss->hkey, &element);
		CHECK(element == NULL);
	}
	union sockaddr_max unrelated = endpoint(AF_INET, true, false);
	unrelated.in.sin_port = htons(6000);
	struct session *survivor = session_new(&f.server, &unrelated, 33);
	CHECK(survivor != NULL);
	void *element = survivor;
	f.server.sessions =
		table_set(f.server.sessions, &survivor->hkey, &element);
	CHECK(element == NULL);
	tracked_sessions = f.server.sessions;
	session_passes = 0;
	obfs_timeout_cb(f.server.loop, &f.obfs->w_timeout, EV_TIMER);
	CHECK(session_passes == 1);
	CHECK(table_size(f.obfs->contexts) == 1 &&
	      table_size(f.server.sessions) == 2);
	CHECK(f.obfs->num_authenticated == 0);
	union sockaddr_max remaining = endpoint(AF_INET, true, false);
	remaining.in.sin_port = htons(5031);
	struct obfs_ctx *ctx = obfs_find_ctx(f.obfs, &remaining.sa);
	CHECK(ctx != NULL);
	ctx->created = now - f.server.dial_timeout;
	session_passes = 0;
	obfs_timeout_cb(f.server.loop, &f.obfs->w_timeout, EV_TIMER);
	CHECK(session_passes == 1 && table_size(f.server.sessions) == 1);
	CHECK(table_size(f.obfs->contexts) == 0);
	tracked_sessions = NULL;
	f.server.sessions = table_del(f.server.sessions, &survivor->hkey, NULL);
	session_free(survivor);
	fixture_close(&f);
}

static void
test_raw_constraints(const int domain, const bool device, const bool failure)
{
	struct fixture f;
	fixture_open(&f, false, domain, true);
	f.conf.netdev = device ? "test-device" : NULL;
	fake_raw_sockets = true;
	fail_netdev = failure;
	device_calls = close_calls = 0;
	raw_output_fd = bound_raw_fd = -1;
	CHECK(obfs_raw_start(f.obfs) == !failure);
	CHECK(device_calls == (device ? 1u : 0u));
	CHECK(bound_raw_fd == (device ? raw_output_fd : -1));
	if (failure) {
		CHECK(f.obfs->cap_fd == -1 && f.obfs->raw_fd == -1);
		CHECK(close_calls == 2);
		CHECK(fcntl(raw_output_fd, F_GETFD) == -1 && errno == EBADF);
	} else {
		CHECK(f.obfs->raw_fd == raw_output_fd);
		obfs_raw_close(f.obfs);
		CHECK(close_calls == 2);
	}
	fake_raw_sockets = false;
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
		socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	CHECK(listener >= 0);
	union sockaddr_max addr = { .in = { .sin_family = AF_INET,
					    .sin_addr.s_addr =
						    htonl(INADDR_LOOPBACK) } };
	CHECK(bind(listener, &addr.sa, sa_len(&addr.sa)) == 0);
	CHECK(listen(listener, 1) == 0);
	socklen_t len = sizeof(addr);
	CHECK(getsockname(listener, &addr.sa, &len) == 0);
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
		CHECK(close(accepted) == 0);
	}
	CHECK(close(listener) == 0);
	fixture_close(&f);
}

int main(int argc, char **argv)
{
	CHECK(argc == 2);
	slog_setoutput(SLOG_OUTPUT_STREAM, log_filewriter(stdout));
	slog_setlevel(LOG_LEVEL_WARNING);
	loadlibs();
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
	} else if (strcmp(argv[1], "raw-constraints") == 0) {
		for (int ipv6 = 0; ipv6 < 2; ipv6++) {
			const int domain = ipv6 ? AF_INET6 : AF_INET;
			test_raw_constraints(domain, true, false);
			test_raw_constraints(domain, true, true);
			test_raw_constraints(domain, false, false);
		}
	} else if (strcmp(argv[1], "authenticated-timeout") == 0) {
		for (int raw = 0; raw < 2; raw++) {
			for (int replay = 0; replay < 2; replay++) {
				test_authenticated_timeout(raw, replay);
			}
		}
	} else if (strcmp(argv[1], "batch-expiry") == 0) {
		test_batch_expiry();
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
	unloadlibs();
	return EXIT_SUCCESS;
}
