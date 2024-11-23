/* kcptun-libev (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* obfs.c - a quick & dirty obfuscator */

#include "obfs.h"

#if WITH_OBFS

#include "conf.h"
#include "event.h"
#include "pktqueue.h"
#include "server.h"
#include "session.h"
#include "sockutil.h"
#include "util.h"

#include "algo/hashtable.h"
#include "math/rand.h"
#include "net/http.h"
#include "utils/arraysize.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/formats.h"
#include "utils/slog.h"

#include <ev.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct obfs_stats {
	uintmax_t pkt_cap, pkt_rx, pkt_tx;
	uintmax_t byt_cap, byt_rx, byt_tx;
	uintmax_t byt_drop;
};

struct obfs {
	struct server *server;
	struct hashtable *contexts;
	int cap_fd, raw_fd;
	int fd;
	int domain;
	union sockaddr_max bind_addr;
	size_t num_authenticated;
	struct {
		struct ev_io w_accept;
		struct ev_timer w_listener;
		struct ev_timer w_timeout;
		struct ev_timer w_redial;
	};
	struct obfs_ctx *client; /* for reference only, no ownership */
	int redial_count;
	struct {
		struct obfs_stats stats, last_stats;
		ev_tstamp last_stats_time;
	};
};

#define OBFS_MAX_REQUEST 4096
#define OBFS_MAX_CONTEXTS 4095
#define OBFS_STARTUP_LIMIT_START 10
#define OBFS_STARTUP_LIMIT_RATE 30
#define OBFS_STARTUP_LIMIT_FULL 60

#define OBFS_CTX_KEY_SIZE (sizeof(union sockaddr_max))

struct obfs_ctx {
	unsigned char key[OBFS_CTX_KEY_SIZE];
	struct obfs *obfs;
	struct ev_io w_read, w_write;
	union sockaddr_max laddr, raddr;
	ev_tstamp created;
	ev_tstamp last_seen;
	struct http_message http_msg;
	char *http_nxt;
	int fd;
	struct {
		bool in_table : 1;
		bool captured : 1;
		bool authenticated : 1;
		bool http_keepalive : 1;
		bool cap_ecn : 1;

		uint32_t cap_flow;
		uint32_t cap_seq, cap_ack_seq;

		uintmax_t num_ecn, num_ece;
		uintmax_t pkt_rx, pkt_tx;
		uintmax_t byt_rx, byt_tx;
	};
	struct {
		BUFFER_HDR;
		unsigned char data[OBFS_MAX_REQUEST];
	} rbuf, wbuf;
};

#define OBFS_CTX_GETKEY(ctx)                                                   \
	((struct hashkey){                                                     \
		.len = OBFS_CTX_KEY_SIZE,                                      \
		.data = (ctx)->key,                                            \
	})

static inline struct obfs_ctx *
obfs_find_ctx(const struct obfs *restrict obfs, const struct sockaddr *sa)
{
	unsigned char key[OBFS_CTX_KEY_SIZE];
	const size_t n = getsocklen(sa);
	memcpy(key, (sa), n);
	memset(key + n, 0, sizeof(key) - n);
	const struct hashkey hkey = {
		.len = sizeof(key),
		.data = key,
	};
	struct obfs_ctx *ctx;
	if (!table_find(obfs->contexts, hkey, (void **)&ctx)) {
		return NULL;
	}
	return ctx;
}

#define OBFS_CTX_LOG_F(level, ctx, format, ...)                                \
	do {                                                                   \
		if (LOGLEVEL(level)) {                                         \
			char laddr[64], raddr[64];                             \
			format_sa(laddr, sizeof(laddr), &(ctx)->laddr.sa);     \
			format_sa(raddr, sizeof(raddr), &(ctx)->raddr.sa);     \
			LOG_F(level, "obfs %s<->%s: " format, laddr, raddr,    \
			      __VA_ARGS__);                                    \
		}                                                              \
	} while (0)
#define OBFS_CTX_LOG(level, ctx, message)                                      \
	OBFS_CTX_LOG_F(level, ctx, "%s", message)

/* RFC 2460: Section 8.1 */
struct pseudo_iphdr {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t zero;
	uint8_t protocol;
	uint16_t tot_len;
};

struct pseudo_ip6hdr {
	struct in6_addr src;
	struct in6_addr dst;
	uint32_t plen;
	uint8_t zero[3];
	uint8_t nxt;
};

/* RFC 3168 */
#define ECN_MASK (0x3u)
#define ECN_ECT1 (0x1u)
#define ECN_ECT0 (0x2u)
#define ECN_CE (0x3u)

static void
obfs_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
obfs_server_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
obfs_client_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
obfs_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

static void obfs_sched_redial(struct obfs *restrict obfs);

static void obfs_tcp_setup(const int fd)
{
	socket_set_buffer(fd, 65536, 65536);
	socket_set_tcp(fd, false, false);
	if (setsockopt(
		    fd, SOL_SOCKET, TCP_WINDOW_CLAMP, &(int){ 32768 },
		    sizeof(int))) {
		LOGW_F("TCP_WINDOW_CLAMP: %s", strerror(errno));
	}
}

static void obfs_tcp_quickack(const int fd, const bool enabled)
{
	const int val = enabled ? 1 : 0;
	if (setsockopt(fd, SOL_SOCKET, TCP_QUICKACK, &val, sizeof(val))) {
		LOGW_F("TCP_QUICKACK: %s", strerror(errno));
	}
}

struct filter_compiler_ctx {
	struct sock_filter *filter;
	uint16_t cap, len;
};

#define FILTER_GENCODE(ctx, fragment)                                          \
	do {                                                                   \
		if ((ctx)->len + ARRAY_SIZE(fragment) > (ctx)->cap) {          \
			return false;                                          \
		}                                                              \
		for (size_t i = 0; i < ARRAY_SIZE(fragment); i++) {            \
			(ctx)->filter[(ctx)->len++] = (fragment)[i];           \
		}                                                              \
	} while (false)

static bool filter_compile_inet(
	struct filter_compiler_ctx *restrict ctx, const struct sockaddr_in *sa)
{
	/* "(ip proto \\tcp) and (dst port 80) and (dst host 1.2.3.4)" */
	const struct sock_filter tcpip4[] = {
		/* IP version */
		BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0x0u),
		BPF_STMT(BPF_ALU | BPF_K | BPF_AND, 0xf0u),
		BPF_JUMP(BPF_JMP | BPF_K | BPF_JEQ, 0x40u, 0, -1),
		/* protocol */
		BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0x9u),
		BPF_JUMP(BPF_JMP | BPF_K | BPF_JEQ, IPPROTO_TCP, 0, -1),
		/* IP fragment */
		BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0x6u),
		BPF_JUMP(BPF_JMP | BPF_K | BPF_JSET, 0x1fffu, -1, 0),
	};
	FILTER_GENCODE(ctx, tcpip4);
	if (sa->sin_port != 0) {
		const uint16_t port = ntohs(sa->sin_port);
		const struct sock_filter ipv4_port[] = {
			/* TCP port */
			BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0x0u),
			BPF_STMT(BPF_LD | BPF_H | BPF_IND, 0x2u),
			BPF_JUMP(BPF_JMP | BPF_K | BPF_JEQ, port, 0, -1),
		};
		FILTER_GENCODE(ctx, ipv4_port);
	}
	if (sa->sin_addr.s_addr != INADDR_ANY) {
		const in_addr_t addr = ntohl(sa->sin_addr.s_addr);
		const struct sock_filter ipv4_addr[] = {
			/* IP destination */
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0x10u),
			BPF_JUMP(BPF_JMP | BPF_K | BPF_JEQ, addr, 0, -1),
		};
		FILTER_GENCODE(ctx, ipv4_addr);
	}
	return true;
}

static bool filter_compile_inet6(
	struct filter_compiler_ctx *restrict ctx, const struct sockaddr_in6 *sa)
{
	/* "(ip6 proto \\tcp) and (dst port 80) and (dst host 1:2:3:4:5:6:7:8)" */
	const struct sock_filter tcpip6[] = {
		/* IP version */
		BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0x0u),
		BPF_STMT(BPF_ALU | BPF_K | BPF_AND, 0xf0u),
		BPF_JUMP(BPF_JMP | BPF_K | BPF_JEQ, 0x60u, 0, -1),
		/* protocol */
		BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0x6u),
		BPF_JUMP(BPF_JMP | BPF_K | BPF_JEQ, IPPROTO_TCP, 0, -1),
	};
	FILTER_GENCODE(ctx, tcpip6);
	if (sa->sin6_port != 0) {
		const uint16_t port = ntohs(sa->sin6_port);
		const struct sock_filter ipv6_port[] = {
			/* TCP port */
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0x2au),
			BPF_JUMP(BPF_JMP | BPF_K | BPF_JEQ, port, 0, -1),
		};
		FILTER_GENCODE(ctx, ipv6_port);
	}
	if (!IN6_IS_ADDR_UNSPECIFIED(&sa->sin6_addr)) {
		const struct sock_filter ipv6_addr[] = {
			/* IPv6 destination */
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0x18u),
			BPF_JUMP(
				BPF_JMP | BPF_K | BPF_JEQ,
				ntohl(sa->sin6_addr.s6_addr32[0]), 0, -1),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0x1cu),
			BPF_JUMP(
				BPF_JMP | BPF_K | BPF_JEQ,
				ntohl(sa->sin6_addr.s6_addr32[1]), 0, -1),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0x20u),
			BPF_JUMP(
				BPF_JMP | BPF_K | BPF_JEQ,
				ntohl(sa->sin6_addr.s6_addr32[2]), 0, -1),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0x24u),
			BPF_JUMP(
				BPF_JMP | BPF_K | BPF_JEQ,
				ntohl(sa->sin6_addr.s6_addr32[3]), 0, -1),
		};
		FILTER_GENCODE(ctx, ipv6_addr);
	}
	return true;
}

static bool
filter_compile(struct sock_fprog *restrict fprog, const struct sockaddr *addr)
{
	struct filter_compiler_ctx ctx = {
		.filter = fprog->filter,
		.cap = fprog->len,
		.len = 0,
	};

	switch (addr->sa_family) {
	case AF_INET:
		if (!filter_compile_inet(
			    &ctx, (const struct sockaddr_in *)addr)) {
			return false;
		}
		break;
	case AF_INET6:
		if (!filter_compile_inet6(
			    &ctx, (const struct sockaddr_in6 *)addr)) {
			return false;
		}
		break;
	}
	const struct sock_filter ret[] = {
		BPF_STMT(BPF_RET | BPF_K, -1),
		BPF_STMT(BPF_RET | BPF_K, 0),
	};
	FILTER_GENCODE(&ctx, ret);

	/* link */
	for (uint16_t i = 0; i < ctx.len; i++) {
		const uint8_t off = ctx.len - (i + 1u);
		if ((int8_t)ctx.filter[i].jt < 0) {
			ctx.filter[i].jt += off;
		}
		if ((int8_t)ctx.filter[i].jf < 0) {
			ctx.filter[i].jf += off;
		}
	}
	fprog->len = ctx.len;
	return true;
}

#undef FILTER_GENCODE

static void
obfs_bind(struct obfs *restrict obfs, const struct sockaddr *restrict sa)
{
	if (sa != NULL) {
		copy_sa(&obfs->bind_addr.sa, sa);
	}

	const struct sockaddr *restrict bind_sa = &obfs->bind_addr.sa;
	uint32_t scope_id = 0;
	if (bind_sa->sa_family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(bind_sa)) {
		scope_id = ((struct sockaddr_in6 *)bind_sa)->sin6_scope_id;
	}
	unsigned int ifindex = 0;
	const struct config *restrict conf = obfs->server->conf;
	if (conf->netdev != NULL) {
		ifindex = if_nametoindex(conf->netdev);
		if (ifindex == 0) {
			LOGW_F("obfs invalid netdev `%s': %s", conf->netdev,
			       strerror(errno));
		} else {
			LOGD_F("obfs netdev `%s': index=%d", conf->netdev,
			       ifindex);
		}
	}
	if (scope_id != 0 && ifindex != scope_id) {
		if (ifindex != 0) {
			LOGW("obfs bind: netdev that differs from the address scope is ignored");
		}
		ifindex = scope_id;
	}
	if (ifindex != 0) {
		LOGD_F("obfs bind: device index=%u", ifindex);
	}

	struct sockaddr_ll addr = {
		.sll_family = AF_PACKET,
		.sll_ifindex = (int)ifindex,
	};
	switch (obfs->domain) {
	case AF_INET:
		addr.sll_protocol = htons(ETH_P_IP);
		break;
	case AF_INET6:
		addr.sll_protocol = htons(ETH_P_IPV6);
		break;
	default:
		FAIL();
	}
	if (bind(obfs->cap_fd, (struct sockaddr *)&addr, sizeof(addr))) {
		LOGW_F("cap bind: %s", strerror(errno));
	}
	struct sock_filter filter[32];
	struct sock_fprog fprog = {
		.filter = filter,
		.len = ARRAY_SIZE(filter),
	};
	if (!filter_compile(&fprog, bind_sa)) {
		LOGW("obfs: cap filter failed");
		return;
	}
	if (setsockopt(
		    obfs->cap_fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog,
		    sizeof(fprog))) {
		LOGW_F("cap filter: %s", strerror(errno));
	}
	if (LOGLEVEL(NOTICE)) {
		char addr_str[64];
		format_sa(addr_str, sizeof(addr_str), bind_sa);
		LOG_F(NOTICE, "obfs bind: %s", addr_str);
	}
}

static bool obfs_raw_start(struct obfs *restrict obfs)
{
	const int domain = obfs->domain;
	const struct config *restrict conf = obfs->server->conf;
	uint16_t protocol;
	switch (domain) {
	case AF_INET:
		protocol = htons(ETH_P_IP);
		break;
	case AF_INET6:
		protocol = htons(ETH_P_IPV6);
		break;
	default:
		FAIL();
	}
	obfs->cap_fd = socket(PF_PACKET, SOCK_DGRAM, protocol);
	if (obfs->cap_fd < 0) {
		LOGE_F("obfs capture: %s", strerror(errno));
		return false;
	}
	if (!socket_set_nonblock(obfs->cap_fd)) {
		LOGE_F("fcntl: %s", strerror(errno));
		return false;
	}
	socket_set_buffer(obfs->cap_fd, 0, conf->udp_rcvbuf);

	obfs->raw_fd = socket(domain, SOCK_RAW, IPPROTO_RAW);
	if (obfs->raw_fd < 0) {
		LOGE_F("obfs raw: %s", strerror(errno));
		return false;
	}
	if (!socket_set_nonblock(obfs->raw_fd)) {
		LOGE_F("fcntl: %s", strerror(errno));
		return false;
	}
	switch (domain) {
	case AF_INET:
		if (setsockopt(
			    obfs->raw_fd, IPPROTO_IP, IP_HDRINCL, &(int){ 1 },
			    sizeof(int))) {
			LOGE_F("raw setup: %s", strerror(errno));
			return false;
		}
		break;
	case AF_INET6:
		if (setsockopt(
			    obfs->raw_fd, IPPROTO_IPV6, IPV6_HDRINCL,
			    &(int){ 1 }, sizeof(int))) {
			LOGE_F("raw setup: %s", strerror(errno));
			return false;
		}
		break;
	default:
		FAIL();
	}
	socket_set_buffer(obfs->raw_fd, conf->udp_sndbuf, 0);
	return true;
}

static void obfs_ctx_free(struct ev_loop *loop, struct obfs_ctx *ctx)
{
	if (ctx == NULL) {
		return;
	}
	if (ctx->fd != -1) {
		struct ev_io *restrict w_read = &ctx->w_read;
		ev_io_stop(loop, w_read);
		struct ev_io *restrict w_write = &ctx->w_write;
		ev_io_stop(loop, w_write);
		CLOSE_FD(ctx->fd);
		ctx->fd = -1;
	}
	free(ctx);
}

static struct obfs_ctx *obfs_ctx_new(struct obfs *restrict obfs)
{
	struct obfs_ctx *restrict ctx = malloc(sizeof(struct obfs_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	ctx->obfs = obfs;
	ctx->fd = -1;
	ctx->http_msg = (struct http_message){ 0 };
	ctx->http_nxt = NULL;
	ctx->cap_ecn = false;
	ctx->captured = false;
	ctx->authenticated = false;
	ctx->http_keepalive = false;
	ctx->num_ecn = ctx->num_ece = 0;
	ctx->pkt_rx = ctx->pkt_tx = 0;
	ctx->byt_rx = ctx->byt_tx = 0;
	ctx->created = ctx->last_seen = TSTAMP_NIL;
	BUF_INIT(ctx->rbuf, 0);
	BUF_INIT(ctx->wbuf, 0);
	return ctx;
}

static bool ctx_del_filter(
	const struct hashtable *t, const struct hashkey key, void *element,
	void *user)
{
	UNUSED(t);
	UNUSED(key);
	struct session *restrict ss = element;
	ASSERT(key.data == ss->key);
	if (sa_equals(&ss->raddr.sa, user)) {
		session_free(element);
		return false;
	}
	return true;
}

static void
obfs_ctx_del(struct obfs *restrict obfs, struct obfs_ctx *restrict ctx)
{
	if (ctx->authenticated) {
		ASSERT(obfs->num_authenticated > 0u);
		obfs->num_authenticated--;
		OBFS_CTX_LOG(INFO, ctx, "closed");
	}
	if (obfs->client == ctx) {
		obfs_sched_redial(obfs);
	}
	/* free all related sessions */
	struct server *restrict s = obfs->server;
	s->sessions = table_filter(s->sessions, ctx_del_filter, &ctx->raddr.sa);
	if (ctx->in_table) {
		obfs->contexts =
			table_del(obfs->contexts, OBFS_CTX_GETKEY(ctx), NULL);
		ctx->in_table = false;
	}
}

static void obfs_ctx_stop(struct ev_loop *loop, struct obfs_ctx *restrict ctx)
{
	ev_io_stop(loop, &ctx->w_read);
	ev_io_stop(loop, &ctx->w_write);
}

static void obfs_ctx_write(struct obfs_ctx *restrict ctx, struct ev_loop *loop)
{
	struct obfs *restrict obfs = ctx->obfs;
	unsigned char *data = ctx->wbuf.data;
	size_t nbsend = 0;
	size_t len = ctx->wbuf.len;
	while (len > 0) {
		const ssize_t nsend = send(ctx->fd, data, len, 0);
		if (nsend < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			LOGE_F("obfs: %s", strerror(err));
			obfs_ctx_del(obfs, ctx);
			obfs_ctx_free(loop, ctx);
			return;
		}
		data += nsend;
		len -= nsend;
		nbsend += nsend;
	}
	ctx->wbuf.len += nbsend;
	struct ev_io *restrict w_write = &ctx->w_write;
	if (len > 0) {
		BUF_CONSUME(ctx->wbuf, nbsend);
		if (!ev_is_active(w_write)) {
			ev_io_start(loop, w_write);
		}
		return;
	}
	if (!ctx->http_keepalive) {
		OBFS_CTX_LOG(DEBUG, ctx, "server close");
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	}
	if (ev_is_active(w_write)) {
		ev_io_stop(loop, w_write);
	}
}

static bool obfs_ctx_start(
	struct obfs *restrict obfs, struct obfs_ctx *restrict ctx, const int fd)
{
	{
		const struct sockaddr *sa = &ctx->raddr.sa;
		const size_t n = getsocklen(sa);
		memcpy(ctx->key, sa, n);
		memset(ctx->key + n, 0, sizeof(ctx->key) - n);
	}
	struct server *restrict s = obfs->server;

	if ((s->conf->mode & MODE_SERVER) &&
	    table_find(obfs->contexts, OBFS_CTX_GETKEY(ctx), NULL)) {
		/* replacing ctx is not allowed in server */
		return false;
	}

	void *elem = ctx;
	obfs->contexts = table_set(obfs->contexts, OBFS_CTX_GETKEY(ctx), &elem);
	if (elem != NULL) {
		struct obfs_ctx *restrict old_ctx = elem;
		old_ctx->in_table = false;
		OBFS_CTX_LOG(DEBUG, old_ctx, "context replaced");
		obfs_ctx_stop(s->loop, old_ctx);
		obfs_ctx_del(obfs, old_ctx);
		obfs_ctx_free(s->loop, old_ctx);
	}
	ctx->in_table = true;

	ctx->fd = fd;
	void (*const obfs_read_cb)(
		struct ev_loop * loop, struct ev_io * watcher, int revents) =
		(s->conf->mode & MODE_CLIENT) ? obfs_client_read_cb :
						obfs_server_read_cb;
	struct ev_io *restrict w_read = &ctx->w_read;
	ev_io_init(w_read, obfs_read_cb, fd, EV_READ);
	w_read->data = ctx;
	ev_io_start(s->loop, w_read);
	struct ev_io *restrict w_write = &ctx->w_write;
	ev_io_init(w_write, obfs_write_cb, fd, EV_WRITE);
	w_write->data = ctx;

	const ev_tstamp now = ev_now(s->loop);
	ctx->created = now;
	ctx->last_seen = now;
	if (LOGLEVEL(DEBUG)) {
		char laddr[64], raddr[64];
		format_sa(laddr, sizeof(laddr), &ctx->laddr.sa);
		format_sa(raddr, sizeof(raddr), &ctx->raddr.sa);
		LOG_F(DEBUG, "obfs: start %s <-> %s", laddr, raddr);
	}
	return true;
}

static bool
obfs_tcp_listen(struct obfs *restrict obfs, const struct sockaddr *restrict sa)
{
	const struct config *restrict conf = obfs->server->conf;
	obfs->fd = socket(obfs->domain, SOCK_STREAM, IPPROTO_TCP);
	if (obfs->fd < 0) {
		LOGE_F("obfs tcp: %s", strerror(errno));
		return false;
	}
	if (!socket_set_nonblock(obfs->fd)) {
		LOGE_F("fcntl: %s", strerror(errno));
		return false;
	}
	socket_set_reuseport(obfs->fd, conf->tcp_reuseport);
	obfs_tcp_setup(obfs->fd);
	if (bind(obfs->fd, sa, getsocklen(sa))) {
		LOGE_F("obfs tcp bind: %s", strerror(errno));
		return false;
	}
	if (listen(obfs->fd, 16)) {
		LOGE_F("obfs tcp listen: %s", strerror(errno));
		return false;
	}
	if (LOGLEVEL(INFO)) {
		char addr_str[64];
		format_sa(addr_str, sizeof(addr_str), sa);
		LOG_F(INFO, "obfs tcp listen: %s", addr_str);
	}
	return true;
}

static bool obfs_ctx_dial(struct obfs *restrict obfs, const struct sockaddr *sa)
{
	struct server *restrict s = obfs->server;
	ASSERT(s->conf->mode & MODE_CLIENT);
	int fd = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		LOGE_F("obfs tcp: %s", strerror(errno));
		return false;
	}
	if (!socket_set_nonblock(fd)) {
		LOGE_F("fcntl: %s", strerror(errno));
		CLOSE_FD(fd);
		return false;
	}
	obfs_tcp_setup(fd);
	struct obfs_ctx *restrict ctx = obfs_ctx_new(obfs);
	if (ctx == NULL) {
		return false;
	}

	struct ev_loop *loop = s->loop;
	if (connect(fd, sa, getsocklen(sa))) {
		const int err = errno;
		if (err != EINTR && err != EINPROGRESS) {
			LOGE_F("obfs tcp connect: %s", strerror(err));
			obfs_ctx_free(loop, ctx);
			return false;
		}
	}
	socklen_t len = sizeof(ctx->laddr);
	if (getsockname(fd, &ctx->laddr.sa, &len)) {
		LOGE_F("obfs client name: %s", strerror(errno));
		obfs_ctx_free(loop, ctx);
		return false;
	}
	copy_sa(&ctx->raddr.sa, sa);
	OBFS_CTX_LOG(INFO, ctx, "connect");

	obfs_bind(obfs, &ctx->laddr.sa);
	if (!obfs_ctx_start(obfs, ctx, fd)) {
		obfs_ctx_free(loop, ctx);
		return false;
	}
	obfs->client = ctx;

	/* send the request */
	char addr_str[64];
	format_sa(addr_str, sizeof(addr_str), &ctx->raddr.sa);
	char *b = (char *)ctx->wbuf.data;
	const int ret = snprintf(
		b, ctx->wbuf.cap,
		"GET /generate_204 HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: curl/7.81.0\r\n"
		"Accept: */*\r\n\r\n",
		addr_str);
	CHECK(ret > 0);
	ctx->wbuf.len = (size_t)ret;
	ctx->http_keepalive = true;
	obfs_ctx_write(ctx, loop);
	return true;
}

void obfs_sched_redial(struct obfs *restrict obfs)
{
	struct server *restrict s = obfs->server;
	const struct config *restrict conf = s->conf;
	if (!(conf->mode & MODE_CLIENT)) {
		return;
	}
	struct ev_timer *restrict w_redial = &obfs->w_redial;
	if (ev_is_active(w_redial) || ev_is_pending(w_redial)) {
		return;
	}
	obfs->client = NULL;
	struct ev_loop *loop = s->loop;
	const int redial_count = obfs->redial_count;
	if (redial_count < 1) {
		ev_feed_event(loop, w_redial, EV_TIMER);
		return;
	}
	static const double wait_schedule[] = {
		0.2,  2.0,  2.0,  5.0,	5.0,   15.0,
		15.0, 15.0, 60.0, 60.0, 120.0, 300.0,
	};
	const double wait_time = wait_schedule[CLAMP(
		redial_count - 1, 0, (int)ARRAY_SIZE(wait_schedule) - 1)];
	if (LOGLEVEL(DEBUG)) {
		LOG_F(DEBUG, "obfs: scheduled redial #%d after %.0fs",
		      redial_count, wait_time);
	}
	ev_timer_set(w_redial, wait_time, 0.0);
	ev_timer_start(loop, w_redial);
}

static bool obfs_ctx_timeout_filt(
	const struct hashtable *t, const struct hashkey key, void *element,
	void *user)
{
	UNUSED(t);
	UNUSED(key);
	struct obfs *restrict obfs = user;
	struct ev_loop *loop = obfs->server->loop;
	struct obfs_ctx *restrict ctx = element;
	ASSERT(key.data == ctx->key);
	const ev_tstamp now = ev_now(loop);
	ASSERT(now >= ctx->last_seen);
	double not_seen, timeout;
	if (ctx->authenticated) {
		not_seen = now - ctx->last_seen;
		timeout = obfs->server->timeout;
	} else {
		not_seen = now - ctx->created;
		timeout = obfs->server->dial_timeout;
	}
	if (not_seen < timeout) {
		return true;
	}
	if (ctx->authenticated) {
		OBFS_CTX_LOG_F(INFO, ctx, "timeout after %.1lfs", not_seen);
	} else {
		OBFS_CTX_LOG_F(DEBUG, ctx, "timeout after %.1lfs", not_seen);
	}
	ctx->in_table = false;
	obfs_ctx_del(obfs, ctx);
	obfs_ctx_free(loop, ctx);
	return false;
}

static void
obfs_redial_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	UNUSED(loop);
	CHECK_REVENTS(revents, EV_TIMER);
	struct obfs *restrict obfs = watcher->data;
	struct server *restrict s = obfs->server;
	const struct config *restrict conf = s->conf;
	if (obfs->client != NULL) {
		return;
	}
	const int redial_count = ++obfs->redial_count;
	LOGI_F("obfs: redial #%d to `%s'", redial_count, conf->kcp_connect);
	union sockaddr_max addr;
	if (!resolve_addr(&addr, conf->kcp_connect, RESOLVE_TCP)) {
		return;
	}
	if (!obfs_ctx_dial(obfs, &addr.sa)) {
		return;
	}
	copy_sa(&s->pkt.kcp_connect.sa, &addr.sa);
}

static void
obfs_listener_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct obfs *restrict obfs = watcher->data;
	/* check & restart accept watcher */
	struct ev_io *restrict w_accept = &obfs->w_accept;
	if (obfs->fd != -1 && !ev_is_active(w_accept)) {
		ev_io_start(loop, w_accept);
	}
}

static void
obfs_timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	UNUSED(loop);
	CHECK_REVENTS(revents, EV_TIMER);
	struct obfs *restrict obfs = watcher->data;
	/* context timeout */
	obfs->contexts =
		table_filter(obfs->contexts, obfs_ctx_timeout_filt, obfs);
}

struct obfs *obfs_new(struct server *restrict s)
{
	struct obfs *obfs = NULL;
	const struct config *restrict conf = s->conf;
	if (strcmp(conf->obfs, "dpi/tcp-wnd") == 0) {
		obfs = malloc(sizeof(struct obfs));
		if (obfs == NULL) {
			LOGOOM();
			return NULL;
		}
		*obfs = (struct obfs){
			.server = s,
			.cap_fd = -1,
			.raw_fd = -1,
			.fd = -1,
			.last_stats_time = ev_now(s->loop),
		};
		int flags = 0;
		if ((conf->mode & MODE_SERVER) != 0) {
			flags |= TABLE_FAST;
		}
		obfs->contexts = table_new(flags);
		if (obfs->contexts == NULL) {
			LOGOOM();
			free(obfs);
			return NULL;
		}
	}
	return obfs;
}

bool obfs_resolve(struct obfs *obfs)
{
	const struct config *restrict conf = obfs->server->conf;
	if (conf->mode & MODE_SERVER) {
		obfs_bind(obfs, NULL);
	} else if (conf->mode & MODE_CLIENT) {
		obfs_sched_redial(obfs);
	}
	return true;
}

struct obfs_stats_ctx {
	ev_tstamp now;
	struct vbuffer *restrict buf;
};

static bool print_ctx_iter(
	const struct hashtable *t, const struct hashkey key, void *element,
	void *user)
{
	UNUSED(t);
	UNUSED(key);
	const struct obfs_ctx *restrict ctx = element;
	ASSERT(key.data == ctx->key);
	struct obfs_stats_ctx *restrict stats = user;
	char addr_str[64];
	format_sa(addr_str, sizeof(addr_str), &ctx->raddr.sa);
	char state = '>';
	if (ctx->captured) {
		state = ctx->authenticated ? '-' : '?';
	}

#define FORMAT_BYTES(name, value)                                              \
	char name[16];                                                         \
	(void)format_iec_bytes(name, sizeof(name), (value))

	FORMAT_BYTES(byt_rx, (double)(ctx->byt_rx));
	FORMAT_BYTES(byt_tx, (double)(ctx->byt_tx));

#undef FORMAT_BYTES

	stats->buf = VBUF_APPENDF(
		stats->buf, "[%s] %c seen=%.0lfs rx/tx=%s/%s ecn/ece=%ju/%ju\n",
		addr_str, state, stats->now - ctx->last_seen, byt_rx, byt_tx,
		ctx->num_ecn, ctx->num_ece);
	return true;
}

struct vbuffer *obfs_stats_const(const struct obfs *obfs, struct vbuffer *buf)
{
	const ev_tstamp now = ev_now(obfs->server->loop);

	struct obfs_stats_ctx stats_ctx = {
		.now = now,
		.buf = buf,
	};
	table_iterate(obfs->contexts, print_ctx_iter, &stats_ctx);
	buf = stats_ctx.buf;

	const size_t num_contexts = table_size(obfs->contexts);
	const size_t authenticated = obfs->num_authenticated;
	ASSERT(authenticated <= num_contexts);

	const struct obfs_stats *restrict stats = &obfs->stats;

#define FORMAT_BYTES(name, value)                                              \
	char name[16];                                                         \
	(void)format_iec_bytes(name, sizeof(name), (value))

	FORMAT_BYTES(byt_drop, (double)(stats->byt_drop));

#undef FORMAT_BYTES

	buf = VBUF_APPENDF(
		buf, "  = %zu(+%zu) contexts; drop %s\n", authenticated,
		num_contexts - authenticated, byt_drop);
	return buf;
}

struct vbuffer *
obfs_stats(struct obfs *restrict obfs, struct vbuffer *restrict buf)
{
	const ev_tstamp now = ev_now(obfs->server->loop);

	struct obfs_stats_ctx stats_ctx = {
		.now = now,
		.buf = buf,
	};
	table_iterate(obfs->contexts, print_ctx_iter, &stats_ctx);
	buf = stats_ctx.buf;

	const double dt = now - obfs->last_stats_time;
	const struct obfs_stats *restrict stats = &obfs->stats;
	const struct obfs_stats *restrict last_stats = &obfs->last_stats;
	const struct obfs_stats dstats = {
		.pkt_cap = stats->pkt_cap - last_stats->pkt_cap,
		.byt_cap = stats->byt_cap - last_stats->byt_cap,
		.pkt_rx = stats->pkt_rx - last_stats->pkt_rx,
		.byt_rx = stats->byt_rx - last_stats->byt_rx,
		.pkt_tx = stats->pkt_tx - last_stats->pkt_tx,
		.byt_tx = stats->byt_tx - last_stats->byt_tx,
		.byt_drop = stats->byt_drop - last_stats->byt_drop,
	};

	const size_t num_contexts = table_size(obfs->contexts);
	const size_t authenticated = obfs->num_authenticated;
	ASSERT(authenticated <= num_contexts);

#define FORMAT_BYTES(name, value)                                              \
	char name[16];                                                         \
	(void)format_iec_bytes(name, sizeof(name), (value))

	const double dpkt_drop = (double)(dstats.pkt_cap - dstats.pkt_rx) / dt;
	FORMAT_BYTES(dbyt_drop, (double)(dstats.byt_drop) / dt);
	FORMAT_BYTES(byt_drop, (double)(stats->byt_drop));

#undef FORMAT_BYTES

	buf = VBUF_APPENDF(
		buf, "  = %zu(+%zu) contexts; drop %.1lf/s (%s/s), %s\n",
		authenticated, num_contexts - authenticated, dpkt_drop,
		dbyt_drop, byt_drop);

	/* rotate stats */
	obfs->last_stats = obfs->stats;
	obfs->last_stats_time = now;
	return buf;
}

bool obfs_start(struct obfs *restrict obfs, struct server *restrict s)
{
	const struct config *restrict conf = obfs->server->conf;
	struct pktconn *restrict pkt = &s->pkt;
	if (conf->mode & MODE_SERVER) {
		union sockaddr_max addr;
		if (!resolve_addr(
			    &addr, conf->kcp_bind,
			    RESOLVE_TCP | RESOLVE_PASSIVE)) {
			return false;
		}
		obfs->domain = addr.sa.sa_family;
		if (!obfs_raw_start(obfs)) {
			return false;
		}
		obfs_bind(obfs, &addr.sa);
		if (!obfs_tcp_listen(obfs, &addr.sa)) {
			return false;
		}
	}
	if (conf->mode & MODE_CLIENT) {
		union sockaddr_max addr;
		if (!resolve_addr(&addr, conf->kcp_connect, RESOLVE_TCP)) {
			return false;
		}
		obfs->domain = addr.sa.sa_family;
		if (!obfs_raw_start(obfs)) {
			return false;
		}
		if (!obfs_ctx_dial(obfs, &addr.sa)) {
			return false;
		}
		copy_sa(&s->pkt.kcp_connect.sa, &addr.sa);
	}

	{
		struct ev_io *restrict w_read = &pkt->w_read;
		ev_io_init(w_read, &pkt_read_cb, obfs->cap_fd, EV_READ);
		w_read->data = s;
		ev_io_start(s->loop, w_read);

		struct ev_io *restrict w_write = &pkt->w_write;
		ev_io_init(w_write, &pkt_write_cb, obfs->raw_fd, EV_WRITE);
		w_write->data = s;
		ev_io_start(s->loop, w_write);
	}

	if (obfs->fd != -1) {
		struct ev_io *restrict w_accept = &obfs->w_accept;
		ev_io_init(w_accept, obfs_accept_cb, obfs->fd, EV_READ);
		ev_set_priority(w_accept, EV_MINPRI);
		w_accept->data = obfs;
		ev_io_start(s->loop, w_accept);
	}
	{
		struct ev_timer *restrict w_listener = &obfs->w_listener;
		ev_timer_init(w_listener, obfs_listener_cb, 0.5, 0.0);
		ev_set_priority(w_listener, EV_MINPRI);
		w_listener->data = obfs;

		struct ev_timer *restrict w_timeout = &obfs->w_timeout;
		ev_timer_init(w_timeout, obfs_timeout_cb, 10.0, 10.0);
		ev_set_priority(w_timeout, EV_MINPRI);
		w_timeout->data = obfs;
		ev_timer_start(s->loop, w_timeout);

		struct ev_timer *restrict w_redial = &obfs->w_redial;
		ev_timer_init(w_redial, obfs_redial_cb, 5.0, 0.0);
		ev_set_priority(w_redial, EV_MINPRI);
		w_redial->data = obfs;
	}
	return true;
}

static bool obfs_shutdown_filt(
	const struct hashtable *t, const struct hashkey key, void *element,
	void *user)
{
	UNUSED(t);
	UNUSED(key);
	struct obfs_ctx *restrict ctx = element;
	ASSERT(key.data == ctx->key);
	struct obfs *restrict obfs = (struct obfs *)user;
	obfs_ctx_free(obfs->server->loop, ctx);
	return false;
}

void obfs_stop(struct obfs *restrict obfs, struct server *s)
{
	obfs->contexts = table_filter(obfs->contexts, obfs_shutdown_filt, obfs);
	obfs->client = NULL;
	struct ev_loop *loop = obfs->server->loop;
	ev_timer_stop(loop, &obfs->w_listener);
	ev_timer_stop(loop, &obfs->w_timeout);
	if (obfs->fd != -1) {
		ev_io_stop(loop, &obfs->w_accept);
		CLOSE_FD(obfs->fd);
		obfs->fd = -1;
	}
	struct pktconn *restrict pkt = &s->pkt;
	if (obfs->cap_fd != -1) {
		ev_io_stop(loop, &pkt->w_read);
		CLOSE_FD(obfs->cap_fd);
		obfs->cap_fd = -1;
	}
	if (obfs->raw_fd != -1) {
		ev_io_stop(loop, &pkt->w_write);
		CLOSE_FD(obfs->raw_fd);
		obfs->raw_fd = -1;
	}
}

void obfs_free(struct obfs *obfs)
{
	if (obfs == NULL) {
		return;
	}
	table_free(obfs->contexts);
	free(obfs);
}

size_t obfs_overhead(const struct obfs *restrict obfs)
{
	switch (obfs->domain) {
	case AF_INET:
		return sizeof(struct iphdr) + sizeof(struct tcphdr);
	case AF_INET6:
		return sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
	default:
		break;
	}
	FAIL();
}

/* RFC 1071 */
static inline uint32_t in_cksum(uint32_t sum, const void *data, size_t n)
{
	ASSERT(!(n & 1));
	const uint16_t *b = data;
	while (n > 1) {
		sum += *b++;
		n -= 2;
	}
	return sum;
}

static inline uint16_t in_cksum_fin(uint32_t sum, const void *data, size_t n)
{
	const uint16_t *b = data;
	while (n > 1) {
		sum += *b++;
		n -= 2;
	}
	if (n == 1) {
		uint16_t odd = 0;
		*(uint8_t *)(&odd) = *(uint8_t *)b;
		sum += odd;
	}

	sum = (sum >> 16u) + (sum & 0xffffu);
	sum += (sum >> 16u);
	return ~(uint16_t)(sum);
}

static void obfs_capture(
	struct obfs_ctx *ctx, const uint32_t flow, const uint8_t ecn,
	const struct tcphdr *restrict tcp)
{
	if (ecn == ECN_CE) {
		ctx->cap_ecn = true;
		ctx->num_ecn++;
	}
	/* RFC 3168: Section 6.1 */
	if (tcp->res2 & 0x1u) {
		ctx->num_ece++;
	}
	if (ctx->captured) {
		return;
	}
	ctx->cap_flow = flow;
	ctx->cap_seq = ntohl(tcp->seq);
	ctx->cap_ack_seq = ntohl(tcp->ack_seq);
	ctx->captured = true;
	OBFS_CTX_LOG(DEBUG, ctx, "captured");
}

static struct obfs_ctx *
obfs_open_ipv4(struct obfs *restrict obfs, struct msgframe *restrict msg)
{
	struct iphdr ip;
	struct tcphdr tcp;
	memcpy(&ip, msg->buf, sizeof(ip));
	if ((uint8_t)ip.version != IPVERSION || ip.protocol != IPPROTO_TCP) {
		return NULL;
	}
	const uint16_t ihl = (uint16_t)ip.ihl * UINT16_C(4);
	if (ihl < sizeof(struct iphdr)) {
		return NULL;
	}
	const uint16_t tot_len = ntohs(ip.tot_len);
	if (tot_len < ihl || msg->len < tot_len) {
		return NULL;
	}
	const uint16_t plen = tot_len - ihl;
	if (plen < sizeof(struct tcphdr)) {
		return NULL;
	}
	memcpy(&tcp, msg->buf + ihl, sizeof(struct tcphdr));
	const uint16_t doff = tcp.doff * UINT16_C(4);
	if (doff < sizeof(struct tcphdr) || plen < doff) {
		return NULL;
	}
	if ((ntohl(ip.saddr) >> IN_CLASSA_NSHIFT) != IN_LOOPBACKNET) {
		const struct pseudo_iphdr pseudo = {
			.saddr = ip.saddr,
			.daddr = ip.daddr,
			.protocol = IPPROTO_TCP,
			.tot_len = htons(plen),
		};
		const uint16_t check = tcp.check;
		tcp.check = 0;
		uint32_t sum = 0;
		sum = in_cksum(sum, &pseudo, sizeof(pseudo));
		sum = in_cksum(sum, &tcp, sizeof(tcp));
		const unsigned char *remain = &msg->buf[ihl + sizeof(tcp)];
		if (in_cksum_fin(sum, remain, plen - sizeof(tcp)) != check) {
			return NULL;
		}
	}
	const struct sockaddr_in dest = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = ip.daddr,
		.sin_port = tcp.dest,
	};
	if (!sa_matches(&obfs->bind_addr.sa, (struct sockaddr *)&dest)) {
		return NULL;
	}
	msg->addr.in = (struct sockaddr_in){
		.sin_family = AF_INET,
		.sin_addr.s_addr = ip.saddr,
		.sin_port = tcp.source,
	};

	struct obfs_ctx *restrict ctx = obfs_find_ctx(obfs, &msg->addr.sa);
	if (ctx == NULL) {
		if (LOGLEVEL(DEBUG)) {
			char addr_str[64];
			format_sa(addr_str, sizeof(addr_str), &msg->addr.sa);
			const ev_tstamp now = ev_now(obfs->server->loop);
			LOG_RATELIMITED_F(
				DEBUG, now, 1.0,
				"* obfs: unrelated %" PRIu16 " bytes from %s",
				msg->len, addr_str);
		}
		return NULL;
	}

	/* inbound */
	if (LOGLEVEL(DEBUG) && tcp.rst) {
		char addr_str[64];
		format_sa(addr_str, sizeof(addr_str), &msg->addr.sa);
		const ev_tstamp now = ev_now(obfs->server->loop);
		LOG_RATELIMITED_F(
			DEBUG, now, 1.0, "* obfs: rst from %s", addr_str);
		return NULL;
	}
	const uint8_t ecn = (ip.tos & ECN_MASK);
	obfs_capture(ctx, UINT32_C(0), ecn, &tcp);

	if (!tcp.psh) {
		return NULL;
	}
	ctx->last_seen = msg->ts;
	msg->off = ihl + doff;
	msg->len = plen - doff;
	return ctx;
}

static struct obfs_ctx *
obfs_open_ipv6(struct obfs *restrict obfs, struct msgframe *restrict msg)
{
	struct ip6_hdr ip6;
	struct tcphdr tcp;
	memcpy(&ip6, msg->buf, sizeof(ip6));
	if ((ip6.ip6_vfc & UINT8_C(0xF0)) != UINT8_C(0x60) ||
	    ip6.ip6_nxt != IPPROTO_TCP) {
		return NULL;
	}
	const uint16_t ihl = sizeof(struct ip6_hdr);
	const uint16_t plen = ntohs(ip6.ip6_plen);
	if (plen < sizeof(struct tcphdr) || msg->len < ihl + plen) {
		return NULL;
	}
	memcpy(&tcp, msg->buf + ihl, sizeof(struct tcphdr));
	const uint16_t doff = tcp.doff * UINT16_C(4);
	if (doff < sizeof(struct tcphdr) || plen < doff) {
		return NULL;
	}
	const struct in6_addr ip6_src = ip6.ip6_src;
	if (!IN6_IS_ADDR_LOOPBACK(&ip6_src)) {
		struct pseudo_ip6hdr pseudo = {
			.src = ip6.ip6_src,
			.dst = ip6.ip6_dst,
			.nxt = IPPROTO_TCP,
			.plen = htonl(plen),
		};
		const uint16_t check = tcp.check;
		tcp.check = 0;
		uint32_t sum = 0;
		sum = in_cksum(sum, &pseudo, sizeof(pseudo));
		sum = in_cksum(sum, &tcp, sizeof(tcp));
		const unsigned char *remain = &msg->buf[ihl + sizeof(tcp)];
		if (in_cksum_fin(sum, remain, plen - sizeof(tcp)) != check) {
			return NULL;
		}
	}
	const struct sockaddr_in6 dest = (struct sockaddr_in6){
		.sin6_family = AF_INET6,
		.sin6_port = tcp.dest,
		.sin6_addr = ip6.ip6_dst,
	};
	if (!sa_matches(&obfs->bind_addr.sa, (struct sockaddr *)&dest)) {
		return NULL;
	}
	msg->addr.in6 = (struct sockaddr_in6){
		.sin6_family = AF_INET6,
		.sin6_port = tcp.source,
		.sin6_addr = ip6.ip6_src,
	};

	struct obfs_ctx *restrict ctx = obfs_find_ctx(obfs, &msg->addr.sa);
	if (ctx == NULL) {
		if (LOGLEVEL(DEBUG)) {
			char addr_str[64];
			format_sa(addr_str, sizeof(addr_str), &msg->addr.sa);
			const ev_tstamp now = ev_now(obfs->server->loop);
			LOG_RATELIMITED_F(
				DEBUG, now, 1.0,
				"* obfs: unrelated %" PRIu16 " bytes from %s",
				msg->len, addr_str);
		}
		return NULL;
	}

	/* inbound */
	if (LOGLEVEL(DEBUG) && tcp.rst) {
		char addr_str[64];
		format_sa(addr_str, sizeof(addr_str), &msg->addr.sa);
		const ev_tstamp now = ev_now(obfs->server->loop);
		LOG_RATELIMITED_F(
			DEBUG, now, 1.0, "* obfs: rst from %s", addr_str);
		return NULL;
	}
	const uint32_t flow = ntohl(ip6.ip6_flow) & UINT32_C(0xFFFFF);
	const uint8_t ecn = ((flow >> 20u) & ECN_MASK);
	obfs_capture(ctx, flow, ecn, &tcp);

	if (!tcp.psh) {
		return NULL;
	}
	ctx->last_seen = msg->ts;
	msg->off = ihl + doff;
	msg->len = plen - doff;
	return ctx;
}

struct obfs_ctx *
obfs_open_inplace(struct obfs *restrict obfs, struct msgframe *restrict msg)
{
	obfs->stats.pkt_cap++;
	obfs->stats.byt_cap += msg->len;
	struct obfs_ctx *ctx = NULL;
	switch (obfs->domain) {
	case AF_INET:
		ctx = obfs_open_ipv4(obfs, msg);
		break;
	case AF_INET6:
		ctx = obfs_open_ipv6(obfs, msg);
		break;
	}
	if (ctx == NULL) {
		obfs->stats.byt_drop += msg->len;
		return NULL;
	}
	ctx->pkt_rx++;
	ctx->byt_rx += msg->len;
	obfs->stats.pkt_rx++;
	obfs->stats.byt_rx += msg->len;
	return ctx;
}

static void
obfs_seal_ipv4(struct obfs_ctx *restrict ctx, struct msgframe *restrict msg)
{
	ASSERT(msg->off == sizeof(struct iphdr) + sizeof(struct tcphdr));
	const struct sockaddr_in *restrict src = &ctx->laddr.in;
	ASSERT(src->sin_family == AF_INET);
	const struct sockaddr_in *restrict dst = &msg->addr.in;
	ASSERT(dst->sin_family == AF_INET);
	const uint16_t plen = sizeof(struct tcphdr) + msg->len;
	struct iphdr ip = {
		.version = IPVERSION,
		.ihl = sizeof(struct iphdr) / 4u,
		.tos = ECN_ECT0,
		.tot_len = htons(sizeof(struct iphdr) + plen),
		.id = (uint16_t)rand64(),
		.frag_off = htons(UINT16_C(0x4000)),
		.ttl = UINT8_C(64),
		.protocol = IPPROTO_TCP,
		.saddr = src->sin_addr.s_addr,
		.daddr = dst->sin_addr.s_addr,
	};
	memcpy(msg->buf, &ip, sizeof(struct iphdr));
	const bool ecn = ctx->cap_ecn;
	if (ecn) {
		ctx->cap_ecn = false;
	}
	struct tcphdr tcp = {
		.source = src->sin_port,
		.dest = dst->sin_port,
		.seq = htonl(ctx->cap_ack_seq + UINT32_C(1492)),
		.ack_seq = htonl(ctx->cap_seq + UINT32_C(1)),
		.doff = sizeof(struct tcphdr) / 4u,
		.res2 = ecn ? 0x1u : 0x0u,
		.psh = 1,
		.ack = 1,
		.window = htons(32748),
	};
	{
		struct pseudo_iphdr pseudo = {
			.saddr = src->sin_addr.s_addr,
			.daddr = dst->sin_addr.s_addr,
			.protocol = IPPROTO_TCP,
			.tot_len = htons(plen),
		};
		uint32_t sum = 0;
		sum = in_cksum(sum, &pseudo, sizeof(pseudo));
		sum = in_cksum(sum, &tcp, sizeof(tcp));
		tcp.check = in_cksum_fin(sum, msg->buf + msg->off, msg->len);
	}
	memcpy(msg->buf + sizeof(ip), &tcp, sizeof(tcp));
	msg->len += msg->off;
	msg->addr.in.sin_port = 0;
}

static void
obfs_seal_ipv6(struct obfs_ctx *restrict ctx, struct msgframe *restrict msg)
{
	ASSERT(msg->off == sizeof(struct ip6_hdr) + sizeof(struct tcphdr));
	const struct sockaddr_in6 *restrict src = &ctx->laddr.in6;
	ASSERT(src->sin6_family == AF_INET6);
	const struct sockaddr_in6 *restrict dst = &msg->addr.in6;
	ASSERT(dst->sin6_family == AF_INET6);
	const uint16_t plen = sizeof(struct tcphdr) + msg->len;
	const uint32_t flow =
		(UINT32_C(6) << 28u) | (ECN_ECT0 << 20u) | ctx->cap_flow;
	struct ip6_hdr ip6 = {
		.ip6_flow = htonl(flow),
		.ip6_plen = htons(plen),
		.ip6_nxt = IPPROTO_TCP,
		.ip6_hops = UINT8_C(64),
		.ip6_src = src->sin6_addr,
		.ip6_dst = dst->sin6_addr,
	};
	memcpy(msg->buf, &ip6, sizeof(ip6));
	const bool ecn = ctx->cap_ecn;
	if (ecn) {
		ctx->cap_ecn = false;
	}
	struct tcphdr tcp = {
		.source = src->sin6_port,
		.dest = dst->sin6_port,
		.seq = htonl(ctx->cap_ack_seq + UINT32_C(1492)),
		.ack_seq = htonl(ctx->cap_seq + UINT32_C(1)),
		.doff = sizeof(struct tcphdr) / 4u,
		.res2 = ecn ? 0x1u : 0x0u,
		.psh = 1,
		.ack = 1,
		.window = htons(32748),
	};
	{
		const struct pseudo_ip6hdr pseudo = {
			.src = src->sin6_addr,
			.dst = dst->sin6_addr,
			.nxt = IPPROTO_TCP,
			.plen = htonl(plen),
		};
		uint32_t sum = 0;
		sum = in_cksum(sum, &pseudo, sizeof(pseudo));
		sum = in_cksum(sum, &tcp, sizeof(tcp));
		tcp.check = in_cksum_fin(sum, msg->buf + msg->off, msg->len);
	}
	memcpy(msg->buf + sizeof(ip6), &tcp, sizeof(tcp));
	msg->len += msg->off;
	msg->addr.in6.sin6_port = 0;
}

bool obfs_seal_inplace(struct obfs *restrict obfs, struct msgframe *restrict msg)
{
	struct obfs_ctx *restrict ctx = obfs_find_ctx(obfs, &msg->addr.sa);
	if (ctx == NULL) {
		if (LOGLEVEL(DEBUG)) {
			char addr_str[64];
			format_sa(addr_str, sizeof(addr_str), &msg->addr.sa);
			const ev_tstamp now = ev_now(obfs->server->loop);
			LOG_RATELIMITED_F(
				WARNING, now, 1.0,
				"* obfs: can't send %" PRIu16
				" bytes to unrelated %s",
				msg->len, addr_str);
		}
		return false;
	}
	if (!ctx->captured) {
		return false;
	}
	switch (obfs->domain) {
	case AF_INET:
		obfs_seal_ipv4(ctx, msg);
		break;
	case AF_INET6:
		obfs_seal_ipv6(ctx, msg);
		break;
	default:
		FAIL();
	}
	ctx->pkt_tx++;
	ctx->byt_tx += msg->len;
	obfs->stats.pkt_tx++;
	obfs->stats.byt_tx += msg->len;
	return true;
}

void obfs_ctx_auth(struct obfs_ctx *restrict ctx, const bool ok)
{
	if (ctx->authenticated == ok) {
		return;
	}
	if (ok) {
		OBFS_CTX_LOG(INFO, ctx, "authenticated");
		ctx->obfs->num_authenticated++;
	}
	ctx->authenticated = ok;
}

static void obfs_accept_one(
	struct obfs *restrict obfs, struct ev_loop *loop, const int fd,
	struct sockaddr *sa, socklen_t len)
{
	struct obfs_ctx *restrict ctx = obfs_ctx_new(obfs);
	if (ctx == NULL) {
		LOGOOM();
		CLOSE_FD(fd);
		return;
	}
	memcpy(&ctx->raddr.sa, sa, len);
	len = sizeof(ctx->laddr);
	if (getsockname(fd, &ctx->laddr.sa, &len)) {
		LOGE_F("obfs accept name: %s", strerror(errno));
		CLOSE_FD(fd);
		obfs_ctx_free(loop, ctx);
		return;
	}
	struct ev_io *restrict w_read = &ctx->w_read;
	ev_io_init(w_read, obfs_server_read_cb, fd, EV_READ);
	w_read->data = ctx;
	OBFS_CTX_LOG(DEBUG, ctx, "accepted");
	if (!obfs_ctx_start(obfs, ctx, fd)) {
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
	}
}

static bool is_startup_limited(struct obfs *restrict obfs)
{
	const size_t num_contexts = table_size(obfs->contexts);
	if (num_contexts >= OBFS_MAX_CONTEXTS) {
		return true;
	}
	const size_t halfopen = num_contexts - obfs->num_authenticated;
	if (halfopen >= OBFS_STARTUP_LIMIT_FULL) {
		return true;
	}
	if (halfopen >= OBFS_STARTUP_LIMIT_START) {
		const double rate = OBFS_STARTUP_LIMIT_RATE / 100.0;
		if (frand() < rate) {
			return true;
		}
	}
	return false;
}

void obfs_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_READ);

	struct obfs *restrict obfs = watcher->data;
	union sockaddr_max m_sa;
	socklen_t len = sizeof(m_sa);

	for (;;) {
		const int fd = accept(watcher->fd, &m_sa.sa, &len);
		if (fd < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			LOGE_F("accept: %s", strerror(err));
			/* sleep for a while, see obfs_listener_cb */
			ev_io_stop(loop, watcher);
			ev_timer_start(loop, &obfs->w_listener);
			return;
		}
		if (is_startup_limited(obfs)) {
			LOG_RATELIMITED(
				ERROR, ev_now(loop), 1.0,
				"* obfs: context limit exceeded, new connections refused");
			CLOSE_FD(fd);
			return;
		}
		if (!socket_set_nonblock(fd)) {
			LOGE_F("fcntl: %s", strerror(errno));
			CLOSE_FD(fd);
			return;
		}

		obfs_accept_one(obfs, loop, fd, &m_sa.sa, len);
	}
}

/* return: 0 - OK, 1 - more, -1 - error */
static int obfs_parse_http(struct obfs_ctx *restrict ctx)
{
	ctx->rbuf.data[ctx->rbuf.len] = '\0';
	char *next = ctx->http_nxt;
	if (next == NULL) {
		next = (char *)ctx->rbuf.data;
		ctx->http_nxt = next;
	}
	struct http_message *restrict msg = &ctx->http_msg;
	if (msg->any.field1 == NULL) {
		next = http_parse(next, msg);
		if (next == NULL) {
			OBFS_CTX_LOG(DEBUG, ctx, "invalid request");
			return -1;
		}
		if (next == ctx->http_nxt) {
			return 1;
		}
		ctx->http_nxt = next;
	}
	char *key, *value;
	for (;;) {
		next = http_parsehdr(ctx->http_nxt, &key, &value);
		if (next == NULL) {
			OBFS_CTX_LOG(DEBUG, ctx, "invalid header");
			return -1;
		}
		if (next == ctx->http_nxt) {
			return 1;
		}
		ctx->http_nxt = next;
		if (key == NULL) {
			break;
		}
		LOGV_F("http: header %s: %s", key, value);
	}
	return 0;
}

void obfs_fail_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct obfs_ctx *restrict ctx = watcher->data;
	obfs_ctx_stop(loop, ctx);
	obfs_sched_redial(ctx->obfs);
}

static void obfs_on_ready(struct obfs_ctx *restrict ctx)
{
	ev_set_cb(&ctx->w_read, obfs_fail_cb);
	obfs_tcp_quickack(ctx->fd, false);

	struct obfs *restrict obfs = ctx->obfs;
	struct server *restrict s = obfs->server;
	const bool is_client = !!(s->conf->mode & MODE_CLIENT);
	OBFS_CTX_LOG_F(INFO, ctx, "%s ready", is_client ? "client" : "server");
	if (!is_client) {
		return;
	}
	s->pkt.connected = true;
	obfs->redial_count = 0;
	server_ping(s);
}

void obfs_server_read_cb(
	struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_READ);

	struct obfs_ctx *restrict ctx = watcher->data;
	struct obfs *restrict obfs = ctx->obfs;

	unsigned char *data = ctx->rbuf.data + ctx->rbuf.len;
	size_t cap = ctx->rbuf.cap - ctx->rbuf.len -
		     (size_t)1; /* for null-terminator */
	const ssize_t nbrecv = recv(watcher->fd, data, cap, 0);
	if (nbrecv < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return;
		}
		if (err == ECONNREFUSED || err == ECONNRESET) {
			OBFS_CTX_LOG_F(DEBUG, ctx, "recv: %s", strerror(err));
			obfs_ctx_del(obfs, ctx);
			obfs_ctx_free(loop, ctx);
			return;
		}
		OBFS_CTX_LOG_F(ERROR, ctx, "recv: %s", strerror(err));
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	}
	if (nbrecv == 0) {
		OBFS_CTX_LOG_F(
			INFO, ctx, "early eof, %zu bytes discarded",
			ctx->rbuf.len);
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	}
	ctx->rbuf.len += nbrecv;
	cap -= nbrecv;

	int ret = obfs_parse_http(ctx);
	if (ret < 0) {
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	}
	if (ret > 0) {
		if (cap == 0) {
			OBFS_CTX_LOG(DEBUG, ctx, "request too large");
			obfs_ctx_del(obfs, ctx);
			obfs_ctx_free(loop, ctx);
		}
		return;
	}

	struct http_message *restrict msg = &ctx->http_msg;
	if (strcmp(msg->req.version, "HTTP/1.1") != 0) {
		OBFS_CTX_LOG_F(
			DEBUG, ctx, "unsupported protocol %s",
			msg->req.version);
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	}
	if (strcmp(msg->req.method, "GET") != 0) {
		ret = http_error(
			(char *)ctx->wbuf.data, ctx->wbuf.cap,
			HTTP_BAD_REQUEST);
		CHECK(ret > 0);
		ctx->wbuf.len = (size_t)ret;
		OBFS_CTX_LOG_F(
			DEBUG, ctx, "HTTP %d `%s'", HTTP_BAD_REQUEST,
			msg->req.method);
		obfs_ctx_write(ctx, loop);
		return;
	}
	char *url = msg->req.url;
	if (strcmp(url, "/generate_204") != 0) {
		ret = http_error(
			(char *)ctx->wbuf.data, ctx->wbuf.cap, HTTP_NOT_FOUND);
		CHECK(ret > 0);
		ctx->wbuf.len = (size_t)ret;
		OBFS_CTX_LOG_F(
			DEBUG, ctx, "HTTP %d `%s'", HTTP_NOT_FOUND,
			msg->req.url);
		obfs_ctx_write(ctx, loop);
		return;
	}

	OBFS_CTX_LOG(DEBUG, ctx, "serving request");
	{
		char date_str[32];
		const size_t date_len = http_date(date_str, sizeof(date_str));
		ret = snprintf(
			(char *)ctx->wbuf.data, ctx->wbuf.cap,
			"HTTP/1.1 204 No Content\r\n"
			"Date: %.*s\r\n"
			"Content-Length: 0\r\n"
			"Connection: keep-alive\r\n\r\n",
			(int)date_len, date_str);
		CHECK(ret > 0);
		ctx->wbuf.len = (size_t)ret;
	}
	ctx->http_keepalive = true;
	obfs_on_ready(ctx);
	obfs_ctx_write(ctx, loop);
}

void obfs_client_read_cb(
	struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct obfs_ctx *restrict ctx = watcher->data;
	struct obfs *restrict obfs = ctx->obfs;

	unsigned char *data = ctx->rbuf.data + ctx->rbuf.len;
	size_t cap = ctx->rbuf.cap - ctx->rbuf.len -
		     (size_t)1; /* for null-terminator */
	const ssize_t nbrecv = recv(watcher->fd, data, cap, 0);
	if (nbrecv < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return;
		}
		LOGE_F("read: %s", strerror(err));
		obfs_ctx_stop(loop, ctx);
		obfs_sched_redial(obfs);
		return;
	}
	if (nbrecv == 0) {
		OBFS_CTX_LOG(INFO, ctx, "got server eof");
		obfs_ctx_stop(loop, ctx);
		obfs_sched_redial(obfs);
		return;
	}
	ctx->rbuf.len += nbrecv;
	cap -= nbrecv;

	const int ret = obfs_parse_http(ctx);
	if (ret < 0) {
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	}
	if (ret > 0) {
		if (cap == 0) {
			OBFS_CTX_LOG(DEBUG, ctx, "response too large");
			obfs_ctx_del(obfs, ctx);
			obfs_ctx_free(loop, ctx);
		}
		return;
	}

	struct http_message *restrict msg = &ctx->http_msg;
	if (strcmp(msg->rsp.version, "HTTP/1.1") != 0) {
		OBFS_CTX_LOG_F(
			DEBUG, ctx, "unsupported protocol %s",
			msg->rsp.version);
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	}
	if (strcmp(msg->rsp.code, "204") != 0) {
		OBFS_CTX_LOG_F(
			DEBUG, ctx, "unexpected http status %s", msg->rsp.code);
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	}

	obfs_on_ready(ctx);
}

void obfs_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct obfs_ctx *restrict ctx = watcher->data;
	obfs_ctx_write(ctx, loop);
}

#endif /* WITH_OBFS */
