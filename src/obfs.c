/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* obfs.c - a quick & dirty obfuscator */

#include "obfs.h"

#if WITH_OBFS

#include "utils/slog.h"
#include "utils/arraysize.h"
#include "utils/hashtable.h"
#include "utils/strbuilder.h"
#include "utils/xorshift.h"
#include "net/http.h"
#include "conf.h"
#include "pktqueue.h"
#include "session.h"
#include "sockutil.h"
#include "util.h"
#include "server.h"
#include "event.h"
#include "event_impl.h"

#include <ev.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>

#include <unistd.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <sys/types.h>
#include <linux/filter.h>
#include <linux/if_packet.h>

struct obfs_stats {
	size_t pkt_cap, pkt_rx, pkt_tx;
	size_t byt_cap, byt_rx, byt_tx;
};

struct obfs {
	struct config *conf;
	struct ev_loop *loop;
	struct hashtable *sessions;
	struct hashtable *contexts;
	struct ev_io w_accept;
	struct ev_timer w_timer;
	struct obfs_ctx *client;
	struct obfs_stats stats, last_stats;
	ev_tstamp last_stats_time;
	sockaddr_max_t bind_addr;
	int cap_fd, raw_fd;
	int fd;
	int domain;
	size_t unauthenticated;
};

#define OBFS_MAX_REQUEST 4096
#define OBFS_MAX_CONTEXTS 4095
#define OBFS_STARTUP_LIMIT_START 10
#define OBFS_STARTUP_LIMIT_RATE 30
#define OBFS_STARTUP_LIMIT_FULL 60

struct obfs_ctx {
	struct obfs *obfs;
	struct ev_io w_read, w_write;
	sockaddr_max_t laddr, raddr;
	int fd;
	unsigned char rbuf[OBFS_MAX_REQUEST];
	size_t rlen, rcap;
	struct http_message http_msg;
	char *http_nxt;
	unsigned char wbuf[OBFS_MAX_REQUEST];
	size_t wlen, wcap;
	uint32_t cap_flow;
	uint32_t cap_seq, cap_ack_seq;
	bool cap_ecn;
	bool established;
	bool authenticated;
	bool http_keepalive;
	size_t num_ecn, num_ece;
	ev_tstamp created;
	ev_tstamp last_seen;
};

#define OBFS_CTX_LOG_F(level, ctx, format, ...)                                \
	do {                                                                   \
		if (LOGLEVEL(level)) {                                         \
			char addr_str[64];                                     \
			format_sa(                                             \
				&(ctx)->raddr.sa, addr_str, sizeof(addr_str)); \
			LOG_WRITE(                                             \
				level, __FILE__, __LINE__,                     \
				"obfs: peer=%s " format, addr_str,             \
				__VA_ARGS__);                                  \
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

static void obfs_tcp_setup(const int fd)
{
	socket_set_buffer(fd, 65536, 65536);
	socket_set_tcp(fd, false, false);
	if (setsockopt(
		    fd, SOL_SOCKET, TCP_WINDOW_CLAMP, &(int){ 32768 },
		    sizeof(int))) {
		const int err = errno;
		LOGW_F("TCP_WINDOW_CLAMP: %s", strerror(err));
	}
}

static void obfs_tcp_quickack(const int fd, const bool enabled)
{
	const int val = enabled ? 1 : 0;
	if (setsockopt(fd, SOL_SOCKET, TCP_QUICKACK, &val, sizeof(val))) {
		const int err = errno;
		LOGW_F("TCP_QUICKACK: %s", strerror(err));
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
	struct filter_compiler_ctx ctx = (struct filter_compiler_ctx){
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

static bool obfs_cap_bind(struct obfs *restrict obfs, const struct sockaddr *sa)
{
	const bool rebind = &obfs->bind_addr.sa == sa;
	if (!rebind) {
		const socklen_t len = getsocklen(sa);
		memcpy(&obfs->bind_addr.sa, sa, len);
	}
	struct sockaddr_ll addr = (struct sockaddr_ll){
		.sll_family = AF_PACKET,
	};
	const char *netdev = obfs->conf->netdev;
	if (netdev != NULL) {
		addr.sll_ifindex = if_nametoindex(netdev);
		if (addr.sll_ifindex == 0) {
			const int err = errno;
			LOGW_F("obfs netdev \"%s\": %s", netdev, strerror(err));
		} else {
			LOGD_F("obfs netdev \"%s\": index=%d", netdev,
			       addr.sll_ifindex);
		}
	}
	switch (obfs->domain) {
	case AF_INET:
		addr.sll_protocol = htons(ETH_P_IP);
		break;
	case AF_INET6:
		addr.sll_protocol = htons(ETH_P_IPV6);
		break;
	default:
		LOGF_F("unknown domain: %d", obfs->domain);
		return false;
	}
	if (bind(obfs->cap_fd, (struct sockaddr *)&addr, sizeof(addr))) {
		const int err = errno;
		LOGW_F("cap bind: %s", strerror(err));
	}
	if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOGD_F("obfs: cap bind %s", addr_str);
	}
	if (rebind) {
		return true;
	}
	struct sock_filter filter[32];
	struct sock_fprog fprog = (struct sock_fprog){
		.filter = filter,
		.len = ARRAY_SIZE(filter),
	};
	if (!filter_compile(&fprog, sa)) {
		LOGW("obfs: cap filter failed");
		return true;
	}
	if (setsockopt(
		    obfs->cap_fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog,
		    sizeof(fprog))) {
		const int err = errno;
		LOGW_F("cap filter: %s", strerror(err));
	}
	return true;
}

static bool obfs_raw_start(struct obfs *restrict obfs)
{
	const int domain = obfs->domain;
	struct config *restrict conf = obfs->conf;
	uint16_t protocol;
	switch (domain) {
	case AF_INET:
		protocol = htons(ETH_P_IP);
		break;
	case AF_INET6:
		protocol = htons(ETH_P_IPV6);
		break;
	default:
		LOGF_F("unknown domain: %d", domain);
		return false;
	}
	obfs->cap_fd = socket(PF_PACKET, SOCK_DGRAM, protocol);
	if (obfs->cap_fd < 0) {
		const int err = errno;
		LOGE_F("obfs capture: %s", strerror(err));
		return false;
	}
	if (!socket_set_nonblock(obfs->cap_fd)) {
		const int err = errno;
		LOGE_F("fcntl: %s", strerror(err));
		return false;
	}
	socket_set_buffer(obfs->cap_fd, 0, conf->udp_rcvbuf);

	obfs->raw_fd = socket(domain, SOCK_RAW, IPPROTO_RAW);
	if (obfs->raw_fd < 0) {
		const int err = errno;
		LOGE_F("obfs raw: %s", strerror(err));
		return false;
	}
	if (!socket_set_nonblock(obfs->raw_fd)) {
		const int err = errno;
		LOGE_F("fcntl: %s", strerror(err));
		return false;
	}
	switch (domain) {
	case AF_INET:
		if (setsockopt(
			    obfs->raw_fd, IPPROTO_IP, IP_HDRINCL, &(int){ 1 },
			    sizeof(int))) {
			const int err = errno;
			LOGE_F("raw setup: %s", strerror(err));
			return false;
		}
		break;
	case AF_INET6:
		if (setsockopt(
			    obfs->raw_fd, IPPROTO_IPV6, IPV6_HDRINCL,
			    &(int){ 1 }, sizeof(int))) {
			const int err = errno;
			LOGE_F("raw setup: %s", strerror(err));
			return false;
		}
		break;
	default:
		LOGF_F("unknown domain: %d", domain);
		return false;
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
		if (close(ctx->fd) != 0) {
			const int err = errno;
			LOGW_F("close: %s", strerror(err));
		}
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
	*ctx = (struct obfs_ctx){
		.obfs = obfs,
		.established = false,
		.rcap = OBFS_MAX_REQUEST,
		.wcap = OBFS_MAX_REQUEST,
	};
	return ctx;
}

static bool ctx_del_filter(
	struct hashtable *t, const hashkey_t *key, void *value, void *user)
{
	UNUSED(t);
	struct {
		sockaddr_max_t sa;
		uint32_t conv;
	} *ep = (void *)key;
	if (sa_equals(&ep->sa.sa, user)) {
		session_free(value);
		return false;
	}
	return true;
}

static void obfs_ctx_del(struct obfs *obfs, struct obfs_ctx *restrict ctx)
{
	/* free all related sessions */
	table_filter(obfs->sessions, ctx_del_filter, &ctx->raddr.sa);
	hashkey_t key;
	conv_make_key(&key, &ctx->raddr.sa, UINT32_C(0));
	(void)table_del(obfs->contexts, &key, NULL);
	if (obfs->client == ctx) {
		obfs->client = NULL;
	}
	if (!ctx->authenticated) {
		assert(obfs->unauthenticated > 0u);
		obfs->unauthenticated--;
	}
}

static void obfs_ctx_stop(struct ev_loop *loop, struct obfs_ctx *restrict ctx)
{
	struct ev_io *restrict w_read = &ctx->w_read;
	if (ev_is_active(w_read)) {
		ev_io_stop(loop, w_read);
	}
	struct ev_io *restrict w_write = &ctx->w_write;
	if (ev_is_active(w_write)) {
		ev_io_stop(loop, w_write);
	}
}

static void obfs_ctx_write(struct obfs_ctx *restrict ctx)
{
	struct obfs *restrict obfs = ctx->obfs;
	unsigned char *buf = ctx->wbuf;
	size_t nbsend = 0;
	size_t len = ctx->wlen;
	while (len > 0) {
		const ssize_t nsend = send(ctx->fd, buf, len, 0);
		if (nsend < 0) {
			const int err = errno;
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == EINTR || err == ENOMEM) {
				break;
			}
			LOGE_F("obfs: %s", strerror(err));
			obfs_ctx_del(obfs, ctx);
			obfs_ctx_free(obfs->loop, ctx);
			return;
		}
		len -= nsend;
		nbsend += nsend;
	}
	ctx->wlen = len;
	struct ev_io *restrict w_write = &ctx->w_write;
	if (len > 0) {
		memmove(buf, buf + nbsend, len);
		if (!ev_is_active(w_write)) {
			ev_io_start(obfs->loop, w_write);
		}
		return;
	}
	if (!ctx->http_keepalive) {
		OBFS_CTX_LOG(LOG_LEVEL_VERBOSE, ctx, "server close");
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(obfs->loop, ctx);
		return;
	}
	if (ev_is_active(w_write)) {
		ev_io_stop(obfs->loop, w_write);
	}
}

static bool obfs_ctx_start(
	struct obfs *restrict obfs, struct obfs_ctx *restrict ctx, const int fd)
{
	ctx->fd = fd;
	struct ev_loop *loop = obfs->loop;
	if (obfs->conf->mode & MODE_CLIENT) {
		struct ev_io *restrict w_read = &ctx->w_read;
		ev_io_init(w_read, obfs_client_read_cb, fd, EV_READ);
		w_read->data = ctx;
		ev_io_start(loop, w_read);
		struct ev_io *restrict w_write = &ctx->w_write;
		ev_io_init(w_write, obfs_write_cb, fd, EV_WRITE);
		w_write->data = ctx;
	} else {
		struct ev_io *restrict w_read = &ctx->w_read;
		ev_io_init(w_read, obfs_server_read_cb, fd, EV_READ);
		w_read->data = ctx;
		ev_io_start(loop, w_read);
		struct ev_io *restrict w_write = &ctx->w_write;
		ev_io_init(w_write, obfs_write_cb, fd, EV_WRITE);
		w_write->data = ctx;
	}
	const ev_tstamp now = ev_now(loop);
	ctx->created = now;
	ctx->last_seen = now;
	if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
		char laddr[64], raddr[64];
		format_sa(&ctx->laddr.sa, laddr, sizeof(laddr));
		format_sa(&ctx->raddr.sa, raddr, sizeof(raddr));
		LOGD_F("obfs: start %s <-> %s", laddr, raddr);
	}
	hashkey_t key;
	conv_make_key(&key, &ctx->raddr.sa, UINT32_C(0));
	struct obfs_ctx *restrict old_ctx = NULL;
	if (table_del(obfs->contexts, &key, (void **)&old_ctx)) {
		if (!old_ctx->authenticated) {
			obfs->unauthenticated--;
		}
		obfs_ctx_free(loop, old_ctx);
	}
	const bool ok = table_set(obfs->contexts, &key, ctx);
	if (!ok) {
		obfs_ctx_stop(loop, ctx);
	}
	obfs->unauthenticated++;
	return ok;
}

static bool obfs_ctx_dial(struct obfs *restrict obfs, const struct sockaddr *sa)
{
	int fd = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		const int err = errno;
		LOGE_F("obfs tcp: %s", strerror(err));
		return false;
	}
	if (!socket_set_nonblock(fd)) {
		const int err = errno;
		LOGE_F("fcntl: %s", strerror(err));
		(void)close(fd);
		return false;
	}
	obfs_tcp_setup(fd);
	struct obfs_ctx *restrict ctx = obfs_ctx_new(obfs);
	if (ctx == NULL) {
		return false;
	}

	if (connect(fd, sa, getsocklen(sa))) {
		const int err = errno;
		if (err != EINPROGRESS) {
			LOGE_F("obfs tcp connect: %s", strerror(err));
			obfs_ctx_free(obfs->loop, ctx);
			return false;
		}
	}
	memcpy(&ctx->raddr, sa, getsocklen(sa));
	OBFS_CTX_LOG(LOG_LEVEL_INFO, ctx, "connect");

	socklen_t len = sizeof(ctx->laddr);
	if (getsockname(fd, &ctx->laddr.sa, &len)) {
		const int err = errno;
		LOGE_F("obfs client name: %s", strerror(err));
		obfs_ctx_free(obfs->loop, ctx);
		return false;
	}
	if (!obfs_cap_bind(obfs, &ctx->laddr.sa)) {
		return false;
	}
	if (!obfs_ctx_start(obfs, ctx, fd)) {
		obfs_ctx_free(obfs->loop, ctx);
		return false;
	}
	if (obfs->conf->mode & MODE_CLIENT) {
		/* send the request */
		char addr_str[64];
		format_sa(&ctx->raddr.sa, addr_str, sizeof(addr_str));
		ctx->wlen = snprintf(
			(char *)ctx->wbuf, ctx->wcap,
			"GET /generate_204 HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: curl/7.81.0\r\n"
			"Accept: */*\r\n\r\n",
			addr_str);
		ctx->http_keepalive = true;
		obfs_ctx_write(ctx);
	}
	obfs->client = ctx;
	return true;
}

static bool obfs_ctx_timeout_filt(
	struct hashtable *t, const hashkey_t *key, void *value, void *user)
{
	UNUSED(t);
	UNUSED(key);
	struct obfs *restrict obfs = user;
	struct obfs_ctx *restrict ctx = value;
	const ev_tstamp now = ev_now(obfs->loop);
	assert(now >= ctx->last_seen);
	double not_seen;
	if (ctx->authenticated) {
		not_seen = now - ctx->last_seen;
		if (not_seen < 600.0) {
			return true;
		}
	} else {
		not_seen = now - ctx->created;
		if (not_seen < 60.0) {
			return true;
		}
	}
	if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
		char laddr[64], raddr[64];
		format_sa(&ctx->laddr.sa, laddr, sizeof(laddr));
		format_sa(&ctx->raddr.sa, raddr, sizeof(raddr));
		OBFS_CTX_LOG_F(
			LOG_LEVEL_DEBUG, ctx, "timeout after %.1lfs", not_seen);
	}
	if (obfs->client == ctx) {
		obfs->client = NULL;
		return true;
	}
	if (!ctx->authenticated) {
		obfs->unauthenticated--;
	}
	obfs_ctx_free(obfs->loop, ctx);
	return false;
}

static void
obfs_timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);
	struct obfs *restrict obfs = (struct obfs *)watcher->data;

	/* check & restart accept watcher */
	struct ev_io *restrict w_accept = &obfs->w_accept;
	if (obfs->fd != -1 && !ev_is_active(w_accept)) {
		ev_io_start(loop, w_accept);
	}

	/* context timeout */
	table_filter(obfs->contexts, obfs_ctx_timeout_filt, obfs);

	/* client redial */
	if ((obfs->conf->mode & MODE_CLIENT) && obfs->client == NULL) {
		struct netaddr *addr = &obfs->conf->kcp_connect;
		if (resolve_netaddr(addr, RESOLVE_TCP)) {
			(void)obfs_ctx_dial(obfs, addr->sa);
		}
	}
}

struct obfs *obfs_new(struct server *restrict s)
{
	struct obfs *obfs = NULL;
	const char *method = s->conf->obfs;
	if (strcmp(method, "dpi/tcp-wnd") == 0) {
		obfs = malloc(sizeof(struct obfs));
		if (obfs == NULL) {
			LOGOOM();
			return NULL;
		}
		*obfs = (struct obfs){
			.loop = s->loop,
			.conf = s->conf,
			.sessions = s->sessions,
			.contexts = table_new(),
			.cap_fd = -1,
			.raw_fd = -1,
			.fd = -1,
			.last_stats_time = ev_now(s->loop),
		};
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
	return obfs_cap_bind(obfs, &obfs->bind_addr.sa);
}

void obfs_sample(struct obfs *restrict obfs)
{
	obfs->last_stats = obfs->stats;
	obfs->last_stats_time = ev_now(obfs->loop);
}

struct obfs_stats_ctx {
	ev_tstamp now;
	struct strbuilder *restrict sb;
};

static bool print_ctx_iter(
	struct hashtable *t, const hashkey_t *key, void *value, void *user)
{
	UNUSED(t);
	UNUSED(key);
	struct obfs_stats_ctx *restrict stats_ctx = user;
	struct obfs_ctx *restrict ctx = value;
	char addr_str[64];
	format_sa(&ctx->raddr.sa, addr_str, sizeof(addr_str));
	if (ctx->established) {
		strbuilder_appendf(
			stats_ctx->sb, 4096,
			"obfs context peer=%s seen=%.0lfs ecn(rx/tx)=%zu/%zu\n",
			addr_str, stats_ctx->now - ctx->last_seen, ctx->num_ecn,
			ctx->num_ece);
	} else {
		strbuilder_appendf(
			stats_ctx->sb, 4096,
			"obfs context peer=%s seen=%.0lfs\n", addr_str,
			stats_ctx->now - ctx->last_seen);
	}
	return true;
}

void obfs_stats(struct obfs *restrict obfs, struct strbuilder *restrict sb)
{
	const ev_tstamp now = ev_now(obfs->loop);
	struct obfs_stats *restrict stats = &obfs->stats;
	struct obfs_stats *restrict last_stats = &obfs->last_stats;

	struct obfs_stats_ctx stats_ctx = (struct obfs_stats_ctx){
		.now = now,
		.sb = sb,
	};
	table_iterate(obfs->contexts, print_ctx_iter, &stats_ctx);

	const double dt = now - obfs->last_stats_time;
	struct obfs_stats dstats = (struct obfs_stats){
		.pkt_cap = stats->pkt_cap - last_stats->pkt_cap,
		.byt_cap = stats->byt_cap - last_stats->byt_cap,
		.pkt_rx = stats->pkt_rx - last_stats->pkt_rx,
		.byt_rx = stats->byt_rx - last_stats->byt_rx,
		.pkt_tx = stats->pkt_tx - last_stats->pkt_tx,
		.byt_tx = stats->byt_tx - last_stats->byt_tx,
	};

	const double dpkt_cap = (double)(dstats.pkt_cap) / dt;
	const double dbyt_rx = (double)(dstats.byt_rx) * 0x1p-10 / dt;
	const double dbyt_tx = (double)(dstats.byt_tx) * 0x1p-10 / dt;
	const size_t drop = stats->pkt_cap - stats->pkt_rx;
	const int num_ctx = table_size(obfs->contexts);
	assert(0 <= num_ctx && obfs->unauthenticated <= (size_t)num_ctx);
	strbuilder_appendf(
		sb, 4096,
		"obfs: %zu(+%zu) contexts, capture %.1lf pkt/s, rx/tx %.1lf/%.1lf KiB/s, drop: %zu\n",
		(size_t)num_ctx - obfs->unauthenticated, obfs->unauthenticated,
		dpkt_cap, dbyt_rx, dbyt_tx, drop);
}

bool obfs_start(struct obfs *restrict obfs, struct server *restrict s)
{
	struct config *restrict conf = obfs->conf;
	struct pktconn *restrict pkt = &s->pkt;
	if (conf->mode & MODE_SERVER) {
		struct netaddr *restrict addr = &conf->kcp_bind;
		if (!resolve_netaddr(addr, RESOLVE_TCP | RESOLVE_PASSIVE)) {
			return false;
		}
		const struct sockaddr *restrict sa = addr->sa;
		const int domain = sa->sa_family;
		obfs->domain = domain;
		obfs_raw_start(obfs);
		if (!obfs_cap_bind(obfs, sa)) {
			return false;
		}
		obfs->fd = socket(domain, SOCK_STREAM, IPPROTO_TCP);
		if (obfs->fd < 0) {
			const int err = errno;
			LOGE_F("obfs tcp: %s", strerror(err));
			return false;
		}
		if (!socket_set_nonblock(obfs->fd)) {
			const int err = errno;
			LOGE_F("fcntl: %s", strerror(err));
			return false;
		}
		socket_set_reuseport(obfs->fd, conf->tcp_reuseport);
		obfs_tcp_setup(obfs->fd);
		if (bind(obfs->fd, sa, getsocklen(sa))) {
			const int err = errno;
			LOGE_F("obfs tcp bind: %s", strerror(err));
			return false;
		}
		if (listen(obfs->fd, 16)) {
			const int err = errno;
			LOGE_F("obfs tcp listen: %s", strerror(err));
			return false;
		}
		if (LOGLEVEL(LOG_LEVEL_INFO)) {
			char addr_str[64];
			format_sa(sa, addr_str, sizeof(addr_str));
			LOGI_F("obfs: tcp listen %s", addr_str);
		}
	}
	if (conf->mode & MODE_CLIENT) {
		if (!resolve_netaddr(&obfs->conf->kcp_connect, RESOLVE_TCP)) {
			return false;
		}
		const struct sockaddr *sa = obfs->conf->kcp_connect.sa;
		obfs->domain = sa->sa_family;
		obfs_raw_start(obfs);
		if (!obfs_ctx_dial(obfs, sa)) {
			return false;
		}
	}

	{
		struct ev_io *restrict w_read = &pkt->w_read;
		ev_io_init(w_read, &pkt_read_cb, obfs->cap_fd, EV_READ);
		w_read->data = s;
		ev_io_start(s->loop, w_read);
	}
	{
		struct ev_io *restrict w_write = &pkt->w_write;
		ev_io_init(w_write, &pkt_write_cb, obfs->raw_fd, EV_WRITE);
		w_write->data = s;
		ev_io_start(s->loop, w_write);
	}

	if (obfs->fd != -1) {
		struct ev_io *restrict w_accept = &obfs->w_accept;
		ev_io_init(w_accept, obfs_accept_cb, obfs->fd, EV_READ);
		w_accept->data = obfs;
		ev_io_start(obfs->loop, w_accept);
	}
	{
		struct ev_timer *restrict w_timer = &obfs->w_timer;
		ev_timer_init(w_timer, obfs_timer_cb, 10.0, 10.0);
		w_timer->data = obfs;
		ev_timer_start(obfs->loop, w_timer);
	}
	return true;
}

static bool obfs_shutdown_filt(
	struct hashtable *t, const hashkey_t *key, void *value, void *user)
{
	UNUSED(t);
	UNUSED(key);
	struct obfs_ctx *restrict ctx = (struct obfs_ctx *)value;
	struct obfs *restrict obfs = (struct obfs *)user;
	obfs_ctx_free(obfs->loop, ctx);
	return false;
}

void obfs_stop(struct obfs *restrict obfs, struct server *s)
{
	struct pktconn *restrict pkt = &s->pkt;
	table_filter(obfs->contexts, obfs_shutdown_filt, obfs);
	obfs->client = NULL;
	struct ev_loop *loop = obfs->loop;
	{
		struct ev_timer *restrict w_timer = &obfs->w_timer;
		ev_timer_stop(loop, w_timer);
	}
	if (obfs->fd != -1) {
		struct ev_io *restrict w_accept = &obfs->w_accept;
		ev_io_stop(loop, w_accept);
		if (close(obfs->fd) != 0) {
			const int err = errno;
			LOGW_F("close: %s", strerror(err));
		}
		obfs->fd = -1;
	}
	if (obfs->cap_fd != -1) {
		struct ev_io *restrict w_read = &pkt->w_read;
		ev_io_stop(loop, w_read);
		if (close(obfs->cap_fd) != 0) {
			const int err = errno;
			LOGW_F("close: %s", strerror(err));
		}
		obfs->cap_fd = -1;
	}
	if (obfs->raw_fd != -1) {
		struct ev_io *restrict w_write = &pkt->w_write;
		ev_io_stop(loop, w_write);
		if (close(obfs->raw_fd) != 0) {
			const int err = errno;
			LOGW_F("close: %s", strerror(err));
		}
		obfs->raw_fd = -1;
	}
}

void obfs_free(struct obfs *obfs)
{
	if (obfs == NULL) {
		return;
	}
	if (obfs->contexts != NULL) {
		table_free(obfs->contexts);
		obfs->contexts = NULL;
	}
	free(obfs);
}

uint16_t obfs_offset(struct obfs *obfs)
{
	switch (obfs->domain) {
	case AF_INET:
		return sizeof(struct iphdr) + sizeof(struct tcphdr);
	case AF_INET6:
		return sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
	default:
		break;
	}
	CHECKMSG(false, "unknown af");
}

/* RFC 1071 */
static inline uint32_t in_cksum(uint32_t sum, const void *data, size_t n)
{
	assert(!(n & 1));
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
	if (ctx->established) {
		return;
	}
	ctx->cap_flow = flow;
	ctx->cap_seq = ntohl(tcp->seq);
	ctx->cap_ack_seq = ntohl(tcp->ack_seq);
	ctx->established = true;
	OBFS_CTX_LOG(LOG_LEVEL_DEBUG, ctx, "captured");
}

static struct obfs_ctx *
obfs_open_ipv4(struct obfs *restrict obfs, struct msgframe *restrict msg)
{
	struct iphdr ip;
	struct tcphdr tcp;
	memcpy(&ip, msg->buf, sizeof(ip));
	if (ip.version != IPVERSION || ip.protocol != IPPROTO_TCP) {
		return NULL;
	}
	const uint16_t ihl = ip.ihl * UINT16_C(4);
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
		struct pseudo_iphdr pseudo = (struct pseudo_iphdr){
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
	const struct sockaddr_in dest = (struct sockaddr_in){
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

	struct obfs_ctx *restrict ctx;
	hashkey_t key;
	conv_make_key(&key, &msg->addr.sa, UINT32_C(0));
	if (!table_find(obfs->contexts, &key, (void **)&ctx)) {
		if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
			char addr_str[64];
			format_sa(&msg->addr.sa, addr_str, sizeof(addr_str));
			LOG_RATELIMITEDF(
				LOG_LEVEL_DEBUG, obfs->loop, 1.0,
				"* obfs: unrelated %" PRIu16 " bytes from %s",
				msg->len, addr_str);
		}
		return NULL;
	}

	/* inbound */
	if (LOGLEVEL(LOG_LEVEL_DEBUG) && tcp.rst) {
		char addr_str[64];
		format_sa(&msg->addr.sa, addr_str, sizeof(addr_str));
		LOG_RATELIMITEDF(
			LOG_LEVEL_DEBUG, obfs->loop, 1.0, "* obfs: rst from %s",
			addr_str);
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
	if (!IN6_IS_ADDR_LOOPBACK(&ip6.ip6_src)) {
		struct pseudo_ip6hdr pseudo = (struct pseudo_ip6hdr){
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

	struct obfs_ctx *restrict ctx;
	hashkey_t key;
	conv_make_key(&key, &msg->addr.sa, UINT32_C(0));
	if (!table_find(obfs->contexts, &key, (void **)&ctx)) {
		if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
			char addr_str[64];
			format_sa(&msg->addr.sa, addr_str, sizeof(addr_str));
			LOG_RATELIMITEDF(
				LOG_LEVEL_DEBUG, obfs->loop, 1.0,
				"* obfs: unrelated %" PRIu16 " bytes from %s",
				msg->len, addr_str);
		}
		return NULL;
	}

	/* inbound */
	if (LOGLEVEL(LOG_LEVEL_DEBUG) && tcp.rst) {
		char addr_str[64];
		format_sa(&msg->addr.sa, addr_str, sizeof(addr_str));
		LOG_RATELIMITEDF(
			LOG_LEVEL_DEBUG, obfs->loop, 1.0, "* obfs: rst from %s",
			addr_str);
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
	if (ctx != NULL) {
		obfs->stats.pkt_rx++;
		obfs->stats.byt_rx += msg->len;
	}
	return ctx;
}

static bool
obfs_seal_ipv4(struct obfs_ctx *restrict ctx, struct msgframe *restrict msg)
{
	assert(msg->off == sizeof(struct iphdr) + sizeof(struct tcphdr));
	const struct sockaddr_in *restrict src = &ctx->laddr.in;
	assert(src->sin_family == AF_INET);
	const struct sockaddr_in *restrict dst = &msg->addr.in;
	assert(dst->sin_family == AF_INET);
	const uint16_t plen = sizeof(struct tcphdr) + msg->len;
	struct iphdr ip = (struct iphdr){
		.version = IPVERSION,
		.ihl = sizeof(struct iphdr) / 4u,
		.tos = ECN_ECT0,
		.tot_len = htons(sizeof(struct iphdr) + plen),
		.id = (uint16_t)rand32(),
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
	struct tcphdr tcp = (struct tcphdr){
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
		struct pseudo_iphdr pseudo = (struct pseudo_iphdr){
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
	return true;
}

static bool
obfs_seal_ipv6(struct obfs_ctx *restrict ctx, struct msgframe *restrict msg)
{
	assert(msg->off == sizeof(struct ip6_hdr) + sizeof(struct tcphdr));
	const struct sockaddr_in6 *restrict src = &ctx->laddr.in6;
	assert(src->sin6_family == AF_INET6);
	const struct sockaddr_in6 *restrict dst = &msg->addr.in6;
	assert(dst->sin6_family == AF_INET6);
	const uint16_t plen = sizeof(struct tcphdr) + msg->len;
	const uint32_t flow =
		(UINT32_C(6) << 28u) | (ECN_ECT0 << 20u) | ctx->cap_flow;
	struct ip6_hdr ip6 = (struct ip6_hdr){
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
	struct tcphdr tcp = (struct tcphdr){
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
		struct pseudo_ip6hdr pseudo = (struct pseudo_ip6hdr){
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
	return true;
}

bool obfs_seal_inplace(struct obfs *restrict obfs, struct msgframe *restrict msg)
{
	hashkey_t key;
	conv_make_key(&key, &msg->addr.sa, UINT32_C(0));
	struct obfs_ctx *restrict ctx;
	if (!table_find(obfs->contexts, &key, (void **)&ctx)) {
		char addr_str[64];
		format_sa(&msg->addr.sa, addr_str, sizeof(addr_str));
		LOG_RATELIMITEDF(
			LOG_LEVEL_WARNING, obfs->loop, 1.0,
			"* obfs: can't send %" PRIu16 " bytes to unrelated %s",
			msg->len, addr_str);
		return false;
	}
	if (!ctx->established) {
		return false;
	}
	bool ok = false;
	switch (obfs->domain) {
	case AF_INET:
		ok = obfs_seal_ipv4(ctx, msg);
		break;
	case AF_INET6:
		ok = obfs_seal_ipv6(ctx, msg);
		break;
	default:
		break;
	}
	if (ok) {
		obfs->stats.pkt_tx++;
		obfs->stats.byt_tx += msg->len;
	}
	return ok;
}

void obfs_ctx_auth(struct obfs_ctx *restrict ctx, const bool ok)
{
	if (ctx->authenticated == ok) {
		return;
	}
	if (ok) {
		OBFS_CTX_LOG(LOG_LEVEL_INFO, ctx, "authenticated");
		ctx->obfs->unauthenticated--;
	}
	ctx->authenticated = ok;
}

static void obfs_accept_one(
	struct obfs *restrict obfs, const int fd, struct sockaddr *sa,
	socklen_t len)
{
	struct obfs_ctx *restrict ctx = obfs_ctx_new(obfs);
	if (ctx == NULL) {
		LOGOOM();
		if (close(fd) != 0) {
			const int err = errno;
			LOGW_F("close: %s", strerror(err));
		}
		return;
	}
	memcpy(&ctx->raddr.sa, sa, len);
	len = sizeof(ctx->laddr);
	if (getsockname(fd, &ctx->laddr.sa, &len)) {
		const int err = errno;
		LOGE_F("obfs accept name: %s", strerror(err));
		(void)close(fd);
		obfs_ctx_free(obfs->loop, ctx);
		return;
	}
	struct ev_io *restrict w_read = &ctx->w_read;
	ev_io_init(w_read, obfs_server_read_cb, fd, EV_READ);
	w_read->data = ctx;
	OBFS_CTX_LOG(LOG_LEVEL_DEBUG, ctx, "accepted");
	if (!obfs_ctx_start(obfs, ctx, fd)) {
		obfs_ctx_free(obfs->loop, ctx);
	}
}

void obfs_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct obfs *restrict obfs = watcher->data;
	sockaddr_max_t m_sa;
	socklen_t len = sizeof(m_sa);

	for (;;) {
		const int fd = accept(watcher->fd, &m_sa.sa, &len);
		if (fd < 0) {
			const int err = errno;
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == EINTR || err == ENOMEM) {
				break;
			}
			LOGE_F("accept: %s", strerror(err));
			/* sleep until next timer, see obfs_timer_cb */
			ev_io_stop(loop, watcher);
			return;
		}
		if (obfs->unauthenticated >= OBFS_STARTUP_LIMIT_FULL ||
		    table_size(obfs->contexts) >= OBFS_MAX_CONTEXTS ||
		    (obfs->unauthenticated >= OBFS_STARTUP_LIMIT_START &&
		     rand32() % UINT32_C(100) <
			     (uint32_t)OBFS_STARTUP_LIMIT_RATE)) {
			LOG_RATELIMITED(
				LOG_LEVEL_ERROR, loop, 1.0,
				"* obfs: context limit exceeded, new connections refused");
			if (close(fd) != 0) {
				const int err = errno;
				LOGW_F("close: %s", strerror(err));
			}
			return;
		}
		if (!socket_set_nonblock(fd)) {
			const int err = errno;
			LOGE_F("fcntl: %s", strerror(err));
			(void)close(fd);
			return;
		}

		obfs_accept_one(obfs, fd, &m_sa.sa, len);
	}
}

/* return: 0 - OK, 1 - more, -1 - error */
static int obfs_parse_http(struct obfs_ctx *restrict ctx)
{
	ctx->rbuf[ctx->rlen] = '\0';
	char *next = ctx->http_nxt;
	if (next == NULL) {
		ctx->http_nxt = next = (char *)ctx->rbuf;
	}
	struct http_message *restrict msg = &ctx->http_msg;
	if (msg->any.field1 == NULL) {
		next = http_parse(next, msg);
		if (next == NULL) {
			OBFS_CTX_LOG(LOG_LEVEL_DEBUG, ctx, "invalid request");
			return -1;
		} else if (next == ctx->http_nxt) {
			return 1;
		}
	}
	ctx->http_nxt = next;
	char *key, *value;
	for (;;) {
		next = http_parsehdr(ctx->http_nxt, &key, &value);
		if (next == NULL) {
			OBFS_CTX_LOG(LOG_LEVEL_DEBUG, ctx, "invalid header");
			return -1;
		} else if (next == ctx->http_nxt) {
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

void obfs_server_read_cb(
	struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct obfs_ctx *restrict ctx = watcher->data;
	struct obfs *restrict obfs = ctx->obfs;

	unsigned char *buf = ctx->rbuf + ctx->rlen;
	size_t cap = ctx->rcap - ctx->rlen - 1; /* for null-terminator */
	const ssize_t nbrecv = recv(watcher->fd, buf, cap, 0);
	if (nbrecv < 0) {
		const int err = errno;
		if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR ||
		    err == ENOMEM) {
			return;
		}
		if (err == ECONNREFUSED || err == ECONNRESET) {
			OBFS_CTX_LOG_F(
				LOG_LEVEL_DEBUG, ctx, "recv: %s",
				strerror(err));
			obfs_ctx_del(obfs, ctx);
			obfs_ctx_free(loop, ctx);
			return;
		}
		OBFS_CTX_LOG_F(LOG_LEVEL_ERROR, ctx, "recv: %s", strerror(err));
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	} else if (nbrecv == 0) {
		OBFS_CTX_LOG_F(
			LOG_LEVEL_INFO, ctx, "early eof, %zu bytes discarded",
			ctx->rlen);
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	}
	ctx->rlen += nbrecv;
	cap -= nbrecv;

	const int ret = obfs_parse_http(ctx);
	if (ret < 0) {
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	} else if (ret > 0) {
		if (cap == 0) {
			OBFS_CTX_LOG(LOG_LEVEL_DEBUG, ctx, "request too large");
			obfs_ctx_del(obfs, ctx);
			obfs_ctx_free(loop, ctx);
		}
		return;
	}

	struct http_message *restrict msg = &ctx->http_msg;
	if (strcmp(msg->req.version, "HTTP/1.1") != 0) {
		OBFS_CTX_LOG_F(
			LOG_LEVEL_DEBUG, ctx, "unsupported protocol %s",
			msg->req.version);
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	}
	if (strcasecmp(msg->req.method, "GET") != 0) {
		ctx->wlen = http_error(
			(char *)ctx->wbuf, ctx->wcap, HTTP_BAD_REQUEST);
		OBFS_CTX_LOG_F(
			LOG_LEVEL_DEBUG, ctx, "HTTP %d \"%s\"",
			HTTP_BAD_REQUEST, msg->req.method);
		obfs_ctx_write(ctx);
		return;
	}
	char *url = msg->req.url;
	if (strcmp(url, "/generate_204") != 0) {
		ctx->wlen = http_error(
			(char *)ctx->wbuf, ctx->wcap, HTTP_NOT_FOUND);
		OBFS_CTX_LOG_F(
			LOG_LEVEL_DEBUG, ctx, "HTTP %d \"%s\"", HTTP_NOT_FOUND,
			msg->req.url);
		obfs_ctx_write(ctx);
		return;
	}

	OBFS_CTX_LOG(LOG_LEVEL_INFO, ctx, "serving request");
	char date_str[32];
	const size_t date_len = http_date(date_str, sizeof(date_str));
	ctx->wlen = snprintf(
		(char *)ctx->wbuf, ctx->wcap,
		"HTTP/1.1 204 No Content\r\n"
		"Date: %*s\r\n"
		"Content-Length: 0\r\n"
		"Connection: keep-alive\r\n\r\n",
		(int)date_len, date_str);
	ctx->http_keepalive = true;
	obfs_ctx_write(ctx);

	/* ignore all data arrived later */
	ev_io_stop(loop, watcher);
	obfs_tcp_quickack(ctx->fd, false);
}

void obfs_client_read_cb(
	struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct obfs_ctx *restrict ctx = watcher->data;
	struct obfs *restrict obfs = ctx->obfs;

	unsigned char *buf = ctx->rbuf + ctx->rlen;
	size_t cap = ctx->rcap - ctx->rlen - 1; /* for null-terminator */
	const ssize_t nbrecv = recv(watcher->fd, buf, cap, 0);
	if (nbrecv < 0) {
		const int err = errno;
		if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR ||
		    err == ENOMEM) {
			return;
		}
		LOGE_F("read: %s", strerror(err));
		obfs_ctx_stop(loop, ctx);
		obfs->client = NULL;
		return;
	} else if (nbrecv == 0) {
		OBFS_CTX_LOG(LOG_LEVEL_INFO, ctx, "got server eof");
		obfs_ctx_stop(loop, ctx);
		obfs->client = NULL;
		return;
	}
	ctx->rlen += nbrecv;
	cap -= nbrecv;

	const int ret = obfs_parse_http(ctx);
	if (ret < 0) {
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	} else if (ret > 0) {
		if (cap == 0) {
			OBFS_CTX_LOG(
				LOG_LEVEL_DEBUG, ctx, "response too large");
			obfs_ctx_del(obfs, ctx);
			obfs_ctx_free(loop, ctx);
		}
		return;
	}

	struct http_message *restrict msg = &ctx->http_msg;
	if (strcmp(msg->rsp.version, "HTTP/1.1") != 0) {
		OBFS_CTX_LOG_F(
			LOG_LEVEL_DEBUG, ctx, "unsupported protocol %s",
			msg->rsp.version);
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	}
	if (strcmp(msg->rsp.code, "204") != 0) {
		OBFS_CTX_LOG_F(
			LOG_LEVEL_DEBUG, ctx, "unexpected http status %s",
			msg->rsp.code);
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	}
	OBFS_CTX_LOG(LOG_LEVEL_DEBUG, ctx, "client ready");

	/* ignore all data arrived later */
	ev_io_stop(loop, watcher);
	obfs_tcp_quickack(ctx->fd, false);
}

void obfs_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	UNUSED(loop);
	CHECK_EV_ERROR(revents);
	struct obfs_ctx *restrict ctx = watcher->data;
	obfs_ctx_write(ctx);
}

#endif /* WITH_OBFS */
