/* obfs.c - a quick & dirty obfuscator */

#include "obfs.h"

#if WITH_OBFS

#include "conf.h"
#include "hashtable.h"
#include "pktqueue.h"
#include "session.h"
#include "slog.h"
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

#include <regex.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#if USE_SOCK_FILTER
#include <linux/filter.h>
#endif

struct obfs_stats {
	size_t pkt_rx, pkt_tx;
	size_t byt_rx, byt_tx;
};

struct obfs {
	struct config *conf;
	struct ev_loop *loop;
	struct hashtable *sessions;
	struct hashtable *contexts;
	regex_t reqpat;
	struct ev_io w_accept;
	struct ev_timer w_timer;
	struct obfs_ctx *client;
	struct obfs_stats stats;
	uint16_t bind_port;
	bool cap_eth;
	int cap_fd, raw_fd;
	int fd;
	int domain;
};

struct obfs_ctx {
	struct obfs *obfs;
	struct ev_io w_read, w_write;
	sockaddr_max_t laddr, raddr;
	int fd;
	uint32_t cap_flow;
	uint32_t cap_seq, cap_ack_seq;
	bool cap_ecn, cap_ece;
	bool established;
	size_t num_ecn, num_ece;
	ev_tstamp last_seen;
};

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
http_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
http_server_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
http_server_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
http_client_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
http_client_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

static void obfs_tcp_setup(const int fd)
{
	socket_set_buffer(fd, 65536, 65536);
	if (setsockopt(
		    fd, SOL_SOCKET, TCP_WINDOW_CLAMP, &(int){ 32768 },
		    sizeof(int))) {
		LOGW_PERROR("obfs tcp window");
	}
	if (setsockopt(fd, SOL_SOCKET, TCP_QUICKACK, &(int){ 0 }, sizeof(int))) {
		LOGW_PERROR("obfs tcp quickack");
	}
}

#if USE_SOCK_FILTER
static struct sock_fprog filter_compile(const int domain, const uint16_t port)
{
	/* "(ip proto \\tcp) and (tcp dst port 80)" */
	static struct sock_filter tcp4[] = {
		{ 0x28, 0, 0, 0x0000000c }, { 0x15, 0, 8, 0x00000800 },
		{ 0x30, 0, 0, 0x00000017 }, { 0x15, 0, 6, 0x00000006 },
		{ 0x28, 0, 0, 0x00000014 }, { 0x45, 4, 0, 0x00001fff },
		{ 0xb1, 0, 0, 0x0000000e }, { 0x48, 0, 0, 0x00000010 },
		{ 0x15, 0, 1, 0x00000050 }, { 0x6, 0, 0, 0x00040000 },
		{ 0x6, 0, 0, 0x00000000 },
	};
	/* "(ip6 proto \\tcp) and (tcp dst port 80)" */
	static struct sock_filter tcp6[] = {
		{ 0x28, 0, 0, 0x0000000c }, { 0x15, 0, 5, 0x000086dd },
		{ 0x30, 0, 0, 0x00000014 }, { 0x15, 0, 3, 0x00000006 },
		{ 0x28, 0, 0, 0x00000038 }, { 0x15, 0, 1, 0x00000050 },
		{ 0x6, 0, 0, 0x00040000 },  { 0x6, 0, 0, 0x00000000 },
	};
	switch (domain) {
	case AF_INET:
		tcp4[8].k = (uint32_t)port;
		return (struct sock_fprog){
			.len = ARRAY_SIZE(tcp4),
			.filter = tcp4,
		};
	case AF_INET6:
		tcp6[5].k = (uint32_t)port;
		return (struct sock_fprog){
			.len = ARRAY_SIZE(tcp6),
			.filter = tcp6,
		};
	default:
		break;
	}
	CHECK_FAILED();
}
#endif

static bool obfs_cap_bind(struct obfs *restrict obfs, const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		obfs->bind_port = ntohs(((struct sockaddr_in *)sa)->sin_port);
		break;
	case AF_INET6:
		obfs->bind_port = ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
		break;
	default:
		return false;
	}
	if (obfs->cap_eth) {
#if USE_SOCK_FILTER
		if (setsockopt(
			    obfs->cap_fd, SOL_SOCKET, SO_DETACH_FILTER, NULL,
			    0)) {
			LOGW_PERROR("cap bind");
		}
		const struct sock_fprog bpf =
			filter_compile(sa->sa_family, obfs->bind_port);
		if (setsockopt(
			    obfs->cap_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf,
			    sizeof(bpf))) {
			LOGW_PERROR("cap bind");
		}
#endif
	} else {
		if (bind(obfs->cap_fd, sa, getsocklen(sa))) {
			LOGW_PERROR("cap bind");
		}
	}
	LOGD_F("obfs: cap bind to port %" PRIu16, obfs->bind_port);
	return true;
}

static bool obfs_raw_start(struct obfs *restrict obfs)
{
	const int domain = obfs->domain;
	struct config *restrict conf = obfs->conf;
	switch (domain) {
	case AF_INET:
		obfs->cap_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
		obfs->cap_eth = false;
		break;
	case AF_INET6:
		obfs->cap_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
		obfs->cap_eth = true;
		break;
	default:
		LOGF_F("unknown domain: %d", domain);
		return false;
	}
	if (obfs->cap_fd < 0) {
		LOGE_PERROR("obfs capture");
		return false;
	}
	if (socket_setup(obfs->cap_fd)) {
		LOGE_PERROR("fcntl");
		return false;
	}
	socket_set_buffer(obfs->cap_fd, 0, conf->udp_rcvbuf);

	obfs->raw_fd = socket(domain, SOCK_RAW, IPPROTO_RAW);
	if (obfs->raw_fd < 0) {
		LOGE_PERROR("obfs raw");
		return false;
	}
	if (socket_setup(obfs->raw_fd)) {
		LOGE_PERROR("fcntl");
		return false;
	}
	switch (domain) {
	case AF_INET:
		if (setsockopt(
			    obfs->raw_fd, IPPROTO_IP, IP_HDRINCL, &(int){ 1 },
			    sizeof(int))) {
			LOGE_PERROR("raw setup");
			return false;
		}
		break;
	case AF_INET6:
		if (setsockopt(
			    obfs->raw_fd, IPPROTO_IPV6, IPV6_HDRINCL,
			    &(int){ 1 }, sizeof(int))) {
			LOGE_PERROR("raw setup");
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

static struct obfs_ctx *obfs_ctx_new(struct obfs *restrict obfs)
{
	struct obfs_ctx *restrict ctx = util_malloc(sizeof(struct obfs_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	*ctx = (struct obfs_ctx){
		.obfs = obfs,
		.established = false,
	};
	return ctx;
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
			LOGW_PERROR("close");
		}
		ctx->fd = -1;
	}
	util_free(ctx);
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
	table_filter(obfs->sessions, ctx_del_filter, &ctx->raddr.sa);
	hashkey_t key;
	conv_make_key(&key, &ctx->raddr.sa, UINT32_C(0));
	(void)table_del(obfs->contexts, &key, NULL);
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

static bool obfs_ctx_start(
	struct obfs *restrict obfs, struct obfs_ctx *restrict ctx, const int fd)
{
	ctx->fd = fd;
	struct ev_loop *loop = obfs->loop;
	if (obfs->conf->mode & MODE_CLIENT) {
		struct ev_io *restrict w_read = &ctx->w_read;
		ev_io_init(w_read, http_client_read_cb, fd, EV_READ);
		w_read->data = ctx;
		ev_io_start(loop, w_read);
		struct ev_io *restrict w_write = &ctx->w_write;
		ev_io_init(w_write, http_client_write_cb, fd, EV_WRITE);
		w_write->data = ctx;
		ev_io_start(loop, w_write);
	} else {
		struct ev_io *restrict w_read = &ctx->w_read;
		ev_io_init(w_read, http_server_read_cb, fd, EV_READ);
		w_read->data = ctx;
		ev_io_start(loop, w_read);
		struct ev_io *restrict w_write = &ctx->w_write;
		ev_io_init(w_write, http_server_write_cb, fd, EV_WRITE);
		w_write->data = ctx;
		/* w_write is not used on the server side */
	}
	ctx->last_seen = ev_now(loop);
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
		obfs_ctx_free(loop, old_ctx);
	}
	const bool ok = table_set(obfs->contexts, &key, ctx);
	if (!ok) {
		obfs_ctx_stop(loop, ctx);
	}
	return ok;
}

static bool obfs_ctx_dial(struct obfs *restrict obfs, const struct sockaddr *sa)
{
	int fd = -1;
	if ((fd = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		LOGE_PERROR("obfs tcp");
		return false;
	}
	if (socket_setup(fd)) {
		LOGE_PERROR("fcntl");
		if (close(fd) != 0) {
			LOGW_PERROR("close");
		}
		return false;
	}
	obfs_tcp_setup(fd);
	struct obfs_ctx *restrict ctx = obfs_ctx_new(obfs);
	if (ctx == NULL) {
		return false;
	}

	if (connect(fd, sa, getsocklen(sa))) {
		if (errno != EINPROGRESS) {
			LOGE_PERROR("obfs tcp connect");
			obfs_ctx_free(obfs->loop, ctx);
			return false;
		}
	}
	memcpy(&ctx->raddr, sa, getsocklen(sa));
	if (LOGLEVEL(LOG_LEVEL_INFO)) {
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOGI_F("obfs connect: %s", addr_str);
	}

	socklen_t len = sizeof(ctx->laddr);
	if (getsockname(fd, &ctx->laddr.sa, &len)) {
		LOGE_PERROR("obfs client name");
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
	const double not_seen = now - ctx->last_seen;
	if (not_seen < 60.0) {
		return true;
	}
	if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
		char laddr[64], raddr[64];
		format_sa(&ctx->laddr.sa, laddr, sizeof(laddr));
		format_sa(&ctx->raddr.sa, raddr, sizeof(raddr));
		LOGD_F("obfs: timeout ctx %s <-> %s after %.1fs", laddr, raddr,
		       not_seen);
	}
	if (obfs->client == ctx) {
		obfs->client = NULL;
		return true;
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
	table_filter(obfs->contexts, obfs_ctx_timeout_filt, obfs);
	if ((obfs->conf->mode & MODE_CLIENT) && obfs->client == NULL) {
		struct netaddr *addr = &obfs->conf->pkt_connect;
		if (resolve_netaddr(addr, RESOLVE_TCP)) {
			(void)obfs_ctx_dial(obfs, addr->sa);
		}
	}
}

static const char http_request[] = "GET /generate_204 HTTP/1.1\r\n"
				   "Host: %s\r\n"
				   "User-Agent: curl/7.81.0\r\n"
				   "Accept: */*\r\n\r\n";

static const char http_pat204[] =
	"^GET /generate_204 HTTP/[0-9][1-9]*(\\.[0-9][1-9]*)?\r\n"
	"([a-zA-Z0-9\\-]+:\\s*\\S*\r\n)*\r\n$";

static const char http_reply_204[] = "HTTP/1.1 204 No Content\r\n"
				     "Date: %s\r\n"
				     "Content-Length: 0\r\n"
				     "Connection: keep-alive\r\n\r\n";

struct obfs *obfs_new(struct server *restrict s)
{
	struct obfs *obfs = NULL;
	const char *method = s->conf->obfs;
	if (strcmp(method, "dpi/tcp-wnd") == 0) {
		obfs = util_malloc(sizeof(struct obfs));
		if (obfs == NULL) {
			LOGOOM();
			return NULL;
		}
		*obfs = (struct obfs){
			.loop = s->loop,
			.conf = s->conf,
			.sessions = s->sessions,
			.contexts = table_create(),
			.cap_fd = -1,
			.raw_fd = -1,
			.fd = -1,
		};
		if (obfs->contexts == NULL) {
			LOGOOM();
			util_free(obfs);
			return NULL;
		}
		CHECK(regcomp(&obfs->reqpat, http_pat204, REG_EXTENDED) == 0);
	}
	return obfs;
}

bool obfs_resolve(struct obfs *obfs)
{
	UNUSED(obfs);
	return true;
}

static bool print_ctx_iter(
	struct hashtable *t, const hashkey_t *key, void *value, void *user)
{
	UNUSED(t);
	UNUSED(key);
	struct obfs *restrict obfs = user;
	struct obfs_ctx *restrict ctx = value;
	const ev_tstamp now = ev_now(obfs->loop);
	char addr_str[64];
	format_sa(&ctx->raddr.sa, addr_str, sizeof(addr_str));
	if (ctx->established) {
		LOGD_F("obfs context peer=%s seen=%.0fs ecn(rx/tx)=%zu/%zu",
		       addr_str, now - ctx->last_seen, ctx->num_ecn,
		       ctx->num_ece);
	} else {
		LOGD_F("obfs context peer=%s seen=%.0fs", addr_str,
		       now - ctx->last_seen);
	}
	return true;
}

void obfs_stats(struct obfs *restrict obfs)
{
	const ev_tstamp now = ev_now(obfs->loop);
	static struct obfs_stats last_stats = { 0 };
	static double last_print_time = TSTAMP_NIL;
	if (last_print_time == TSTAMP_NIL) {
		last_print_time = now;
		last_stats = obfs->stats;
		return;
	}
	if (now - last_print_time < 30.0) {
		return;
	}
	table_iterate(obfs->contexts, print_ctx_iter, obfs);

	const double dt = now - last_print_time;
	struct obfs_stats dstats = (struct obfs_stats){
		.pkt_rx = obfs->stats.pkt_rx - last_stats.pkt_rx,
		.byt_rx = obfs->stats.byt_rx - last_stats.byt_rx,
	};

	if (dstats.pkt_rx) {
		double pkt_rate, byte_rate;
		pkt_rate = (double)(dstats.pkt_rx) / dt;
		byte_rate = (double)(dstats.byt_rx >> 10u) / dt;
		LOGD_F("obfs: %d contexts, capture %.1f pkt/s, %.1f KiB/s, total %zu pkts",
		       table_size(obfs->contexts), pkt_rate, byte_rate,
		       obfs->stats.pkt_rx);
	}
	last_print_time = now;
	last_stats = obfs->stats;
}

bool obfs_start(struct obfs *restrict obfs, struct server *restrict s)
{
	struct config *restrict conf = obfs->conf;
	struct pktconn *restrict pkt = &s->pkt;
	if (conf->mode & MODE_SERVER) {
		struct netaddr *restrict addr = &conf->pkt_bind;
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
			LOGE_PERROR("obfs tcp");
			return false;
		}
		if (socket_setup(obfs->fd)) {
			LOGE_PERROR("fcntl");
			return false;
		}
		socket_set_reuseport(obfs->fd, conf->tcp_reuseport);
		obfs_tcp_setup(obfs->fd);
		if (bind(obfs->fd, sa, getsocklen(sa))) {
			LOGE_PERROR("obfs tcp bind");
			return false;
		}
		if (listen(obfs->fd, 16)) {
			LOGE_PERROR("obfs tcp listen");
			return false;
		}
		if (LOGLEVEL(LOG_LEVEL_INFO)) {
			char addr_str[64];
			format_sa(sa, addr_str, sizeof(addr_str));
			LOGI_F("obfs: tcp listen %s", addr_str);
		}
	}
	if (conf->mode & MODE_CLIENT) {
		if (!resolve_netaddr(&obfs->conf->pkt_connect, RESOLVE_TCP)) {
			return false;
		}
		const struct sockaddr *sa = obfs->conf->pkt_connect.sa;
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
		ev_io_init(w_accept, &http_accept_cb, obfs->fd, EV_READ);
		w_accept->data = obfs;
		ev_io_start(obfs->loop, w_accept);
	}
	{
		struct ev_timer *restrict w_timer = &obfs->w_timer;
		ev_timer_init(w_timer, obfs_timer_cb, 10.0, 10.0);
		w_timer->data = obfs;
		ev_timer_start(obfs->loop, w_timer);
	}

	const ev_tstamp now = ev_time();
	pkt->last_send_time = now;
	pkt->last_recv_time = now;
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
			LOGW_PERROR("close");
		}
		obfs->fd = -1;
	}
	if (obfs->cap_fd != -1) {
		struct ev_io *restrict w_read = &pkt->w_read;
		ev_io_stop(loop, w_read);
		if (close(obfs->cap_fd) != 0) {
			LOGW_PERROR("close");
		}
		obfs->cap_fd = -1;
	}
	if (obfs->raw_fd != -1) {
		struct ev_io *restrict w_write = &pkt->w_write;
		ev_io_stop(loop, w_write);
		if (close(obfs->raw_fd) != 0) {
			LOGW_PERROR("close");
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
	regfree(&obfs->reqpat);
	util_free(obfs);
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
	CHECK_FAILED();
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
	ctx->cap_ecn = (ecn == ECN_CE);
	if (ctx->cap_ecn) {
		ctx->num_ecn++;
	}
	/* RFC 3168: Section 6.1 */
	ctx->cap_ece = !!(tcp->res2 & 0x1u);
	if (ctx->cap_ece) {
		ctx->num_ece++;
	}
	if (ctx->established) {
		return;
	}
	ctx->cap_flow = flow;
	ctx->cap_seq = ntohl(tcp->seq);
	ctx->cap_ack_seq = ntohl(tcp->ack_seq);
	ctx->established = true;
	if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
		char addr_str[64];
		format_sa(&ctx->raddr.sa, addr_str, sizeof(addr_str));
		LOGD_F("obfs: captured from %s", addr_str);
	}
}

static bool obfs_open_ipv4(struct obfs *obfs, struct msgframe *msg)
{
	const uint16_t ehl = obfs->cap_eth ? sizeof(struct ethhdr) : 0;
	if (msg->len < ehl + sizeof(struct iphdr)) {
		return false;
	}
	struct iphdr ip;
	struct tcphdr tcp;
	memcpy(&ip, msg->buf + ehl, sizeof(ip));
	const uint16_t ihl = ip.ihl * UINT16_C(4);
	const uint16_t plen = ntohs(ip.tot_len) - ihl;
	if (ip.protocol != IPPROTO_TCP) {
		return false;
	}
	const uint8_t ecn = (ip.tos & ECN_MASK);
	if (msg->len < ehl + ihl + plen || plen < sizeof(struct tcphdr)) {
		return false;
	}
	memcpy(&tcp, msg->buf + ehl + ihl, sizeof(struct tcphdr));
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
		sum = in_cksum_fin(
			sum, msg->buf + ehl + ihl + sizeof(tcp),
			plen - sizeof(tcp));
		if (check != (uint16_t)sum) {
			return false;
		}
	}
	const uint16_t doff = tcp.doff * UINT16_C(4);
	if (msg->len < ehl + ihl + doff) {
		return false;
	}
	if (ntohs(tcp.dest) != obfs->bind_port) {
		return false;
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
		return false;
	}

	/* inbound */
	if (LOGLEVEL(LOG_LEVEL_DEBUG) && tcp.rst) {
		char addr_str[64];
		format_sa(&msg->addr.sa, addr_str, sizeof(addr_str));
		LOG_RATELIMITEDF(
			LOG_LEVEL_DEBUG, obfs->loop, 1.0, "* obfs: rst from %s",
			addr_str);
		return false;
	}
	obfs_capture(ctx, UINT32_C(0), ecn, &tcp);
	ctx->last_seen = msg->ts;
	msg->off = ehl + ihl + doff;
	msg->len = plen - doff;
	return true;
}

static bool obfs_open_ipv6(struct obfs *obfs, struct msgframe *msg)
{
	const uint16_t ehl = obfs->cap_eth ? sizeof(struct ethhdr) : 0;
	if (ehl + sizeof(struct ip6_hdr) > msg->len) {
		return false;
	}
	struct ip6_hdr ip6;
	struct tcphdr tcp;
	memcpy(&ip6, msg->buf + ehl, sizeof(ip6));
	const uint16_t ihl = sizeof(struct ip6_hdr);
	const uint16_t plen = ntohs(ip6.ip6_plen);
	if (ip6.ip6_nxt != IPPROTO_TCP) {
		return false;
	}
	const uint8_t ecn = ((ip6.ip6_flow >> 20u) & ECN_MASK);
	if (msg->len < ehl + ihl + plen || plen < sizeof(struct tcphdr)) {
		return false;
	}
	memcpy(&tcp, msg->buf + ehl + ihl, sizeof(struct tcphdr));
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
		sum = in_cksum_fin(
			sum, msg->buf + ehl + ihl + sizeof(tcp),
			plen - sizeof(tcp));
		if (check != (uint16_t)sum) {
			return false;
		}
	}
	const uint16_t doff = tcp.doff * UINT16_C(4);
	if (ehl + ihl + doff > msg->len) {
		return false;
	}
	if (ntohs(tcp.dest) != obfs->bind_port) {
		return false;
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
		return false;
	}

	/* inbound */
	if (LOGLEVEL(LOG_LEVEL_DEBUG) && tcp.rst) {
		char addr_str[64];
		format_sa(&msg->addr.sa, addr_str, sizeof(addr_str));
		LOG_RATELIMITEDF(
			LOG_LEVEL_DEBUG, obfs->loop, 1.0, "* obfs: rst from %s",
			addr_str);
		return false;
	}
	const uint32_t flow = ntohl(ip6.ip6_flow) & UINT32_C(0xFFFFF);
	obfs_capture(ctx, flow, ecn, &tcp);
	ctx->last_seen = msg->ts;
	msg->off = ehl + ihl + doff;
	msg->len = plen - doff;
	return true;
}

bool obfs_open_inplace(struct obfs *obfs, struct msgframe *msg)
{
	obfs->stats.pkt_rx++;
	obfs->stats.byt_rx += msg->len;
	switch (obfs->domain) {
	case AF_INET:
		return obfs_open_ipv4(obfs, msg);
	case AF_INET6:
		return obfs_open_ipv6(obfs, msg);
	default:
		break;
	}
	return false;
}

bool obfs_seal_ipv4(struct obfs_ctx *ctx, struct msgframe *msg)
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
	struct tcphdr tcp = (struct tcphdr){
		.source = src->sin_port,
		.dest = dst->sin_port,
		.seq = htonl(ctx->cap_ack_seq + UINT32_C(1492)),
		.ack_seq = htonl(ctx->cap_seq + UINT32_C(1)),
		.doff = sizeof(struct tcphdr) / 4u,
		.res2 = ctx->cap_ecn ? 0x1u : 0x0u,
		.psh = 1,
		.ack = 1,
		.window = htons(32767),
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

bool obfs_seal_ipv6(struct obfs_ctx *ctx, struct msgframe *msg)
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
	struct tcphdr tcp = (struct tcphdr){
		.source = src->sin6_port,
		.dest = dst->sin6_port,
		.seq = htonl(ctx->cap_ack_seq + UINT32_C(1492)),
		.ack_seq = htonl(ctx->cap_seq + UINT32_C(1)),
		.doff = sizeof(struct tcphdr) / 4u,
		.res2 = ctx->cap_ecn ? 0x1u : 0x0u,
		.psh = 1,
		.ack = 1,
		.window = htons(32767),
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

bool obfs_seal_inplace(struct obfs *obfs, struct msgframe *msg)
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

static size_t http_server_date(char *buf, size_t buf_size)
{
	/* RFC 1123: Section 5.2.14 */
	static const char fmt[] = "%a, %d %b %Y %H:%M:%S GMT";
	const time_t now = time(NULL);
	const struct tm *gmt = gmtime(&now);
	return strftime(buf, buf_size, fmt, gmt);
}

void http_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct obfs *restrict obfs = watcher->data;
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
	struct obfs_ctx *restrict ctx = obfs_ctx_new(obfs);
	if (ctx == NULL) {
		LOGOOM();
		if (close(fd) != 0) {
			LOGW_PERROR("close");
		}
		return;
	}
	memcpy(&ctx->raddr.sa, &m_sa, len);
	len = sizeof(ctx->laddr);
	if (getsockname(fd, &ctx->laddr.sa, &len)) {
		LOGE_PERROR("obfs accept name");
		if (close(fd) != 0) {
			LOGW_PERROR("close");
		}
		obfs_ctx_free(loop, ctx);
		return;
	}
	struct ev_io *restrict w_read = &ctx->w_read;
	ev_io_init(w_read, http_server_read_cb, fd, EV_READ);
	w_read->data = ctx;
	if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
		char addr_str[64];
		format_sa(&m_sa.sa, addr_str, sizeof(addr_str));
		LOGD_F("obfs: accept %s", addr_str);
	}
	if (!obfs_ctx_start(obfs, ctx, fd)) {
		obfs_ctx_free(loop, ctx);
	}
}

void http_server_read_cb(
	struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct obfs_ctx *restrict ctx = watcher->data;
	struct obfs *restrict obfs = ctx->obfs;

	char buf[256];
	const ssize_t nbrecv = read(watcher->fd, buf, sizeof(buf) - 1);
	if (nbrecv < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ||
		    errno == ENOMEM) {
			return;
		}
		LOGE_PERROR("read");
		/* harden for SYN flood */
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	} else if (nbrecv == 0) {
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	}
	buf[nbrecv] = '\0';
	regex_t *pat = &obfs->reqpat;
	regmatch_t m;
	if (regexec(pat, buf, 1, &m, 0) != 0) {
		/* bad request */
		LOGD("http bad request");
		/* harden for DDoS attack */
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	}

	char date_str[32];
	CHECK(http_server_date(date_str, sizeof(date_str)) < sizeof(date_str));
	const int n = snprintf(buf, sizeof(buf), http_reply_204, date_str);
	CHECK(n > 0);
	ssize_t nbsend = write(watcher->fd, buf, n);
	if (nbsend != n) {
		LOGE_PERROR("write");
		/* harden for DDoS attack */
		obfs_ctx_del(obfs, ctx);
		obfs_ctx_free(loop, ctx);
		return;
	}
	if (LOGLEVEL(LOG_LEVEL_INFO)) {
		char addr_str[64];
		format_sa(&ctx->raddr.sa, addr_str, sizeof(addr_str));
		LOGI_F("obfs: request handled from %s", addr_str);
	}
}

void http_server_write_cb(
	struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	ev_io_stop(loop, watcher);
}

void http_client_read_cb(
	struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct obfs_ctx *restrict ctx = watcher->data;
	struct obfs *restrict obfs = ctx->obfs;

	char buf[256];
	const ssize_t nbrecv = read(watcher->fd, buf, sizeof(buf));
	if (nbrecv < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ||
		    errno == ENOMEM) {
			return;
		}
		LOGE_PERROR("read");
		obfs_ctx_stop(loop, ctx);
		obfs->client = NULL;
		return;
	} else if (nbrecv == 0) {
		LOGD("obfs: client eof");
		obfs_ctx_stop(loop, ctx);
		obfs->client = NULL;
		return;
	}
	/* discard */
	LOGD("obfs: client ready");
}

void http_client_write_cb(
	struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct obfs_ctx *restrict ctx = watcher->data;
	struct obfs *restrict obfs = ctx->obfs;

	char buf[256];
	char addr_str[64];
	format_sa(&ctx->raddr.sa, addr_str, sizeof(addr_str));
	const int n = snprintf(buf, sizeof(buf), http_request, addr_str);
	CHECK(n > 0);
	const size_t len = n;
	const ssize_t nbsend = write(watcher->fd, buf, len);
	if (nbsend != (ssize_t)len) {
		LOGE_PERROR("write");
		obfs_ctx_stop(loop, ctx);
		obfs->client = NULL;
		return;
	}
	ev_io_stop(loop, watcher);
	LOGD("obfs: request sent");
}

#endif /* WITH_OBFS */
