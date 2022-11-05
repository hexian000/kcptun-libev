#include "obfs.h"

#if WITH_OBFS

#include "conf.h"
#include "hashtable.h"
#include "pktqueue.h"
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
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>

struct obfs {
	struct config *conf;
	struct ev_loop *loop;
	struct hashtable *contexts;
	regex_t reqpat;
	struct ev_io w_accept;
	struct ev_timer w_timer;
	struct obfs_ctx *client;
	uint16_t bind_port;
	int cap_fd, raw_fd;
	int fd;
};

struct obfs_ctx {
	struct obfs *obfs;
	struct ev_io w_read, w_write;
	sockaddr_max_t laddr, raddr;
	int fd;
	uint32_t cap_seq, cap_ack_seq;
	bool captured;
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
	struct in6_addr ip6_src;
	struct in6_addr ip6_dst;
	uint32_t ip6_plen;
	uint16_t zero1;
	uint8_t zero2;
	uint8_t ip6_nxt;
};

static void
http_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
http_server_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
http_client_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
http_client_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

static struct obfs_ctx *obfs_ctx_new(struct obfs *restrict obfs)
{
	struct obfs_ctx *restrict ctx = util_malloc(sizeof(struct obfs_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	*ctx = (struct obfs_ctx){
		.obfs = obfs,
		.captured = false,
	};
	return ctx;
}

static void obfs_ctx_free(struct obfs_ctx *ctx)
{
	if (ctx == NULL) {
		return;
	}
	if (ctx->fd != -1) {
		(void)close(ctx->fd);
		ctx->fd = -1;
	}
	util_free(ctx);
}

static bool obfs_is_client(struct obfs *restrict obfs)
{
	return !!(obfs->conf->mode & MODE_CLIENT);
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

static bool
obfs_ctx_start(struct obfs *restrict obfs, struct obfs_ctx *restrict ctx)
{
	struct ev_loop *loop = obfs->loop;
	struct ev_io *restrict w_read = &ctx->w_read;
	ev_io_start(loop, w_read);
	if (obfs_is_client(obfs)) {
		struct ev_io *restrict w_write = &ctx->w_write;
		ev_io_start(loop, w_write);
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
		obfs_ctx_stop(obfs->loop, old_ctx);
		obfs_ctx_free(old_ctx);
	}
	const bool ok = table_set(obfs->contexts, &key, ctx);
	if (!ok) {
		obfs_ctx_stop(loop, ctx);
	}
	return ok;
}

static void obfs_tcp_setup(const int fd)
{
	socket_set_buffer(fd, 65536, 65536);
	if (setsockopt(
		    fd, SOL_SOCKET, TCP_WINDOW_CLAMP, &(int){ 32768 },
		    sizeof(int))) {
		LOGE_PERROR("obfs tcp window");
	}
	if (setsockopt(fd, SOL_SOCKET, TCP_QUICKACK, &(int){ 0 }, sizeof(int))) {
		LOGE_PERROR("obfs tcp quickack");
	}
}

static bool obfs_ctx_dial(struct obfs *restrict obfs)
{
	if (!resolve_netaddr(&obfs->conf->pkt_connect, RESOLVE_TCP)) {
		return false;
	}
	const struct sockaddr *sa = obfs->conf->pkt_connect.sa;
	int fd = -1;
	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		LOGE_PERROR("obfs tcp");
		return false;
	}
	if (socket_setup(fd)) {
		LOGE_PERROR("fcntl");
		close(fd);
		return false;
	}
	obfs_tcp_setup(fd);
	struct obfs_ctx *restrict ctx = obfs_ctx_new(obfs);
	if (ctx == NULL) {
		return false;
	}
	ctx->fd = fd;

	if (connect(fd, sa, getsocklen(sa))) {
		if (errno != EINPROGRESS) {
			LOGE_PERROR("obfs tcp connect");
			obfs_ctx_free(ctx);
			return false;
		}
	}
	memcpy(&ctx->raddr, sa, getsocklen(sa));
	if (LOGLEVEL(LOG_LEVEL_INFO)) {
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOGI_F("tcp connect: %s", addr_str);
	}

	socklen_t len = sizeof(ctx->laddr);
	if (getsockname(fd, &ctx->laddr.sa, &len)) {
		LOGE_PERROR("obfs client name");
		obfs_ctx_free(ctx);
		return false;
	}
	obfs->bind_port = ntohs(ctx->laddr.in.sin_port);
	LOGD_F("obfs: cap bind %" PRIu16, obfs->bind_port);

	{
		struct ev_io *restrict w_read = &ctx->w_read;
		ev_io_init(w_read, &http_client_read_cb, fd, EV_READ);
		w_read->data = ctx;

		struct ev_io *restrict w_write = &ctx->w_write;
		ev_io_init(w_write, &http_client_write_cb, fd, EV_WRITE);
		w_write->data = ctx;
	}
	if (!obfs_ctx_start(obfs, ctx)) {
		obfs_ctx_free(ctx);
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
	if (not_seen > 60.0) {
		char laddr[64], raddr[64];
		format_sa(&ctx->laddr.sa, laddr, sizeof(laddr));
		format_sa(&ctx->raddr.sa, raddr, sizeof(raddr));
		LOGD_F("obfs: timeout ctx %s <-> %s after %.1fs", laddr, raddr,
		       not_seen);
		obfs_ctx_stop(obfs->loop, ctx);
		obfs_ctx_free(ctx);
		return false;
	}
	return true;
}

static void
obfs_timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);
	struct obfs *restrict obfs = (struct obfs *)watcher->data;
	table_filter(obfs->contexts, obfs_ctx_timeout_filt, obfs);
	if (obfs_is_client(obfs) && obfs->client == NULL) {
		(void)obfs_ctx_dial(obfs);
	}
}

const char http_request[] = "GET /generate_204 HTTP/1.1\r\n"
			    "Host: %s\r\n"
			    "User-Agent: curl/7.81.0\r\n"
			    "Accept: */*\r\n\r\n";

const char http_reqpat[] =
	"^GET /generate_204 HTTP/[0-9][1-9]*(\\.[0-9][1-9]*)?\r\n"
	"([a-zA-Z0-9\\-]+:\\s*\\S*\r\n)*\r\n$";

const char http_reply_204[] = "HTTP/1.1 204 No Content\r\n"
			      "Date: %s\r\n"
			      "Content-Length: 0\r\n"
			      "Connection: keep-alive\r\n\r\n";

struct obfs *obfs_new(struct ev_loop *restrict loop, struct config *conf)
{
	struct obfs *obfs = NULL;
	const char *method = conf->obfs;
	if (strcmp(method, "dpi/tcp-wnd") == 0) {
		obfs = util_malloc(sizeof(struct obfs));
		if (obfs == NULL) {
			LOGOOM();
			return NULL;
		}
		*obfs = (struct obfs){
			.loop = loop,
			.conf = conf,
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
		CHECK(regcomp(&obfs->reqpat, http_reqpat, REG_EXTENDED) == 0);
	}
	return obfs;
}

bool obfs_resolve(struct obfs *obfs)
{
	struct config *restrict conf = obfs->conf;
	if (conf->pkt_connect.str != NULL &&
	    !resolve_netaddr(&conf->pkt_connect, RESOLVE_TCP)) {
		return false;
	}
	if (conf->pkt_bind.str != NULL &&
	    !resolve_netaddr(&conf->pkt_bind, RESOLVE_TCP | RESOLVE_PASSIVE)) {
		return false;
	}
	return true;
}

bool obfs_start(struct obfs *restrict obfs, struct server *restrict s)
{
	struct config *restrict conf = obfs->conf;
	struct pktconn *restrict pkt = &s->pkt;
	obfs->cap_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (obfs->cap_fd < 0) {
		LOGE_PERROR("obfs capture");
		return false;
	}
	if (socket_setup(obfs->cap_fd)) {
		LOGE_PERROR("fcntl");
		return false;
	}
	socket_set_buffer(obfs->cap_fd, 0, conf->udp_rcvbuf);

	obfs->raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (obfs->raw_fd < 0) {
		LOGE_PERROR("obfs raw");
		return false;
	}
	if (socket_setup(obfs->raw_fd)) {
		LOGE_PERROR("fcntl");
		return false;
	}
	socket_set_buffer(obfs->raw_fd, conf->udp_sndbuf, 0);

	if (conf->mode & MODE_SERVER) {
		struct netaddr *restrict addr = &conf->pkt_bind;
		if (!resolve_netaddr(addr, RESOLVE_TCP | RESOLVE_PASSIVE)) {
			return false;
		}
		const struct sockaddr *restrict sa = addr->sa;
		if (sa->sa_family != AF_INET) {
			LOGE("obfs: currently only ipv4 is supported");
			return false;
		}
		obfs->bind_port = ntohs(((struct sockaddr_in *)sa)->sin_port);
		LOGD_F("obfs: cap bind %" PRIu16, obfs->bind_port);
		obfs->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (obfs->fd < 0) {
			LOGE_PERROR("obfs tcp");
			return false;
		}
		if (socket_setup(obfs->fd)) {
			LOGE_PERROR("fcntl");
			return false;
		}
		socket_set_reuseport(obfs->fd, true);
		obfs_tcp_setup(obfs->fd);
		if (bind(obfs->fd, sa, getsocklen(sa))) {
			LOGE_PERROR("obfs tcp bind");
			return false;
		}
		if (listen(obfs->fd, 16)) {
			LOGE_PERROR("obfs tcp listen");
			return false;
		}
		if (((struct sockaddr_in *)sa)->sin_addr.s_addr != INADDR_ANY) {
			if (bind(obfs->cap_fd, sa, getsocklen(sa))) {
				LOGE_PERROR("obfs cap bind");
				return false;
			}
		}
		if (LOGLEVEL(LOG_LEVEL_INFO)) {
			char addr_str[64];
			format_sa(sa, addr_str, sizeof(addr_str));
			LOGI_F("obfs: tcp listen %s", addr_str);
		}
	}
	if (obfs_is_client(obfs) && !obfs_ctx_dial(obfs)) {
		return false;
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
	obfs_ctx_stop(obfs->loop, ctx);
	obfs_ctx_free(ctx);
	return false;
}

void obfs_stop(struct obfs *obfs, struct server *s)
{
	struct pktconn *restrict pkt = &s->pkt;
	table_filter(obfs->contexts, obfs_shutdown_filt, obfs);
	obfs->client = NULL;
	struct ev_loop *loop = obfs->loop;
	{
		struct ev_timer *restrict w_timer = &obfs->w_timer;
		if (ev_is_active(w_timer)) {
			ev_timer_stop(loop, w_timer);
		}
	}
	if (obfs->fd != -1) {
		struct ev_io *restrict w_accept = &obfs->w_accept;
		if (ev_is_active(w_accept)) {
			ev_io_stop(loop, w_accept);
		}
		close(obfs->fd);
	}
	if (obfs->cap_fd != -1) {
		struct ev_io *restrict w_read = &pkt->w_read;
		if (ev_is_active(w_read)) {
			ev_io_stop(loop, w_read);
		}
		close(obfs->cap_fd);
	}
	if (obfs->raw_fd != -1) {
		struct ev_io *restrict w_write = &pkt->w_write;
		if (ev_is_active(w_write)) {
			ev_io_stop(loop, w_write);
		}
		close(obfs->raw_fd);
	}
}

void obfs_free(struct obfs *obfs)
{
	if (obfs == NULL) {
		return;
	}
	if (obfs->fd != -1) {
		close(obfs->fd);
		obfs->fd = -1;
	}
	if (obfs->cap_fd != -1) {
		close(obfs->cap_fd);
		obfs->cap_fd = -1;
	}
	if (obfs->raw_fd != -1) {
		close(obfs->raw_fd);
		obfs->raw_fd = -1;
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
	UNUSED(obfs);
	return sizeof(struct iphdr) + sizeof(struct tcphdr);
}

static uint32_t in_cksum(uint32_t sum, void *data, size_t n)
{
	assert(!(n & 1));
	uint16_t *b = data;
	while (n > 1) {
		sum += *b++;
		n -= 2;
	}
	return sum;
}

static uint16_t in_cksum_fin(uint32_t sum, void *data, size_t n)
{
	uint16_t *b = data;
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

static void obfs_capture(struct obfs_ctx *ctx, struct msgframe *msg)
{
	struct iphdr *restrict ip = (struct iphdr *)msg->buf;
	const size_t ihl = ip->ihl * 4u;
	struct tcphdr *restrict tcp = (struct tcphdr *)(msg->buf + ihl);
	if (ctx->captured) {
		return;
	}
	ctx->cap_seq = ntohl(tcp->seq);
	ctx->cap_ack_seq = ntohl(tcp->ack_seq);
	ctx->captured = true;
	if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
		char addr_str[64];
		format_sa(&msg->addr.sa, addr_str, sizeof(addr_str));
		LOGD_F("obfs: captured from %s", addr_str);
	}
}

bool obfs_open_inplace(struct obfs *obfs, struct msgframe *msg)
{
	struct iphdr *restrict ip = (struct iphdr *)msg->buf;
	const size_t ihl = ip->ihl * 4u;
	assert(ip->version == IPVERSION);
	assert(ip->protocol == IPPROTO_TCP);
	struct tcphdr *restrict tcp = (struct tcphdr *)(msg->buf + ihl);
	{
		struct pseudo_iphdr pseudo = (struct pseudo_iphdr){
			.saddr = ip->saddr,
			.daddr = ip->daddr,
			.protocol = IPPROTO_TCP,
			.tot_len = htons(msg->len - ihl),
		};
		const uint16_t check = tcp->check;
		tcp->check = 0;
		uint32_t sum = in_cksum(0, &pseudo, sizeof(pseudo));
		if (check != in_cksum_fin(sum, tcp, msg->len - ihl)) {
			return false;
		}
	}
	if (ntohs(tcp->dest) != obfs->bind_port) {
		return false;
	}
	const size_t doff = tcp->doff * 4u;
	msg->addr.in = (struct sockaddr_in){
		.sin_family = AF_INET,
		.sin_addr.s_addr = ip->saddr,
		.sin_port = tcp->source,
	};

	struct obfs_ctx *restrict ctx;
	hashkey_t key;
	conv_make_key(&key, &msg->addr.sa, UINT32_C(0));
	if (!table_find(obfs->contexts, &key, (void **)&ctx)) {
		/* unrelated */
		if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
			char addr_str[64];
			format_sa(&msg->addr.sa, addr_str, sizeof(addr_str));
			LOGD_F("obfs: unrelated %" PRIu16 " bytes from %s",
			       msg->len, addr_str);
		}
		return false;
	}

	/* inbound */
	if (LOGLEVEL(LOG_LEVEL_DEBUG) && tcp->rst) {
		char addr_str[64];
		format_sa(&msg->addr.sa, addr_str, sizeof(addr_str));
		LOGD_F("obfs: rst from %s", addr_str);
		return false;
	}
	ctx->last_seen = msg->ts;
	obfs_capture(ctx, msg);
	msg->off = ihl + doff;
	if (msg->off >= msg->len) {
		return false;
	}
	msg->len -= msg->off;
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
		LOGW_F("obfs: can't send %" PRIu16 "bytes to unrelated %s",
		       msg->len, addr_str);
		return false;
	}
	if (!ctx->captured) {
		return false;
	}
	const struct sockaddr_in *restrict src = &ctx->laddr.in;
	const struct sockaddr_in *restrict dst = &msg->addr.in;
	struct iphdr *restrict ip = (struct iphdr *)msg->buf;
	*ip = (struct iphdr){
		.version = IPVERSION,
		.ihl = sizeof(struct iphdr) / 4u,
		.frag_off = htons(UINT16_C(0x4000)),
		.ttl = UINT8_C(64),
		.protocol = IPPROTO_TCP,
		.daddr = dst->sin_addr.s_addr,
		.id = (uint16_t)rand32(),
	};
	CHECK(msg->off == sizeof(struct iphdr) + sizeof(struct tcphdr));
	struct tcphdr *restrict tcp =
		(struct tcphdr *)(msg->buf + sizeof(struct iphdr));
	*tcp = (struct tcphdr){
		.seq = htonl(ctx->cap_ack_seq + UINT32_C(1492)),
		.ack_seq = htonl(ctx->cap_seq + UINT32_C(1)),
		.psh = 1,
		.ack = 1,
		.window = htons(16384),
		.source = src->sin_port,
		.dest = dst->sin_port,
		.doff = sizeof(struct tcphdr) / 4u,
	};

	{
		struct pseudo_iphdr pseudo = (struct pseudo_iphdr){
			.saddr = src->sin_addr.s_addr,
			.daddr = dst->sin_addr.s_addr,
			.protocol = IPPROTO_TCP,
			.tot_len = htons(sizeof(struct tcphdr) + msg->len),
		};
		uint32_t sum = in_cksum(0, &pseudo, sizeof(pseudo));
		tcp->check = in_cksum_fin(
			sum, tcp, sizeof(struct tcphdr) + msg->len);
	}
	msg->len += msg->off;
	return true;
}

static size_t http_server_date(char *buf, size_t buf_size)
{
	static const char rfc1123fmt[] = "%a, %d %b %Y %H:%M:%S GMT";
	const time_t now = time(NULL);
	const struct tm *gmt = gmtime(&now);
	return strftime(buf, buf_size, rfc1123fmt, gmt);
}

void http_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);

	struct obfs *restrict obfs = watcher->data;
	sockaddr_max_t m_sa;
	socklen_t len = sizeof(m_sa);
	const int fd = accept(watcher->fd, &m_sa.sa, &len);
	if (socket_setup(fd)) {
		LOGE_PERROR("fcntl");
		close(fd);
		return;
	}
	struct obfs_ctx *restrict ctx = obfs_ctx_new(obfs);
	if (ctx == NULL) {
		LOGOOM();
		close(fd);
		return;
	}
	ctx->fd = fd;
	memcpy(&ctx->raddr.sa, &m_sa, len);
	len = sizeof(ctx->laddr);
	if (getsockname(fd, &ctx->laddr.sa, &len)) {
		LOGE_PERROR("obfs accept name");
		obfs_ctx_free(ctx);
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
	if (!obfs_ctx_start(obfs, ctx)) {
		obfs_ctx_free(ctx);
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
	if (nbrecv <= 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ||
		    errno == ENOMEM) {
			return;
		}
		LOGE_PERROR("read");
		obfs_ctx_stop(loop, ctx);
		return;
	}
	buf[nbrecv] = '\0';
	regex_t *pat = &obfs->reqpat;
	regmatch_t m;
	if (regexec(pat, buf, 1, &m, 0) != 0) {
		/* bad request */
		LOGD("http bad request");
		obfs_ctx_stop(loop, ctx);
		return;
	}

	char date_str[32];
	CHECK(http_server_date(date_str, sizeof(date_str)) < sizeof(date_str));
	const int n = snprintf(buf, sizeof(buf), http_reply_204, date_str);
	CHECK(n > 0);
	ssize_t nbsend = write(watcher->fd, buf, n);
	if (nbsend != n) {
		LOGE_PERROR("write");
		obfs_ctx_stop(loop, ctx);
		return;
	}
	LOGD("obfs: request handled");
}

void http_client_read_cb(
	struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct obfs_ctx *restrict ctx = watcher->data;
	struct obfs *restrict obfs = ctx->obfs;

	char buf[256];
	const ssize_t nbrecv = read(watcher->fd, buf, sizeof(buf));
	if (nbrecv <= 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ||
		    errno == ENOMEM) {
			return;
		}
		LOGE_PERROR("read");
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
