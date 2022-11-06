#include "session.h"
#include "aead.h"
#include "event.h"
#include "hashtable.h"
#include "server.h"
#include "pktqueue.h"
#include "sockutil.h"
#include "util.h"

#include <ev.h>

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <inttypes.h>
#include <stdint.h>

static ikcpcb *
kcp_new(struct session *restrict ss, struct config *restrict cfg, uint32_t conv)
{
	ikcpcb *kcp = ikcp_create(conv, ss);
	if (kcp == NULL) {
		return NULL;
	}
	ikcp_wndsize(kcp, cfg->kcp_sndwnd, cfg->kcp_rcvwnd);
	int mtu = cfg->kcp_mtu;
#if WITH_CRYPTO
	struct aead *crypto = ss->server->pkt.queue->crypto;
	if (crypto != NULL) {
		mtu -= (int)(crypto->overhead + crypto->nonce_size);
	}
#endif
	ikcp_setmtu(kcp, mtu);
	ikcp_nodelay(
		kcp, cfg->kcp_nodelay, cfg->kcp_interval, cfg->kcp_resend,
		cfg->kcp_nc);
	ikcp_setoutput(kcp, udp_output);
	return kcp;
}

struct session *session_new(
	struct server *restrict s, const struct sockaddr *addr,
	const uint32_t conv)
{
	struct session *restrict ss =
		(struct session *)util_malloc(sizeof(struct session));
	if (ss == NULL) {
		return NULL;
	}
	const ev_tstamp now = ev_now(s->loop);
	*ss = (struct session){
		.created = now,
		.state = STATE_HALFOPEN,
		.server = s,
		.tcp_fd = -1,
		.conv = conv,
		.kcp_checked = false,
		.last_send = now,
		.last_recv = now,
	};
	ss->kcp = kcp_new(ss, s->conf, conv);
	if (ss->kcp == NULL) {
		session_free(ss);
		return NULL;
	}
	memset(&ss->raddr, 0, sizeof(ss->raddr));
	memcpy(&ss->raddr, addr, getsocklen(addr));
	LOGD_F("session [%08" PRIX32 "] new: %p", conv, (void *)ss);
	return ss;
}

void session_free(struct session *restrict ss)
{
	session_shutdown(ss);
	LOGD_F("session [%08" PRIX32 "] free: %p", ss->conv, (void *)ss);
	struct ev_loop *loop = ss->server->loop;
	struct ev_io *restrict w_read = &ss->w_read;
	ev_io_stop(loop, w_read);
	struct ev_io *restrict w_write = &ss->w_write;
	ev_io_stop(loop, w_write);
	if (ss->kcp != NULL) {
		ikcp_release(ss->kcp);
		ss->kcp = NULL;
	}
	util_free(ss);
}

void session_start(struct session *restrict ss, const int fd)
{
	LOGD_F("session [%08" PRIX32 "] start, fd: %d", ss->conv, fd);
	ss->tcp_fd = fd;
	// Initialize and start watchers to transfer data
	struct ev_loop *loop = ss->server->loop;
	struct ev_io *restrict w_read = &ss->w_read;
	struct ev_io *restrict w_write = &ss->w_write;
	ev_io_init(w_read, read_cb, fd, EV_READ);
	w_read->data = ss;
	if (ss->state == STATE_CONNECTED) {
		ev_io_start(loop, w_read);
	}
	ev_io_init(w_write, write_cb, fd, EV_WRITE);
	w_write->data = ss;
	ev_io_start(loop, w_write);
}

void session_shutdown(struct session *restrict ss)
{
	if (ss->tcp_fd != -1) {
		LOGD_F("session [%08" PRIX32 "] shutdown, fd: %d", ss->conv,
		       ss->tcp_fd);
		struct ev_loop *loop = ss->server->loop;
		struct ev_io *restrict w_read = &ss->w_read;
		if (ev_is_active(w_read)) {
			ev_io_stop(loop, w_read);
		}
		struct ev_io *restrict w_write = &ss->w_write;
		if (ev_is_active(w_write)) {
			ev_io_stop(loop, w_write);
		}
		close(ss->tcp_fd);
		ss->tcp_fd = -1;
	}
}

static void consume_wbuf(struct session *restrict ss, size_t len)
{
	ss->wbuf_len -= len;
	if (ss->wbuf_len > 0) {
		memmove(ss->wbuf, ss->wbuf + len, ss->wbuf_len);
	}
}

static bool proxy_dial(struct session *restrict ss, const struct sockaddr *sa)
{
	int fd = socket(sa->sa_family, SOCK_STREAM, 0);
	// Create socket
	if (fd < 0) {
		LOGE_PERROR("socket");
		return false;
	}
	if (socket_setup(fd)) {
		LOGE_PERROR("fcntl");
		close(fd);
		return false;
	}
	{
		struct config *restrict cfg = ss->server->conf;
		socket_set_tcp(fd, cfg->tcp_nodelay, cfg->tcp_keepalive);
		socket_set_buffer(fd, cfg->tcp_sndbuf, cfg->tcp_rcvbuf);
	}

	// Connect to address
	if (connect(fd, sa, getsocklen(sa)) != 0) {
		if (errno != EINPROGRESS) {
			LOGE_PERROR("connect");
			return NULL;
		}
	}
	ss->state = STATE_CONNECT;

	if (LOGLEVEL(LOG_LEVEL_INFO)) {
		const struct sockaddr *remote_sa =
			(const struct sockaddr *)&ss->raddr;
		char raddr_str[64];
		format_sa(remote_sa, raddr_str, sizeof(raddr_str));
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOGI_F("session [%08" PRIX32 "] open: "
		       "from %s to tcp %s",
		       ss->conv, raddr_str, addr_str);
	}
	session_start(ss, fd);
	return true;
}

void session_on_msg(struct session *restrict ss, struct tlv_header *restrict hdr)
{
	switch (hdr->msg) {
	case SMSG_DIAL: {
		if (hdr->len != TLV_HEADER_SIZE) {
			break;
		}
		LOGD_F("session [%08" PRIX32 "] msg: dial", ss->conv);
		if (ss->tcp_fd != -1) {
			break;
		}
		struct sockaddr *sa = ss->server->conf->connect.sa;
		if (sa == NULL) {
			break;
		}
		if (!proxy_dial(ss, sa)) {
			break;
		}
		consume_wbuf(ss, hdr->len);
		return;
	}
	case SMSG_PUSH: {
		/* tcp connection is lost, discard packet */
		if (ss->tcp_fd == -1) {
			break;
		}
		ss->wbuf_navail = (size_t)hdr->len - TLV_HEADER_SIZE;
		return;
	}
	case SMSG_EOF: {
		if (hdr->len != TLV_HEADER_SIZE) {
			break;
		}
		LOGI_F("session [%08" PRIX32 "] shutdown: eof", ss->conv);
		ss->wbuf_len = 0;
		session_shutdown(ss);
		ss->state = STATE_LINGER;
		return;
	}
	case SMSG_KEEPALIVE: {
		if (hdr->len != TLV_HEADER_SIZE) {
			break;
		}
		LOGD_F("session [%08" PRIX32 "] msg: keepalive", ss->conv);
		consume_wbuf(ss, hdr->len);
		return;
	}
	}
	LOGE_F("smsg error: %04" PRIX16 ", %04" PRIX16, hdr->msg, hdr->len);
	kcp_reset(ss);
	ss->state = STATE_LINGER;
}

static bool
shutdown_filt(struct hashtable *t, const hashkey_t *key, void *ss, void *user)
{
	UNUSED(t);
	UNUSED(key);
	UNUSED(user);
	session_free((struct session *)ss);
	return false;
}

void session_close_all(struct hashtable *t)
{
	table_filter(t, shutdown_filt, NULL);
}

static inline struct session0_header ss0_header_read(const unsigned char *d)
{
	return (struct session0_header){
		.zero = read_uint32((const uint8_t *)d),
		.what = read_uint16((const uint8_t *)d + sizeof(uint32_t)),
	};
}

static inline void
ss0_header_write(unsigned char *d, struct session0_header header)
{
	write_uint32((uint8_t *)d, header.zero);
	write_uint16((uint8_t *)d + sizeof(uint32_t), header.what);
}

void ss0_reset(struct server *s, struct sockaddr *sa, uint32_t conv)
{
	unsigned char b[sizeof(uint32_t)];
	write_uint32(b, conv);
	ss0_send(s, sa, S0MSG_RESET, b, sizeof(b));
}

bool ss0_send(
	struct server *restrict s, struct sockaddr *sa, const uint16_t what,
	const unsigned char *b, const size_t n)
{
	struct pktqueue *restrict q = s->pkt.queue;
	struct msgframe *restrict msg = msgframe_new(q, sa);
	if (msg == NULL) {
		return false;
	}
	unsigned char *packet = msg->buf + msg->off;
	ss0_header_write(
		packet, (struct session0_header){
				.zero = 0,
				.what = what,
			});
	memcpy(packet + SESSION0_HEADER_SIZE, b, n);
	msg->len = SESSION0_HEADER_SIZE + n;
	return packet_send(q, s, msg);
}

static void
ss0_on_ping(struct server *restrict s, struct msgframe *restrict msg)
{
	if (msg->len < SESSION0_HEADER_SIZE + sizeof(uint32_t)) {
		LOGW_F("short ping message: %" PRIu16 " bytes", msg->len);
		return;
	}
	const unsigned char *msgbuf =
		msg->buf + msg->off + SESSION0_HEADER_SIZE;
	const uint32_t tstamp = read_uint32(msgbuf);
	/* send echo message */
	unsigned char b[sizeof(uint32_t)];
	write_uint32(b, tstamp);
	ss0_send(s, msg->hdr.msg_name, S0MSG_PONG, b, sizeof(b));
}

static void
ss0_on_pong(struct server *restrict s, struct msgframe *restrict msg)
{
	UNUSED(s);
	if (msg->len < SESSION0_HEADER_SIZE + sizeof(uint32_t)) {
		LOGW_F("short pong message: %" PRIu16 " bytes", msg->len);
		return;
	}
	const unsigned char *msgbuf =
		msg->buf + msg->off + SESSION0_HEADER_SIZE;
	const uint32_t tstamp = read_uint32(msgbuf);
	/*  print RTT */
	const uint32_t now_ms = tstamp2ms(ev_time());
	LOGD_F("roundtrip finished, RTT: %" PRIu32 " ms", now_ms - tstamp);
	s->pkt.inflight_ping = TSTAMP_NIL;
}

static void
ss0_on_reset(struct server *restrict s, struct msgframe *restrict msg)
{
	if (msg->len < SESSION0_HEADER_SIZE + sizeof(uint32_t)) {
		LOGW_F("short reset message: %" PRIu16 " bytes", msg->len);
		return;
	}
	const unsigned char *msgbuf =
		msg->buf + msg->off + SESSION0_HEADER_SIZE;
	const uint32_t conv = read_uint32(msgbuf);
	hashkey_t key;
	conv_make_key(&key, &msg->addr.sa, conv);
	struct session *restrict ss = NULL;
	if (!table_find(s->sessions, &key, (void **)&ss)) {
		return;
	}
	if (ss->state == STATE_TIME_WAIT) {
		return;
	}
	LOGI_F("session [%08" PRIX32 "] close: session reset by peer", conv);
	session_shutdown(ss);
	ss->state = STATE_TIME_WAIT;
}

void session0(struct server *restrict s, struct msgframe *restrict msg)
{
	if (msg->len < SESSION0_HEADER_SIZE) {
		LOGW_F("short session 0 message: %" PRIu16 " bytes", msg->len);
		return;
	}
	const unsigned char *packet = msg->buf + msg->off;
	struct session0_header header = ss0_header_read(packet);
	switch (header.what) {
	case S0MSG_PING:
		ss0_on_ping(s, msg);
		break;
	case S0MSG_PONG:
		ss0_on_pong(s, msg);
		break;
	case S0MSG_RESET:
		ss0_on_reset(s, msg);
		break;
	default:
		LOGW_F("unknown session 0 message: %04" PRIX16, header.what);
		break;
	}
}
