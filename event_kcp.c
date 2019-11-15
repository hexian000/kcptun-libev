#include "event_impl.h"

static inline struct session *connect_server(struct server *server,
					     uint32_t conv,
					     struct sockaddr_in *udp_remote,
					     ev_tstamp now)
{
	int fd;
	// Create socket
	if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		LOG_PERROR("socket error");
		return NULL;
	}
	socket_set_nonblock(fd);

	struct session *session;
	session = session_new(server, fd, conv, udp_remote);
	if (session == NULL) {
		LOG_E("cannot create session (out of memory)");
		return NULL;
	}
	session->state = STATE_CONNECT;
	session->last_seen = now;
	const struct sockaddr_in *addr = server->conf->addr_connect;

	// Connect to address
	if (connect(session->tcp_fd, (struct sockaddr *)addr,
		    sizeof(struct sockaddr_in)) != 0) {
		if (errno != EINPROGRESS) {
			LOG_PERROR("connect error");
			return NULL;
		}
	}
	{
		char addr_str[64];
		inet_ntop(AF_INET, &addr->sin_addr, addr_str, INET_ADDRSTRLEN);
		LOGF_I("connect to: %s %u", addr_str, ntohs(addr->sin_port));
	}

	session_start(session);
	conv_insert(server->conv, conv, session);
	return session;
}

static inline void move_wbuf(struct session *restrict session)
{
	assert(session->wbuf_flush == session->wbuf.start);
	assert(session->wbuf.end >= session->wbuf_flush);
	assert(session->wbuf.cap >= session->wbuf.end);
	size_t len = session->wbuf.end - session->wbuf_flush;
	if (len == 0) {
		/* no need to move */
		session->wbuf.start = 0;
		session->wbuf.end = 0;
		session->wbuf_flush = 0;
		return;
	}
	/* move buffer */
	memmove(session->wbuf.data, session->wbuf.data + session->wbuf_flush,
		len);
	session->wbuf.start = 0;
	session->wbuf.end = len;
	session->wbuf_flush = 0;
}

void kcp_close(struct session *restrict session, ev_tstamp now)
{
	switch (session->state) {
	case STATE_CONNECT:
	case STATE_CONNECTED:
		break;
	default:
		/* can not send close cmd in other states */
		return;
	}
	// Not in linger, send close message
	char packet[TLV_HEADER_SIZE];
	tlv_header_write(packet, (struct tlv_header){
					 .msg = SMSG_CLOSE,
					 .len = 0,
				 });
	int r = ikcp_send(session->kcp, (const char *)&packet, TLV_HEADER_SIZE);
	LOGF_D("session [%08" PRIX32 "] kcp send close: %d",
	       (uint32_t)session->kcp->conv, r);
	if (r >= 0) {
		session->stats.kcp_out += TLV_HEADER_SIZE;
		session->server->stats.kcp_out += TLV_HEADER_SIZE;
	}
	session->state = STATE_LINGER;
	session->last_seen = now;
	kcp_forceupdate(session, now);
}

void kcp_recv(struct session *restrict session, ev_tstamp now)
{
	move_wbuf(session);

	char *buf = session->wbuf.data + session->wbuf.end;
	size_t buf_size = session->wbuf.cap - session->wbuf.end;
	if (buf_size == 0) {
		return;
	}
	int r;
	do {
		r = ikcp_recv(session->kcp, buf, buf_size);
		if (r > 0) {
			size_t n = (size_t)r;
			session->stats.kcp_in += n;
			session->server->stats.kcp_in += n;
			session->last_seen = now;
			session->wbuf.end += n;
			buf += n;
			buf_size -= n;
#if KCP_PER_PACKET_LOG
			LOGF_V("session [%08" PRIX32 "] kcp recv: %zu bytes",
			       (uint32_t)session->kcp->conv, n);
#endif
		}
	} while (r >= 0 && buf_size > 0);

	/* try decode */
	if (slice_len(session->wbuf) < TLV_HEADER_SIZE) {
		return;
	}
	struct tlv_header header = tlv_header_read(session->wbuf.data);
	switch (header.msg) {
	case SMSG_DATA: {
		assert(header.len != 0);
		const size_t len = (size_t)header.len;
		if (slice_len(session->wbuf) < TLV_HEADER_SIZE + len) {
			return;
		}
		session->wbuf.start += TLV_HEADER_SIZE;
		session->wbuf_flush = session->wbuf.start + len;
	} break;
	case SMSG_CLOSE: {
		assert(header.len == 0);
		session->wbuf.start += TLV_HEADER_SIZE;
		session->wbuf_flush = session->wbuf.start;
		LOGF_V("session [%08" PRIX32 "] kcp close signal",
		       (uint32_t)session->kcp->conv);
		session_shutdown_input(session);
		session->state = STATE_LINGER;
		session->last_seen = now;
	} break;
	default: {
		LOGF_E("malformed TLV msg: %04" PRIX16, header.msg);
		assert(0);
		session_shutdown_input(session);
		kcp_close(session, now);
	} break;
	}
}

void udp_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct server *restrict server = (struct server *)watcher->data;
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);

	size_t len;
	const char *buf =
		udp_recv(server, (struct sockaddr *)&addr, &addr_len, &len);
	if (buf == NULL) {
		return;
	}

	uint32_t conv = ikcp_getconv(buf);
	if (conv == 0) {
		session0(server, (struct sockaddr *)&addr, addr_len, buf, len);
		return;
	}
	struct session *restrict session =
		(struct session *)conv_find(server->conv, conv);
	if (session == NULL) {
		if (!is_server(server)) {
			LOGF_W("session not found [%08" PRIX32 "]", conv);
			return;
		}
		/* running in server mode, connect to real server */
		session = connect_server(server, conv, &addr, ev_now(loop));
		if (session == NULL) {
			return;
		}
	}
	switch (session->state) {
	case STATE_CONNECT:
	case STATE_CONNECTED:
	case STATE_LINGER:
		break;
	default:
		/* session can not get incoming data in other states */
		return;
	}

	session->stats.udp_in += len;
	int r = ikcp_input(session->kcp, buf, len);
	if (r < 0) {
		LOGF_W("udp_read_cb ikcp_input error: %d", r);
		return;
	}
	kcp_forceupdate(session, ev_now(loop));

	if (ikcp_peeksize(session->kcp) > 0) {
		if (session->w_write == NULL) {
			/* discard data */
			UNUSED(ikcp_recv(session->kcp, session->wbuf.data,
					 session->wbuf.cap));
			return;
		}
		ev_io_start(loop, session->w_write);
	}
}
