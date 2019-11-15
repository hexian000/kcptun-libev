#include "event_impl.h"

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	int client_fd;

	// Accept client request
	client_fd = accept(watcher->fd, (struct sockaddr *)&client_addr,
			   &client_len);
	if (client_fd < 0) {
		LOG_PERROR("accept error");
		return;
	}
	socket_set_nonblock(client_fd);

	{
		char addr_str[64];
		inet_ntop(AF_INET, &client_addr.sin_addr, addr_str,
			  INET_ADDRSTRLEN);
		LOGF_I("new connection from: %s:%u", addr_str,
		       ntohs(client_addr.sin_port));
	}

	// Initialize and start watcher to read client requests
	struct server *s = (struct server *)watcher->data;
	uint32_t conv = conv_new(s->conv);
	struct session *restrict session;
	session = session_new(s, client_fd, conv, s->conf->addr_udp_connect);
	if (session == NULL) {
		LOG_E("cannot create session (out of memory)");
		if (close(client_fd) == -1) {
			LOG_PERROR("close fd");
		}
		return;
	}
	session->state = STATE_CONNECTED;
	session->last_seen = ev_now(loop);
	conv_insert(s->conv, conv, session);
	session_start(session);
}

void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct session *restrict session = (struct session *)watcher->data;
	{
		const int window_size = session->server->conf->kcp_sndwnd;
		if (ikcp_waitsnd(session->kcp) > 2 * window_size) {
			/* KCP EAGAIN */
			session->kcp_blocked = true;
			ev_io_stop(loop, watcher);
			return;
		}
	}

	char *buf = session->rbuf.data + TLV_HEADER_SIZE;
	size_t len = session->rbuf.cap - TLV_HEADER_SIZE;
	assert(len > 0);

	// Receive message from client socket
	const ssize_t read = recv(watcher->fd, buf, len, 0);
	switch (read) {
	case -1: {
		const int err = errno;
		assert(read == -1);
		LOGF_E("fd=%d tcp recv error: [%d] %s", watcher->fd, err,
		       strerror(err));
		session_shutdown(session);
		kcp_close(session, ev_now(loop));
		return;
	}
	case 0: /* EOF */ {
		LOGF_I("session [%08" PRIX32 "] tcp closing",
		       (uint32_t)session->kcp->conv);
		// Stop and free session if client socket is closing
		if (session->state == STATE_CONNECTED) {
			session_shutdown(session);
			kcp_close(session, ev_now(loop));
		}
		return;
	}
	default:
		assert(read > 0);
	}
	len = (size_t)read;
	session->stats.tcp_in += len;
	session->server->stats.tcp_in += len;
	const ev_tstamp now = ev_now(loop);
	session->last_seen = now;

#if TCP_PER_PACKET_LOG
	LOGF_V("session [%08" PRIX32 "] tcp recv: %zu bytes",
	       (uint32_t)session->kcp->conv, len);
#endif
	tlv_header_write(session->rbuf.data, (struct tlv_header){
						     .msg = SMSG_DATA,
						     .len = (uint16_t)len,
					     });
	len = TLV_HEADER_SIZE + len;
	buf = session->rbuf.data;
	int n = ikcp_send(session->kcp, buf, len);
	if (n < 0) {
		LOGF_E("session [%08" PRIX32 "] ikcp_send error: %zu bytes",
		       (uint32_t)session->kcp->conv, len);
		return;
	}
	session->stats.kcp_out += len;
	session->server->stats.kcp_out += len;
#if KCP_PER_PACKET_LOG
	LOGF_V("session [%08" PRIX32 "] kcp send: %zu bytes",
	       (uint32_t)session->kcp->conv, len);
#endif
	kcp_forceupdate(session, now);
}

void write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct session *restrict session = (struct session *)watcher->data;
	if (session->state == STATE_CONNECT) {
		session->state = STATE_CONNECTED;
		session->last_seen = ev_now(loop);
		LOGF_V("session [%08" PRIX32 "] tcp connected",
		       (uint32_t)session->kcp->conv);
	}

	if (session->wbuf.start == session->wbuf_flush) {
		kcp_recv(session, ev_now(loop));
		if (session->wbuf.start == session->wbuf_flush) {
			/* no more data */
			ev_io_stop(loop, watcher);
			if (session->state == STATE_LINGER) {
				session_shutdown(session);
			}
			return;
		}
	}

	ssize_t n;
	{
		char *buf = session->wbuf.data + session->wbuf.start;
		assert(session->wbuf_flush >= session->wbuf.start);
		const size_t len = session->wbuf_flush - session->wbuf.start;
		assert(len > 0);
		n = send(session->tcp_fd, buf, len, 0);
	}
	switch (n) {
	case -1: {
		const int err = errno;
		if (err == EAGAIN || err == EWOULDBLOCK || err == EINPROGRESS) {
			/* ignore temporary errors */
			return;
		}
		LOGF_E("session [%08" PRIu32 "] fd=%d tcp send error: [%d] %s",
		       (uint32_t)session->kcp->conv, session->tcp_fd, err,
		       strerror(err));
		session_shutdown(session);
		kcp_close(session, ev_now(loop));
		return;
	} break;
	case 0: {
		return;
	} break;
	default: {
		assert(n > 0);
	} break;
	}
	session->stats.tcp_out += (size_t)n;
	session->server->stats.tcp_out += (size_t)n;
	session->wbuf.start += (size_t)n;
#if TCP_PER_PACKET_LOG
	LOGF_V("session [%08" PRIX32 "] tcp send: %zu bytes, remain: %zu bytes",
	       (uint32_t)session->kcp->conv, n,
	       session->wbuf_flush - session->wbuf.start);
#endif
}
