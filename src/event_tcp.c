#include "event.h"
#include "event_impl.h"
#include "hashtable.h"
#include "server.h"
#include "pktqueue.h"
#include "session.h"
#include "slog.h"
#include "util.h"
#include "sockutil.h"

#include <ev.h>

#include <unistd.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>

static void accept_one(
	struct server *restrict s, const int fd,
	const struct sockaddr *client_sa)
{
	/* Initialize and start watcher to read client requests */
	struct session *restrict ss;
	const struct sockaddr *sa = s->conf->kcp_connect.sa;
	uint32_t conv = conv_new(s, sa);
	ss = session_new(s, sa, conv);
	if (ss == NULL) {
		LOGOOM();
		if (close(fd) != 0) {
			LOGW_PERROR("close");
		}
		return;
	}
	if (!kcp_sendmsg(ss, SMSG_DIAL)) {
		LOGOOM();
		if (close(fd) != 0) {
			LOGW_PERROR("close");
		}
		session_free(ss);
		return;
	}
	hashkey_t key;
	conv_make_key(&key, sa, conv);
	table_set(s->sessions, &key, ss);
	ss->state = STATE_CONNECTED;
	if (LOGLEVEL(LOG_LEVEL_INFO)) {
		char addr_str[64];
		format_sa(client_sa, addr_str, sizeof(addr_str));
		LOGI_F("session [%08" PRIX32 "] open: "
		       "tcp accepted from %s",
		       conv, addr_str);
	}
	session_start(ss, fd);
}

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct server *restrict s = watcher->data;
	struct config *restrict conf = s->conf;
	sockaddr_max_t m_sa;
	socklen_t sa_len = sizeof(m_sa);
	int client_fd;

	while (true) {
		sa_len = sizeof(m_sa);
		// Accept client request
		client_fd = accept(watcher->fd, &m_sa.sa, &sa_len);
		if (client_fd < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == EINTR || errno == ENOMEM) {
				break;
			}
			LOGE_PERROR("accept");
			return;
		}
		if (table_size(s->sessions) >= MAX_SESSIONS) {
			if (close(client_fd) != 0) {
				LOGW_PERROR("close");
			}
			LOG_RATELIMITED(
				LOG_LEVEL_ERROR, loop, 1.0,
				"* max session count exceeded, new connections refused");
			return;
		}
		if (socket_setup(client_fd)) {
			LOGE_PERROR("fcntl");
			if (close(client_fd) != 0) {
				LOGW_PERROR("close");
			}
			return;
		}
		socket_set_tcp(client_fd, conf->tcp_nodelay, conf->tcp_keepalive);
		socket_set_buffer(client_fd, conf->tcp_sndbuf, conf->tcp_rcvbuf);

		accept_one((struct server *)watcher->data, client_fd, &m_sa.sa);
	}
}

static bool tcp_recv(struct session *restrict ss)
{
	/* reserve some space to encode header in place */
	size_t cap = TLV_MAX_LENGTH - TLV_HEADER_SIZE - ss->rbuf_len;
	if (cap == 0) {
		return false;
	}

	unsigned char *buf = ss->rbuf + TLV_HEADER_SIZE + ss->rbuf_len;
	size_t len = 0;
	bool tcp_eof = false;
	do {
		/* Receive message from client socket */
		const ssize_t nread = recv(ss->tcp_fd, buf, cap, 0);
		if (nread < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == EINTR || errno == ENOMEM) {
				break;
			}
			const int err = errno;
			LOGE_F("session [%08" PRIX32 "] close: "
			       "tcp recv error on fd %d: [%d] %s",
			       ss->conv, ss->tcp_fd, err, strerror(err));
			session_stop(ss);
			kcp_reset(ss);
			return false;
		}
		if (nread == 0) {
			tcp_eof = true;
			break;
		}
		buf += nread, cap -= nread, len += nread;
	} while (cap > 0);
	ss->rbuf_len += len;

	if (len > 0) {
		ss->stats.tcp_rx += len;
		ss->server->stats.tcp_rx += len;
		LOGV_F("session [%08" PRIX32 "] "
		       "tcp recv: %zu bytes, cap: %zu bytes",
		       ss->conv, len, cap);
	}

	if (tcp_eof) {
		LOGI_F("session [%08" PRIX32 "] close: tcp closed by peer",
		       ss->conv);
		// Stop and free session if client socket is closing
		session_stop(ss);
		kcp_close(ss);
		return false;
	}
	return len > 0;
}

void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	UNUSED(loop);
	struct session *restrict ss = (struct session *)watcher->data;
	assert(watcher->fd == ss->tcp_fd);
	assert(watcher == &ss->w_read);

	if (ss->state == STATE_LINGER) {
		if (ss->tcp_fd != -1 && ev_is_active(watcher)) {
			ev_io_stop(loop, watcher);
		}
		return;
	}

	do {
		kcp_flush(ss);
	} while (tcp_recv(ss));
}

static bool tcp_send(struct session *restrict ss)
{
	const size_t navail = ss->wbuf_next;
	if (navail == 0) {
		return false;
	}

	unsigned char *raw = ss->wbuf + TLV_HEADER_SIZE;
	unsigned char *next = raw + navail;
	unsigned char *buf = raw + ss->wbuf_flush;
	size_t len = next - buf;

	ssize_t nsend = send(ss->tcp_fd, buf, len, 0);
	if (nsend < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ||
		    errno == ENOMEM) {
			return 0;
		}
		const int err = errno;
		LOGE_F("session [%08" PRIX32 "] close: "
		       "tcp send error on fd %d: [%d] %s",
		       ss->conv, ss->tcp_fd, err, strerror(err));
		session_stop(ss);
		kcp_reset(ss);
		return false;
	} else if (nsend == 0) {
		return false;
	}
	if ((size_t)nsend < len) {
		ss->wbuf_flush += nsend;
	} else {
		const size_t msg_len = TLV_HEADER_SIZE + navail;
		ss->wbuf_len -= msg_len;
		ss->wbuf_next = 0;
		ss->wbuf_flush = 0;
		memmove(ss->wbuf, next, ss->wbuf_len);
	}

	ss->stats.tcp_tx += nsend;
	ss->server->stats.tcp_tx += nsend;
	LOGV_F("session [%08" PRIX32 "] tcp send: %zd bytes, remain: %zu bytes",
	       ss->conv, nsend, len - (size_t)nsend + ss->wbuf_len);
	return true;
}

void tcp_flush(struct session *restrict ss)
{
	if (ss->tcp_fd == -1) {
		return;
	}
	if (ss->state != STATE_CONNECTED && ss->state != STATE_LINGER) {
		return;
	}
	(void)tcp_send(ss);
	if (ss->wbuf_next == 0) {
		if (ss->state == STATE_LINGER) {
			session_stop(ss);
		}
		return;
	}
	if (ss->tcp_fd != -1) {
		struct ev_io *restrict w_write = &ss->w_write;
		if (!ev_is_active(w_write)) {
			ev_io_start(ss->server->loop, w_write);
		}
	}
}

void write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct session *restrict ss = (struct session *)watcher->data;
	assert(watcher->fd == ss->tcp_fd);
	assert(watcher == &ss->w_write);

	if (ss->state == STATE_CONNECT) {
		ss->state = STATE_CONNECTED;
		struct ev_io *restrict w_read = &ss->w_read;
		ev_io_start(loop, w_read);
		LOGD_F("session [%08" PRIX32 "] tcp connected", ss->conv);
	}

	while (kcp_recv(ss), session_parse(ss), tcp_send(ss)) {
	}

	/* no more data */
	if (ss->wbuf_next == 0) {
		if (ss->tcp_fd != -1 && ev_is_active(watcher)) {
			ev_io_stop(loop, watcher);
		}
	}
}
