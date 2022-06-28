#include "proxy.h"
#include "hashtable.h"
#include "slog.h"
#include "util.h"
#include "sockutil.h"
#include "server.h"
#include "session.h"

#include <ev.h>
#include <sys/socket.h>

struct session *
proxy_dial(struct server *restrict s, struct sockaddr *addr, const int32_t conv)
{
	const struct sockaddr *sa = s->conf->connect.sa;
	int fd;
	// Create socket
	if ((fd = socket(sa->sa_family, SOCK_STREAM, 0)) < 0) {
		LOG_PERROR("socket");
		return NULL;
	}
	if (socket_set_nonblock(fd)) {
		LOG_PERROR("fcntl");
		return NULL;
	}
	{
		struct config *restrict cfg = s->conf;
		socket_set_tcp(
			fd, cfg->tcp_nodelay, cfg->tcp_lingertime,
			cfg->tcp_keepalive);
		socket_set_buffer(fd, cfg->tcp_sndbuf, cfg->tcp_rcvbuf);
	}
	struct session *ss = session_new(s, fd, addr, conv);
	if (ss == NULL) {
		LOGE("proxy_dial: out of memory");
		return NULL;
	}
	ss->state = STATE_CONNECT;

	// Connect to address
	if (connect(ss->tcp_fd, sa, getsocklen(sa)) != 0) {
		if (errno != EINPROGRESS) {
			LOG_PERROR("connect");
			return NULL;
		}
	}
	if (LOGLEVEL(LOG_LEVEL_INFO)) {
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOGI_F("connect to: %s", addr_str);
	}
	hashkey_t sskey;
	conv_make_key(&sskey, addr, conv);
	table_set(s->sessions, &sskey, ss);
	session_start(ss);
	return ss;
}
