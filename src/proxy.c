#include "proxy.h"
#include "hashtable.h"
#include "slog.h"
#include "util.h"
#include "sockutil.h"
#include "server.h"
#include "session.h"

#include <ev.h>

#include <unistd.h>
#include <sys/socket.h>

bool proxy_dial(struct session *restrict ss, struct sockaddr *sa)
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
	if (LOGLEVEL(LOG_LEVEL_INFO)) {
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOGI_F("connect to: %s", addr_str);
	}

	ss->state = STATE_CONNECT;
	session_start(ss, fd);
	return true;
}
