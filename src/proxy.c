#include "proxy.h"
#include "hashtable.h"
#include "slog.h"
#include "sockutil.h"
#include "server.h"
#include "session.h"

#include <unistd.h>
#include <sys/socket.h>

#include <inttypes.h>

bool proxy_dial(struct session *restrict ss, const struct sockaddr *sa)
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
			(const struct sockaddr *)&ss->udp_remote;
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
