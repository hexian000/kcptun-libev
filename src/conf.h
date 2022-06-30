#ifndef CONF_H
#define CONF_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

struct netaddr {
	char *str;
	struct sockaddr *sa;
};

enum runmode {
	MODE_SERVER,
	MODE_PEER,
};

const char *runmode_str(int mode);

struct config {
	struct netaddr listen;
	struct netaddr connect;
	struct netaddr udp_bind;
	struct netaddr udp_connect;
	int udp_af;

	int mode;
	int kcp_mtu, kcp_sndwnd, kcp_rcvwnd;
	int kcp_nodelay, kcp_interval, kcp_resend, kcp_nc;

	/* socket options */
	bool tcp_reuseport, tcp_keepalive, tcp_nodelay;
	int tcp_sndbuf, tcp_rcvbuf;
	bool udp_reuseport;
	int udp_sndbuf, udp_rcvbuf;

	char *method;
	char *password;
	unsigned char *psk;
	size_t psklen;

	int timeout, linger, keepalive, time_wait;
	int log_level;
};

struct config *conf_read(const char *path);
void conf_free(struct config *conf);

void conf_resolve(struct config *conf);

#endif /* CONF_H */
