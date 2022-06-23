#ifndef CONF_H
#define CONF_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

struct netaddr {
	char *str;
	struct sockaddr *sa;
};

struct config {
	struct netaddr listen;
	struct netaddr connect;
	struct netaddr udp_bind;
	struct netaddr udp_connect;
	int udp_af;

	bool is_server;
	int kcp_mtu, kcp_sndwnd, kcp_rcvwnd;
	int kcp_nodelay, kcp_interval, kcp_resend, kcp_nc;

	char *password;
	unsigned char *psk;

	int timeout, linger, keepalive, time_wait;
	bool reuseport;
	int log_level;
};

struct config *conf_read(const char *path);
void conf_free(struct config *conf);

void conf_resolve(struct config *conf);

#endif /* CONF_H */
