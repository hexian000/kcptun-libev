#ifndef CONF_H
#define CONF_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

struct endpoint {
	struct sockaddr *sa;
	socklen_t len;
};

struct config {
	size_t n_listen;
	struct endpoint *addr_listen;
	struct endpoint addr_connect;
	struct endpoint addr_udp_bind, addr_udp_connect;
	int kcp_mtu, kcp_sndwnd, kcp_rcvwnd;
	int kcp_nodelay, kcp_interval, kcp_resend, kcp_nc;
	char *password;
	int timeout, linger, keepalive;
	bool reuseport;
};

struct config *conf_read(const char * /*file*/);
void conf_free(struct config * /*conf*/);

#endif /* CONF_H */
