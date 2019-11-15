#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <stddef.h>

struct sockaddr_in;

struct config {
	size_t n_listen;
	struct sockaddr_in **addr_listen;
	struct sockaddr_in *addr_connect;
	struct sockaddr_in *addr_udp_bind, *addr_udp_connect;
	int kcp_mtu, kcp_sndwnd, kcp_rcvwnd;
	int kcp_nodelay, kcp_interval, kcp_resend, kcp_nc;
	char *password;
	int timeout, linger, keepalive;
	bool reuseport;
};

struct config *conf_read(const char * /*file*/);
void conf_free(struct config * /*conf*/);

#endif /* CONFIG_H */
