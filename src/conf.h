/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef CONF_H
#define CONF_H

#include <stdbool.h>
#include <stddef.h>

struct sockaddr;

enum runmode {
	MODE_SERVER = 1 << 0,
	MODE_CLIENT = 1 << 1,
	MODE_RENDEZVOUS = 1 << 2,
};

struct config {
	char *listen;
	char *connect;
	char *kcp_bind;
	char *kcp_connect;
	char *rendezvous_server;
	char *service_id;
	size_t service_idlen;
	char *http_listen;
	char *netdev;

	int mode;
	int kcp_mtu, kcp_sndwnd, kcp_rcvwnd;
	int kcp_nodelay, kcp_interval, kcp_resend, kcp_nc;
	int kcp_flush;

	/* socket options */
	bool tcp_reuseport, tcp_keepalive, tcp_nodelay;
	int tcp_sndbuf, tcp_rcvbuf;
	bool udp_reuseport;
	int udp_sndbuf, udp_rcvbuf;

#if WITH_CRYPTO
	char *method;
	char *password;
	char *psk;
#endif

#if WITH_OBFS
	char *obfs;
#endif

	int timeout, linger, keepalive, time_wait;
	int log_level;
	char *user;
};

struct config *conf_read(const char *path);
const char *conf_modestr(const struct config *conf);
void conf_free(struct config *conf);

#endif /* CONF_H */
