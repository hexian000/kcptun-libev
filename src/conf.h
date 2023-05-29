/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef CONF_H
#define CONF_H

#include <stdbool.h>
#include <stddef.h>

struct sockaddr;

struct netaddr {
	char *str;
	struct sockaddr *sa;
};

enum runmode {
	MODE_SERVER = 1 << 0,
	MODE_CLIENT = 1 << 1,
};

const char *runmode_str(int mode);

struct config {
	const char *netdev;
	struct netaddr listen;
	struct netaddr connect;
	struct netaddr kcp_bind;
	struct netaddr kcp_connect;
	struct netaddr http_listen;

	int mode;
	int kcp_mtu, kcp_sndwnd, kcp_rcvwnd;
	int kcp_nodelay, kcp_interval, kcp_resend, kcp_nc;
	int kcp_flush;

	/* socket options */
	bool tcp_reuseport, tcp_keepalive, tcp_nodelay;
	int tcp_sndbuf, tcp_rcvbuf;
	int udp_sndbuf, udp_rcvbuf;

#if WITH_CRYPTO
	char *method;
	char *password;
	char *psk;
#endif

#if WITH_OBFS
	const char *obfs;
#endif

	int timeout, linger, keepalive, time_wait;
	int log_level;
	const char *user;
};

struct config *conf_read(const char *path);
void conf_free(struct config *conf);

bool resolve_netaddr(struct netaddr *restrict addr, int flags);

#endif /* CONF_H */
