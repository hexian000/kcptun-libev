/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SOCKUTIL_H
#define SOCKUTIL_H

#include "algo/hashtable.h"

#include <stdbool.h>
#include <stdint.h>

#include <netinet/in.h>
#include <sys/socket.h>

typedef union {
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
} sockaddr_max_t;

bool socket_set_nonblock(int fd);
void socket_set_reuseport(int fd, bool reuseport);
void socket_set_tcp(int fd, bool nodelay, bool keepalive);
void socket_set_buffer(int fd, size_t send, size_t recv);
void socket_bind_netdev(int fd, const char *netdev);

socklen_t getsocklen(const struct sockaddr *sa);
bool sa_equals(const struct sockaddr *a, const struct sockaddr *b);
bool sa_matches(const struct sockaddr *bind, const struct sockaddr *dest);
int format_sa(const struct sockaddr *sa, char *buf, size_t buf_size);

enum {
	RESOLVE_TCP = 0x0,
	RESOLVE_UDP = 0x1,
	RESOLVE_PASSIVE = 0x2,
};
bool resolve_addr(sockaddr_max_t *sa, const char *s, int flags);

#endif /* SOCKUTIL_H */
