/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SOCKUTIL_H
#define SOCKUTIL_H

#include <netinet/in.h>
#include <sys/socket.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

/* Check if the error is generally "transient":
 *   In accept()/send()/recv()/sendmsg()/recvmsg()/sendmmsg()/recvmmsg(),
 * transient errors should not cause the socket to fail. The operation should
 * be retried later if the corresponding event is still available.
 */
#define IS_TRANSIENT_ERROR(err)                                                \
	((err) == EINTR || (err) == EAGAIN || (err) == EWOULDBLOCK ||          \
	 (err) == ENOBUFS || (err) == ENOMEM)

union sockaddr_max {
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
};

bool socket_set_nonblock(int fd);
void socket_set_reuseport(int fd, bool reuseport);
void socket_set_tcp(int fd, bool nodelay, bool keepalive);
void socket_set_buffer(int fd, int send, int recv);
void socket_bind_netdev(int fd, const char *netdev);
int socket_get_error(int fd);

socklen_t getsocklen(const struct sockaddr *sa);
void copy_sa(struct sockaddr *dst, const struct sockaddr *src);
bool sa_equals(const struct sockaddr *a, const struct sockaddr *b);
bool sa_matches(const struct sockaddr *bind, const struct sockaddr *dest);
int format_sa(char *s, size_t maxlen, const struct sockaddr *sa);

enum {
	RESOLVE_TCP = 0x0,
	RESOLVE_UDP = 0x1,
	RESOLVE_PASSIVE = 0x2,
};
bool resolve_addr(union sockaddr_max *sa, const char *s, int flags);

#endif /* SOCKUTIL_H */
