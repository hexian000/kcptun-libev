/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef OS_SOCKET_H
#define OS_SOCKET_H

#include "utils/slog.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * @defgroup sockutil
 * @brief Utilities for socket setup and management.
 * @{
 */

/**
 * @def SOCKET_SHUTDOWN_FD(fd, dir)
 * @brief Shuts down the write end of the socket and logs any errors.
 * @param fd The socket file descriptor.
 * @param dir The shutdown direction (RD, WR, RDWR).
 */
#define SOCKET_SHUTDOWN_FD(fd, dir)                                            \
	do {                                                                   \
		if (shutdown((fd), SHUT_##dir) != 0) {                         \
			const int err = errno;                                 \
			LOGW_F("shutdown [fd:%d]: (%d) %s", (fd), err,         \
			       strerror(err));                                 \
		}                                                              \
	} while (0)

/**
 * @def SOCKET_CLOSE_FD(fd)
 * @brief Closes the file descriptor and logs any errors.
 * @param fd The file descriptor.
 */
#define SOCKET_CLOSE_FD(fd)                                                    \
	do {                                                                   \
		if (close((fd)) != 0) {                                        \
			const int err = errno;                                 \
			LOGW_F("close [fd:%d]: (%d) %s", (fd), err,            \
			       strerror(err));                                 \
		}                                                              \
	} while (0)

/**
 * @brief Union to hold sockaddr structures for IPv4 and IPv6.
 * @note POSIX version: POSIX.1-2001
 */
union sockaddr_max {
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
};

/**
 * @brief Sets the socket to close-on-exec mode.
 * @param fd The socket file descriptor.
 * @return 0 on success, or errno on failure; logs LOGE on failure.
 * @note POSIX version: POSIX.1-2001
 */
int socket_set_cloexec(int fd);

/**
 * @brief Sets the socket to non-blocking mode.
 * @param fd The socket file descriptor.
 * @return 0 on success, or errno on failure; logs LOGE on failure.
 * @note POSIX version: POSIX.1-2001
 */
int socket_set_nonblock(int fd);

/**
 * @brief Sets the send and receive buffer sizes for the socket.
 * @param fd The socket file descriptor.
 * @param sndbuf The send buffer size in bytes; ignored if <= 0.
 * @param rcvbuf The receive buffer size in bytes; ignored if <= 0.
 * @note POSIX version: POSIX.1-2001. Logs LOGW on setsockopt failure.
 */
void socket_set_buffer(int fd, int sndbuf, int rcvbuf);

/**
 * @brief Sets socket reuse options for binding to the same address and port.
 * @param fd The socket file descriptor.
 * @param reuseport If true, enables SO_REUSEPORT (Linux 3.9+), otherwise only SO_REUSEADDR.
 * @note POSIX version: POSIX.1-2001 (SO_REUSEADDR), Linux 3.9+ (SO_REUSEPORT). Logs LOGE on failure.
 */
void socket_set_reuseport(int fd, bool reuseport);

/**
 * @brief Sets TCP-specific options for the socket.
 * @param fd The socket file descriptor.
 * @param nodelay If true, disables Nagle's algorithm (TCP_NODELAY).
 * @param keepalive If true, enables TCP keepalive.
 * @note POSIX version: POSIX.1-2001. Logs LOGW on individual option failures.
 */
void socket_set_tcp(int fd, bool nodelay, bool keepalive);

/**
 * @brief Sets SO_LINGER behavior for close() on the socket.
 * @param fd The socket file descriptor.
 * @param enabled If true, enables linger behavior.
 * @param seconds Linger timeout in seconds when enabled.
 * @note POSIX version: POSIX.1-2001. Logs LOGW on failure.
 */
void socket_set_linger(int fd, bool enabled, int seconds);

/**
 * @brief Enables TCP Fast Open for server-side.
 * @param fd The socket file descriptor.
 * @param backlog The maximum number of pending TFO connections.
 * @note No-op unless compiled with WITH_TCP_FASTOPEN (Linux 3.6+). Logs LOGW on failure.
 */
void socket_set_fastopen(int fd, int backlog);

/**
 * @brief Enables TCP Fast Open for client-side.
 * @param fd The socket file descriptor.
 * @param enabled If true, enables client-side TFO.
 * @note No-op unless TCP_FASTOPEN_CONNECT is defined at compile time (Linux 4.11+). Logs LOGW on failure.
 */
void socket_set_fastopen_connect(int fd, bool enabled);

/**
 * @brief Sets the minimum number of bytes to receive before notifying.
 * @param fd The socket file descriptor.
 * @param bytes The minimum receive buffer low water mark; no-op if <= 0.
 * @note POSIX version: POSIX.1-2001. Logs LOGE on failure.
 */
void socket_rcvlowat(int fd, int bytes);

/**
 * @brief Retrieves the pending socket error.
 * @param fd The socket file descriptor.
 * @return SO_ERROR value on success, or errno if getsockopt itself fails.
 * @note POSIX version: POSIX.1-2001
 */
int socket_get_error(int fd);

/**
 * @brief Retrieves the local address of the socket.
 * @param fd The socket file descriptor.
 * @param[out] sa The output sockaddr union.
 * @return The length of the address on success, 0 on failure; logs LOGE on failure.
 * @note POSIX version: POSIX.1-2001
 */
socklen_t socket_get_addr(int fd, union sockaddr_max *sa);

/**
 * @brief Retrieves the peer address of the socket.
 * @param fd The socket file descriptor.
 * @param[out] sa The output sockaddr union.
 * @return The length of the address on success, 0 on failure; logs LOGE on failure.
 * @note POSIX version: POSIX.1-2001
 */
socklen_t socket_get_peer(int fd, union sockaddr_max *sa);

/**
 * @brief Sends data on a socket, retrying on EINTR.
 * @param fd The socket file descriptor.
 * @param buf The data buffer.
 * @param[in,out] len Input: bytes to send. Output: bytes sent; 0 on failure.
 * @return 0 on success; errno on failure (e.g. EAGAIN/EWOULDBLOCK).
 * @note POSIX version: POSIX.1-2001
 */
static inline int
socket_send(const int fd, const void *restrict buf, size_t *restrict len)
{
	ssize_t nsend;
	do {
		nsend = send(fd, buf, *len, 0);
	} while (nsend < 0 && errno == EINTR);
	if (nsend < 0) {
		*len = 0;
		return errno;
	}
	*len = (size_t)nsend;
	return 0;
}

/**
 * @brief Receives data from a socket, retrying on EINTR.
 * @param fd The socket file descriptor.
 * @param buf The data buffer.
 * @param[in,out] len Input: buffer size. Output: bytes received; 0 on EOF or failure.
 * @return 0 on success or EOF; errno on failure (e.g. EAGAIN/EWOULDBLOCK).
 *         EOF is indicated by a return value of 0 with @p len set to 0.
 * @note POSIX version: POSIX.1-2001
 */
static inline int
socket_recv(const int fd, void *restrict buf, size_t *restrict len)
{
	ssize_t nrecv;
	do {
		nrecv = recv(fd, buf, *len, 0);
	} while (nrecv < 0 && errno == EINTR);
	if (nrecv < 0) {
		*len = 0;
		return errno;
	}
	/* nrecv == 0: EOF */
	*len = (size_t)nrecv;
	return 0;
}

/**
 * @brief Returns the length of the sockaddr structure based on its family.
 * @param sa The sockaddr structure.
 * @return The length in bytes.
 * @note POSIX version: POSIX.1-2001
 */
socklen_t sa_len(const struct sockaddr *sa);

/**
 * @brief Copies a sockaddr structure.
 * @param dst The destination sockaddr.
 * @param src The source sockaddr.
 * @note POSIX version: POSIX.1-2001
 */
void sa_copy(struct sockaddr *restrict dst, const struct sockaddr *restrict src);

/**
 * @brief Formats a sockaddr into a string representation.
 * @param s The output buffer.
 * @param maxlen The maximum length of the buffer.
 * @param sa The sockaddr to format.
 * @return The number of characters written, or -1 on error.
 * @note POSIX version: POSIX.1-2001
 */
int sa_format(char *restrict s, size_t maxlen, const struct sockaddr *sa);

/**
 * @brief Checks if two sockaddr structures are equal.
 * @param a The first sockaddr.
 * @param b The second sockaddr.
 * @return True if equal.
 * @note POSIX version: POSIX.1-2001
 */
bool sa_equals(const struct sockaddr *a, const struct sockaddr *b);

/**
 * @brief Checks if a sockaddr matches a bind address (wildcards allowed).
 * @param bind The bind sockaddr.
 * @param dest The destination sockaddr.
 * @return True if matches.
 * @note POSIX version: POSIX.1-2001
 */
bool sa_matches(const struct sockaddr *bind, const struct sockaddr *dest);

enum ipclass {
	IPCLASS_UNKNOWN = -1,
	IPCLASS_UNSPECIFIED = 0,
	IPCLASS_LOOPBACK,
	IPCLASS_LINKLOCAL,
	IPCLASS_SITELOCAL,
	IPCLASS_MULTICAST,
	IPCLASS_GLOBAL,
};

/**
 * @brief Classifies the IP address of a sockaddr into an address class.
 * @param sa The sockaddr to classify.
 * @return The address class; IPCLASS_UNKNOWN for unknown address families.
 * @note POSIX version: POSIX.1-2001
 */
enum ipclass sa_ipclassify(const struct sockaddr *sa);

enum sa_resolve_type {
	SA_RESOLVE_TCP,
	SA_RESOLVE_UDP,
};

/**
 * @brief Resolves a hostname and service into a sockaddr.
 * @param[out] sa The output sockaddr union.
 * @param[in] name The hostname or IP.
 * @param[in] service The service name or port.
 * @param type The socket type (SA_RESOLVE_TCP or SA_RESOLVE_UDP).
 * @param family The preferred protocol family (PF_UNSPEC, PF_INET, or PF_INET6).
 * @return True on success, false on failure; logs LOGE on getaddrinfo failure.
 * @note POSIX version: POSIX.1-2001
 */
bool sa_resolve(
	union sockaddr_max *restrict sa, const char *name, const char *service,
	enum sa_resolve_type type, int family);

/**
 * @brief Resolves a bind hostname and service into a sockaddr.
 * @param[out] sa The output sockaddr union.
 * @param[in] name The hostname or IP.
 * @param[in] service The service name or port.
 * @param type The socket type (SA_RESOLVE_TCP or SA_RESOLVE_UDP).
 * @return True on success, false on failure; logs LOGE on getaddrinfo failure.
 * @note POSIX version: POSIX.1-2001
 */
bool sa_resolve_bind(
	union sockaddr_max *restrict sa, const char *name, const char *service,
	enum sa_resolve_type type);

/** @} */

#endif /* OS_SOCKET_H */
