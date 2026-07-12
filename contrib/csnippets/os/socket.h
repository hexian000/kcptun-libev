/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef OS_SOCKET_H
#define OS_SOCKET_H

#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

/**
 * @defgroup sockutil
 * @brief Utilities for socket setup and management.
 * @{
 */

/**
 * @brief Shuts down part of a full-duplex socket and logs any errors.
 * @param fd The socket file descriptor.
 * @param how The shutdown direction (SHUT_RD, SHUT_WR, or SHUT_RDWR).
 * @return True on success, false on failure; logs LOGW on failure.
 * @note POSIX version: POSIX.1-2001
 */
bool socket_shutdown(int fd, int how);

/**
 * @brief Closes the file descriptor and logs any errors.
 * @param fd The file descriptor.
 * @note POSIX version: POSIX.1-2001. Logs LOGW on failure.
 */
void socket_close(int fd);

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
 * @return True on success, false on failure; logs LOGE on failure.
 * @note POSIX version: POSIX.1-2001
 * @note On failure, the fd stays inheritable across exec() and may leak into
 * child processes.
 */
bool socket_set_cloexec(int fd);

/**
 * @brief Sets the socket to non-blocking mode.
 * @param fd The socket file descriptor.
 * @return True on success, false on failure; logs LOGE on failure.
 * @note POSIX version: POSIX.1-2001
 * @note On failure, the socket stays in blocking mode; I/O calls on it can
 * block the calling thread instead of returning EAGAIN/EWOULDBLOCK.
 */
bool socket_set_nonblock(int fd);

/**
 * @brief Sets the send and receive buffer sizes for the socket.
 * @param fd The socket file descriptor.
 * @param sndbuf The send buffer size in bytes; ignored if <= 0.
 * @param rcvbuf The receive buffer size in bytes; ignored if <= 0.
 * @return True on success, false on failure; logs LOGW on failure.
 * @note POSIX version: POSIX.1-2001
 * @note sndbuf and rcvbuf are applied independently; on failure, one may
 * have been applied while the other keeps its existing (system default)
 * size.
 */
bool socket_set_buffer(int fd, int sndbuf, int rcvbuf);

/**
 * @brief Sets socket reuse options for binding to the same address and port.
 * @param fd The socket file descriptor.
 * @param reuseport If true, enables SO_REUSEPORT (Linux 3.9+), otherwise only SO_REUSEADDR.
 * @return True on success, false on failure; logs LOGE on failure.
 * @note POSIX version: POSIX.1-2001 (SO_REUSEADDR), Linux 3.9+ (SO_REUSEPORT)
 * @note SO_REUSEADDR and SO_REUSEPORT are applied independently; on
 * failure, one may have been applied while the other was not, and a
 * subsequent bind() to an address/port already in use may then fail.
 */
bool socket_set_reuseport(int fd, bool reuseport);

/**
 * @brief Sets TCP-specific options for the socket.
 * @param fd The socket file descriptor.
 * @param nodelay If true, disables Nagle's algorithm (TCP_NODELAY).
 * @param keepalive If true, enables TCP keepalive.
 * @return True on success, false on failure; logs LOGW on individual option failures.
 * @note POSIX version: POSIX.1-2001
 * @note nodelay and keepalive are applied independently; on failure, one
 * may have been applied while the other is left at its previous setting.
 */
bool socket_set_tcp(int fd, bool nodelay, bool keepalive);

/**
 * @brief Sets SO_LINGER behavior for close() on the socket.
 * @param fd The socket file descriptor.
 * @param enabled If true, enables linger behavior.
 * @param seconds Linger timeout in seconds when enabled.
 * @return True on success, false on failure; logs LOGW on failure.
 * @note POSIX version: POSIX.1-2001
 * @note On failure, close() uses the platform's default (non-linger)
 * behavior instead of the requested setting.
 */
bool socket_set_linger(int fd, bool enabled, int seconds);

/**
 * @brief Enables TCP Fast Open for server-side.
 * @param fd The socket file descriptor.
 * @param backlog The maximum number of pending TFO connections.
 * @return True on success; false on failure or if unsupported at compile time. Logs LOGW on failure.
 * @note No-op unless TCP_FASTOPEN is defined at compile time (Linux 3.6+).
 * @note On failure, TFO is not enabled and connections use a regular TCP
 * handshake.
 */
bool socket_set_fastopen(int fd, int backlog);

/**
 * @brief Enables TCP Fast Open for client-side.
 * @param fd The socket file descriptor.
 * @param enabled If true, enables client-side TFO.
 * @return True on success; false on failure or if unsupported at compile time. Logs LOGW on failure.
 * @note No-op unless TCP_FASTOPEN_CONNECT is defined at compile time (Linux 4.11+).
 * @note On failure, TFO is not enabled and connections use a regular TCP
 * handshake.
 */
bool socket_set_fastopen_connect(int fd, bool enabled);

/**
 * @brief Sets the maximum amount of unsent data allowed in the TCP send buffer.
 * @param fd The socket file descriptor.
 * @param bytes The unsent data limit in bytes.
 * @return True on success; false on failure or if unsupported at compile time. Logs LOGW on failure.
 * @note No-op unless TCP_NOTSENT_LOWAT is defined at compile time (Linux 3.12+).
 * @note On failure, the socket keeps its existing unsent-data limit.
 */
bool socket_notsent_lowat(int fd, int bytes);

/**
 * @brief Sets the minimum number of bytes to receive before notifying.
 * @param fd The socket file descriptor.
 * @param bytes The minimum receive buffer low water mark; no-op if <= 0.
 * @return True on success, false on failure; logs LOGE on failure.
 * @note POSIX version: POSIX.1-2001
 * @note On failure, the socket keeps its existing receive low water mark.
 */
bool socket_rcvlowat(int fd, int bytes);

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
 * @return True on success, false on failure; logs LOGE on failure.
 * @note POSIX version: POSIX.1-2001
 */
bool socket_get_addr(int fd, union sockaddr_max *sa);

/**
 * @brief Retrieves the peer address of the socket.
 * @param fd The socket file descriptor.
 * @param[out] sa The output sockaddr union.
 * @return True on success, false on failure; logs LOGE on failure.
 * @note POSIX version: POSIX.1-2001
 */
bool socket_get_peer(int fd, union sockaddr_max *sa);

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
