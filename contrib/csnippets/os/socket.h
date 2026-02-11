/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef OS_SOCKUTIL_H
#define OS_SOCKUTIL_H

#include "utils/slog.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/**
 * @defgroup sockutil
 * @brief Utilities for socket setup and management.
 * @{
 */

/**
 * @def IS_TRANSIENT_ERROR(err)
 * @brief Checks if the error code indicates a transient error that may be retried.
 * @param err The error code to check.
 * @return True if the error is transient.
 * @note POSIX version: POSIX.1-2001
 */
#define IS_TRANSIENT_ERROR(err)                                                \
	((err) == EINTR || (err) == EAGAIN || (err) == EWOULDBLOCK ||          \
	 (err) == ENOBUFS || (err) == ENOMEM)

/**
 * @def SHUTDOWN_FD(fd)
 * @brief Shuts down the write end of the socket and logs any errors.
 * @param fd The socket file descriptor.
 */
#define SHUTDOWN_FD(fd)                                                        \
	do {                                                                   \
		if (shutdown((fd), SHUT_WR) != 0) {                            \
			const int err = errno;                                 \
			LOGW_F("shutdown [fd:%d]: (%d) %s", (fd), err,         \
			       strerror(err));                                 \
		}                                                              \
	} while (0)

/**
 * @def CLOSE_FD(fd)
 * @brief Closes the file descriptor and logs any errors.
 * @param fd The file descriptor.
 */
#define CLOSE_FD(fd)                                                           \
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
 * @brief Sets the socket to non-blocking mode and enables the close-on-exec flag.
 * @param fd The socket file descriptor.
 * @return True on success, false on failure.
 * @note POSIX version: POSIX.1-2001
 */
bool socket_set_nonblock(int fd);

/**
 * @brief Sets the send and receive buffer sizes for the socket.
 * @param fd The socket file descriptor.
 * @param sndbuf The send buffer size in bytes; ignored if <= 0.
 * @param rcvbuf The receive buffer size in bytes; ignored if <= 0.
 * @return True on success, false on failure.
 * @note POSIX version: POSIX.1-2001
 */
bool socket_set_buffer(int fd, int sndbuf, int rcvbuf);

/**
 * @brief Sets socket reuse options for binding to the same address and port.
 * @param fd The socket file descriptor.
 * @param reuseport If true, enables SO_REUSEPORT (Linux 3.9+), otherwise only SO_REUSEADDR.
 * @note POSIX version: POSIX.1-2001 (SO_REUSEADDR), Linux 3.9+ (SO_REUSEPORT)
 */
void socket_set_reuseport(int fd, bool reuseport);

/**
 * @brief Sets TCP-specific options for the socket.
 * @param fd The socket file descriptor.
 * @param nodelay If true, disables Nagle's algorithm (TCP_NODELAY).
 * @param keepalive If true, enables TCP keepalive.
 * @note POSIX version: POSIX.1-2001
 */
void socket_set_tcp(int fd, bool nodelay, bool keepalive);

/**
 * @brief Enables TCP Fast Open for server-side.
 * @param fd The socket file descriptor.
 * @param backlog The maximum number of pending TFO connections.
 * @note Linux version: Linux 3.6+
 */
void socket_set_fastopen(int fd, int backlog);

/**
 * @brief Enables TCP Fast Open for client-side.
 * @param fd The socket file descriptor.
 * @param enabled If true, enables client-side TFO.
 * @note Linux version: Linux 4.11+
 */
void socket_set_fastopen_connect(int fd, bool enabled);

/**
 * @brief Sets the minimum number of bytes to receive before notifying.
 * @param fd The socket file descriptor.
 * @param bytes The minimum receive buffer low water mark.
 * @note POSIX version: POSIX.1-2001
 */
void socket_rcvlowat(int fd, int bytes);

/**
 * @brief Retrieves the pending socket error.
 * @param fd The socket file descriptor.
 * @return The error code, or 0 if no error.
 * @note POSIX version: POSIX.1-2001
 */
int socket_get_error(int fd);

/**
 * @brief Sends data on a socket, handling partial sends and transient errors.
 * @param fd The socket file descriptor.
 * @param buf The data buffer.
 * @param len Pointer to the length of data to send; updated to bytes sent.
 * @return 0 on success, -1 on unrecoverable failure.
 * @note POSIX version: POSIX.1-2001
 */
int socket_send(int fd, const void *restrict buf, size_t *restrict len);

/**
 * @brief Receives data from a socket, handling partial receives and transient errors.
 * @param fd The socket file descriptor.
 * @param buf The data buffer.
 * @param len Pointer to the buffer size; updated to bytes received.
 * @return 0 on success, -1 on unrecoverable failure, 1 on EOF.
 * @note POSIX version: POSIX.1-2001
 */
int socket_recv(int fd, void *restrict buf, size_t *restrict len);

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

/**
 * @brief Checks if the sockaddr represents an unspecified address.
 * @param sa The sockaddr.
 * @return True if unspecified.
 * @note POSIX version: POSIX.1-2001
 */
bool sa_is_unspecified(const struct sockaddr *sa);

/**
 * @brief Checks if the sockaddr represents a multicast address.
 * @param sa The sockaddr.
 * @return True if multicast.
 * @note POSIX version: POSIX.1-2001
 */
bool sa_is_multicast(const struct sockaddr *sa);

/**
 * @brief Checks if the sockaddr represents a local (private) address.
 * @param sa The sockaddr.
 * @return True if local.
 * @note POSIX version: POSIX.1-2001
 */
bool sa_is_local(const struct sockaddr *sa);

/**
 * @brief Resolves a hostname and service into a TCP sockaddr.
 * @param[out] sa The output sockaddr union.
 * @param[in] name The hostname or IP.
 * @param[in] service The service name or port.
 * @param family The preferred protocol family (PF_UNSPEC, PF_INET, or PF_INET6).
 * @return True on success.
 * @note POSIX version: POSIX.1-2001
 */
bool sa_resolve_tcp(
	union sockaddr_max *restrict sa, const char *name, const char *service,
	int family);

/**
 * @brief Resolves a bind hostname and service string into a TCP sockaddr.
 * @param[out] sa The output sockaddr union.
 * @param[in] name The hostname or IP.
 * @param[in] service The service name or port.
 * @return True on success.
 * @note POSIX version: POSIX.1-2001
 */
bool sa_resolve_tcpbind(
	union sockaddr_max *restrict sa, const char *name, const char *service);

/**
 * @brief Resolves a hostname and service into a UDP sockaddr.
 * @param[out] sa The output sockaddr union.
 * @param[in] name The hostname or IP.
 * @param[in] service The service name or port.
 * @param family The preferred protocol family (PF_UNSPEC, PF_INET, or PF_INET6).
 * @return True on success.
 * @note POSIX version: POSIX.1-2001
 */
bool sa_resolve_udp(
	union sockaddr_max *restrict sa, const char *name, const char *service,
	int family);

/**
 * @brief Resolves a bind hostname and service string into a UDP sockaddr.
 * @param[out] sa The output sockaddr union.
 * @param[in] name The hostname or IP.
 * @param[in] service The service name or port.
 * @return True on success.
 * @note POSIX version: POSIX.1-2001
 */
bool sa_resolve_udpbind(
	union sockaddr_max *restrict sa, const char *name, const char *service);

/** @} */

#endif /* OS_SOCKUTIL_H */
