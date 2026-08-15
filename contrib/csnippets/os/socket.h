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
 * @details Setup functions return 0 on success or an errno on failure, and
 * never log. ENOPROTOOPT means the option is unsupported on this platform,
 * whether rejected at runtime or absent at compile time.
 * @{
 */

/**
 * @brief Shuts down part of a full-duplex socket.
 * @param fd The socket file descriptor.
 * @param how The shutdown direction (SHUT_RD, SHUT_WR, or SHUT_RDWR).
 * @return 0 on success; errno on failure.
 * @note POSIX version: POSIX.1-2001
 */
int socket_shutdown(int fd, int how);

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
 * @return 0 on success; errno on failure.
 * @note POSIX version: POSIX.1-2001
 * @note On failure, the fd stays inheritable across exec() and may leak into
 * child processes.
 */
int socket_set_cloexec(int fd);

/**
 * @brief Sets the socket to non-blocking mode.
 * @param fd The socket file descriptor.
 * @return 0 on success; errno on failure.
 * @note POSIX version: POSIX.1-2001
 * @note On failure, the socket stays in blocking mode; I/O calls on it can
 * block the calling thread instead of returning EAGAIN/EWOULDBLOCK.
 */
int socket_set_nonblock(int fd);

/**
 * @brief Sets the send and receive buffer sizes for the socket.
 * @param fd The socket file descriptor.
 * @param sndbuf The send buffer size in bytes; ignored if <= 0.
 * @param rcvbuf The receive buffer size in bytes; ignored if <= 0.
 * @return 0 on success; the first failing option's errno on failure.
 * @note POSIX version: POSIX.1-2001
 * @note sndbuf and rcvbuf are applied independently; on failure, one may
 * have been applied while the other keeps its existing (system default)
 * size.
 */
int socket_set_buffer(int fd, int sndbuf, int rcvbuf);

/**
 * @brief Sets socket reuse options for binding to the same address and port.
 * @param fd The socket file descriptor.
 * @param reuseport If true, enables SO_REUSEPORT (Linux 3.9+), otherwise only SO_REUSEADDR.
 * @return 0 on success; the first failing option's errno on failure.
 * @note POSIX version: POSIX.1-2001 (SO_REUSEADDR), Linux 3.9+ (SO_REUSEPORT)
 * @note Requesting reuseport yields ENOPROTOOPT if SO_REUSEPORT is not defined
 * at compile time, rather than reporting success on SO_REUSEADDR alone;
 * reuseport=false (SO_REUSEADDR only) still succeeds there.
 * @note SO_REUSEADDR and SO_REUSEPORT are applied independently; on
 * failure, one may have been applied while the other was not, and a
 * subsequent bind() to an address/port already in use may then fail.
 */
int socket_set_reuseport(int fd, bool reuseport);

/**
 * @brief Sets TCP-specific options for the socket.
 * @param fd The socket file descriptor.
 * @param nodelay If true, disables Nagle's algorithm (TCP_NODELAY).
 * @param keepalive If true, enables TCP keepalive.
 * @return 0 on success; the first failing option's errno on failure.
 * @note POSIX version: POSIX.1-2001
 * @note nodelay and keepalive are applied independently; on failure, one
 * may have been applied while the other is left at its previous setting.
 */
int socket_set_tcp(int fd, bool nodelay, bool keepalive);

/**
 * @brief Sets SO_LINGER behavior for close() on the socket.
 * @param fd The socket file descriptor.
 * @param enabled If true, enables linger behavior.
 * @param seconds Linger timeout in seconds when enabled.
 * @return 0 on success; errno on failure.
 * @note POSIX version: POSIX.1-2001
 * @note On failure, close() uses the platform's default (non-linger)
 * behavior instead of the requested setting.
 */
int socket_set_linger(int fd, bool enabled, int seconds);

/**
 * @brief Enables TCP Fast Open for server-side.
 * @param fd The socket file descriptor.
 * @param backlog The maximum number of pending TFO connections.
 * @return 0 on success; errno on failure.
 * @note Requires TCP_FASTOPEN at compile time (Linux 3.6+); ENOPROTOOPT
 * otherwise.
 * @note On failure, TFO is not enabled and connections use a regular TCP
 * handshake.
 */
int socket_set_fastopen(int fd, int backlog);

/**
 * @brief Enables TCP Fast Open for client-side.
 * @param fd The socket file descriptor.
 * @param enabled If true, enables client-side TFO.
 * @return 0 on success; errno on failure.
 * @note Requires TCP_FASTOPEN_CONNECT at compile time (Linux 4.11+);
 * ENOPROTOOPT otherwise.
 * @note On failure, TFO is not enabled and connections use a regular TCP
 * handshake.
 */
int socket_set_fastopen_connect(int fd, bool enabled);

/**
 * @brief Sets the maximum amount of unsent data allowed in the TCP send buffer.
 * @param fd The socket file descriptor.
 * @param bytes The unsent data limit in bytes.
 * @return 0 on success; errno on failure.
 * @note Requires TCP_NOTSENT_LOWAT at compile time (Linux 3.12+); ENOPROTOOPT
 * otherwise.
 * @note On failure, the socket keeps its existing unsent-data limit.
 */
int socket_notsent_lowat(int fd, int bytes);

/**
 * @brief Sets the minimum number of bytes to receive before notifying.
 * @param fd The socket file descriptor.
 * @param bytes The minimum receive buffer low water mark; no-op if <= 0.
 * @return 0 on success; errno on failure.
 * @note POSIX version: POSIX.1-2001
 * @note On failure, the socket keeps its existing receive low water mark.
 */
int socket_rcvlowat(int fd, int bytes);

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
 * @return 0 on success; errno on failure.
 * @note POSIX version: POSIX.1-2001
 */
int socket_get_addr(int fd, union sockaddr_max *sa);

/**
 * @brief Retrieves the peer address of the socket.
 * @param fd The socket file descriptor.
 * @param[out] sa The output sockaddr union.
 * @return 0 on success; errno on failure.
 * @note POSIX version: POSIX.1-2001
 */
int socket_get_peer(int fd, union sockaddr_max *sa);

/**
 * @brief Sends data on a socket, retrying on EINTR.
 * @param fd The socket file descriptor.
 * @param buf The data buffer.
 * @param[in,out] len Input: bytes to send. Output: bytes sent; 0 on failure.
 * @return 0 on success; errno on failure (e.g. EAGAIN/EWOULDBLOCK).
 * @note This calls send() without MSG_NOSIGNAL, so writing to a socket whose
 * peer has closed its read side raises SIGPIPE, which by default terminates the
 * process. Callers must ignore SIGPIPE (e.g. signal(SIGPIPE, SIG_IGN)) before
 * use, after which the send fails with EPIPE instead.
 * @note POSIX version: POSIX.1-2001
 */
static inline int
socket_send(const int fd, const void *restrict buf, size_t *restrict len)
{
	for (;;) {
		const ssize_t nsend = send(fd, buf, *len, 0);
		if (nsend < 0) {
			/* read errno once per failure, before anything else can
			 * clobber it */
			const int err = errno;
			if (err == EINTR) {
				continue;
			}
			*len = 0;
			return err;
		}
		*len = (size_t)nsend;
		return 0;
	}
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
	for (;;) {
		const ssize_t nrecv = recv(fd, buf, *len, 0);
		if (nrecv < 0) {
			/* read errno once per failure, before anything else can
			 * clobber it */
			const int err = errno;
			if (err == EINTR) {
				continue;
			}
			*len = 0;
			return err;
		}
		/* nrecv == 0: EOF */
		*len = (size_t)nrecv;
		return 0;
	}
}

/**
 * @brief Returns the length of the sockaddr structure based on its family.
 * @param sa The sockaddr structure.
 * @return The length in bytes for AF_INET / AF_INET6, or 0 for any other
 * (unsupported) family. Callers such as sa_copy rely on this 0.
 * @note POSIX version: POSIX.1-2001
 */
socklen_t sa_len(const struct sockaddr *sa);

/**
 * @brief Copies a sockaddr structure.
 * @param dst The destination sockaddr.
 * @param src The source sockaddr.
 * @note The source family must be supported by sa_len (AF_INET or AF_INET6);
 *       any other family would copy zero bytes and leave dst indeterminate,
 *       so it is rejected by an assertion.
 * @note POSIX version: POSIX.1-2001
 */
void sa_copy(struct sockaddr *restrict dst, const struct sockaddr *restrict src);

/**
 * @brief Formats a sockaddr into a string representation.
 * @param s The output buffer.
 * @param maxlen The maximum length of the buffer.
 * @param sa The sockaddr to format.
 * @return snprintf semantics: the length the full output would have, excluding
 * the terminating null, so a value >= maxlen means the output was truncated;
 * -1 on error.
 * @note POSIX version: POSIX.1-2001
 */
int sa_format(
	char *restrict s, size_t maxlen, const struct sockaddr *restrict sa);

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
	IPCLASS_SHARED, /* RFC 6598 shared address space (100.64.0.0/10, CGNAT) */
	IPCLASS_RESERVED, /* RFC 1112 reserved for future use (240.0.0.0/4) */
	IPCLASS_BROADCAST, /* RFC 919 limited broadcast (255.255.255.255) */
};

/**
 * @brief Classifies the IP address of a sockaddr into an address class.
 * @details Only blocks that RFC assigns a class of their own are special-cased.
 * A reservation without one reports IPCLASS_GLOBAL by design -- the RFC 5737 /
 * RFC 3849 documentation and RFC 2544 / RFC 5180 benchmarking ranges are used
 * as ordinary addresses in practice.
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
 * @return True on success, false on failure; logs LOGE on failure, whether
 * getaddrinfo failed or returned no usable address.
 * @note POSIX version: POSIX.1-2001
 * @note AI_ADDRCONFIG applies only when @p name needs the resolver. A numeric
 * address is taken as given: the flag ignores loopback, so it would otherwise
 * reject 127.0.0.1 and ::1 on a host with only `lo` up.
 */
bool sa_resolve(
	union sockaddr_max *restrict sa, const char *restrict name,
	const char *restrict service, enum sa_resolve_type type, int family);

/**
 * @brief Resolves a bind hostname and service into a sockaddr.
 * @param[out] sa The output sockaddr union.
 * @param[in] name The hostname or IP.
 * @param[in] service The service name or port.
 * @param type The socket type (SA_RESOLVE_TCP or SA_RESOLVE_UDP).
 * @return True on success, false on failure; logs LOGE on failure, whether
 * getaddrinfo failed or returned no usable address.
 * @note POSIX version: POSIX.1-2001
 * @note AI_ADDRCONFIG is never applied, so a host with only `lo` up still
 * resolves. An empty or NULL @p name therefore yields the wildcard of whichever
 * family the resolver lists first; name "0.0.0.0" or "::" to pin one.
 */
bool sa_resolve_bind(
	union sockaddr_max *restrict sa, const char *restrict name,
	const char *restrict service, enum sa_resolve_type type);

/** @} */

#endif /* OS_SOCKET_H */
