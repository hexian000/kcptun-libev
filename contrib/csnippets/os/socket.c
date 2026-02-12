/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "socket.h"

#include "utils/slog.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool socket_set_nonblock(const int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		const int err = errno;
		LOGE_F("fcntl [fd:%d]: F_GETFL (%d) %s", fd, err,
		       strerror(err));
		return false;
	}
	if (fcntl(fd, F_SETFL, flags | FD_CLOEXEC | O_NONBLOCK) == -1) {
		const int err = errno;
		LOGE_F("fcntl [fd:%d]: F_SETFL (%d) %s", fd, err,
		       strerror(err));
		return false;
	}
	return true;
}

bool socket_set_buffer(const int fd, const int sndbuf, const int rcvbuf)
{
	if (sndbuf > 0) {
		if (setsockopt(
			    fd, SOL_SOCKET, SO_SNDBUF, &sndbuf,
			    sizeof(sndbuf)) != 0) {
			const int err = errno;
			LOGW_F("setsockopt [fd:%d]: SO_SNDBUF (%d) %s", fd, err,
			       strerror(err));
		}
	}
	if (rcvbuf > 0) {
		if (setsockopt(
			    fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf,
			    sizeof(rcvbuf)) != 0) {
			const int err = errno;
			LOGW_F("setsockopt [fd:%d]: SO_RCVBUF (%d) %s", fd, err,
			       strerror(err));
		}
	}
	return true;
}

void socket_set_reuseport(const int fd, const bool reuseport)
{
	const int opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
		const int err = errno;
		LOGE_F("setsockopt [fd:%d]: SO_REUSEADDR (%d) %s", fd, err,
		       strerror(err));
	}
#ifdef SO_REUSEPORT
	const int opt_reuseport = reuseport ? 1 : 0;
	if (setsockopt(
		    fd, SOL_SOCKET, SO_REUSEPORT, &opt_reuseport,
		    sizeof(opt_reuseport)) != 0) {
		const int err = errno;
		LOGE_F("setsockopt [fd:%d]: SO_REUSEPORT (%d) %s", fd, err,
		       strerror(err));
	}
#else
	(void)reuseport;
#endif
}

void socket_set_tcp(const int fd, const bool nodelay, const bool keepalive)
{
	{
		const int opt = nodelay ? 1 : 0;
		if (setsockopt(
			    fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) !=
		    0) {
			const int err = errno;
			LOGW_F("setsockopt [fd:%d]: TCP_NODELAY (%d) %s", fd,
			       err, strerror(err));
		}
	}
	{
		const int opt = keepalive ? 1 : 0;
		if (setsockopt(
			    fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) !=
		    0) {
			const int err = errno;
			LOGW_F("setsockopt [fd:%d]: SO_KEEPALIVE (%d) %s", fd,
			       err, strerror(err));
		}
	}
}

void socket_set_fastopen(const int fd, const int backlog)
{
#if WITH_TCP_FASTOPEN
	if (setsockopt(
		    fd, IPPROTO_TCP, TCP_FASTOPEN, &backlog, sizeof(backlog)) !=
	    0) {
		const int err = errno;
		LOGW_F("setsockopt [fd:%d]: TCP_FASTOPEN (%d) %s", fd, err,
		       strerror(err));
	}
#else
	(void)fd;
	(void)backlog;
#endif
}

void socket_set_fastopen_connect(const int fd, const bool enabled)
{
#ifdef TCP_FASTOPEN_CONNECT
	int val = enabled ? 1 : 0;
	if (setsockopt(
		    fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &val, sizeof(val))) {
		const int err = errno;
		LOGW_F("setsockopt [fd:%d]: TCP_FASTOPEN_CONNECT (%d) %s", fd,
		       err, strerror(err));
	}
#else
	(void)fd;
	(void)enabled;
#endif
}

void socket_rcvlowat(const int fd, const int bytes)
{
	if (bytes > 0) {
		socklen_t len = sizeof(bytes);
		if (setsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &bytes, len)) {
			const int err = errno;
			LOGE_F("setsockopt [fd:%d]: SO_RCVLOWAT (%d) %s", fd,
			       err, strerror(err));
		}
	}
}

int socket_get_error(const int fd)
{
	int err = 0;
	socklen_t len = sizeof(err);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) {
		err = errno;
	}
	return err;
}

int socket_send(const int fd, const void *restrict buf, size_t *restrict len)
{
	const unsigned char *b = buf;
	size_t nbsend = 0;
	size_t n = *len;
	while (n > 0) {
		const ssize_t nsend = send(fd, b, n, 0);
		if (nsend < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			LOGE_F("send [fd:%d]: (%d) %s", fd, err, strerror(err));
			*len = nbsend;
			return -1;
		}
		if (nsend == 0) {
			break;
		}
		b += nsend;
		n -= nsend;
		nbsend += nsend;
	}
	*len = nbsend;
	return 0;
}

int socket_recv(const int fd, void *restrict buf, size_t *restrict len)
{
	unsigned char *b = buf;
	size_t nbrecv = 0;
	size_t n = *len;
	while (n > 0) {
		const ssize_t nrecv = recv(fd, b, n, 0);
		if (nrecv < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			LOGE_F("recv [fd:%d]: (%d) %s", fd, err, strerror(err));
			*len = nbrecv;
			return -1;
		}
		if (nrecv == 0) {
			*len = nbrecv;
			return 1; /* EOF */
		}
		b += nrecv;
		n -= nrecv;
		nbrecv += nrecv;
	}
	*len = nbrecv;
	return 0;
}

socklen_t sa_len(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	default:
		break;
	}
	return 0;
}

void sa_copy(struct sockaddr *restrict dst, const struct sockaddr *restrict src)
{
	memcpy(dst, src, sa_len(src));
}

static int sa_format_inet(
	char *restrict s, const size_t maxlen,
	const struct sockaddr_in *restrict sa)
{
	char buf[INET_ADDRSTRLEN];
	if (inet_ntop(AF_INET, &(sa->sin_addr), buf, sizeof(buf)) == NULL) {
		return -1;
	}
	const uint16_t port = ntohs(sa->sin_port);
	return snprintf(s, maxlen, "%s:%" PRIu16, buf, port);
}

static int sa_format_inet6(
	char *restrict s, const size_t maxlen,
	const struct sockaddr_in6 *restrict sa)
{
	char buf[INET6_ADDRSTRLEN];
	if (inet_ntop(AF_INET6, &(sa->sin6_addr), buf, sizeof(buf)) == NULL) {
		return -1;
	}
	const uint16_t port = ntohs(sa->sin6_port);
	const uint32_t scope = sa->sin6_scope_id;
	if (scope == 0) {
		return snprintf(s, maxlen, "[%s]:%" PRIu16, buf, port);
	}
	return snprintf(
		s, maxlen, "[%s%%%" PRIu32 "]:%" PRIu16, buf, scope, port);
}

int sa_format(
	char *restrict s, const size_t maxlen,
	const struct sockaddr *restrict sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return sa_format_inet(s, maxlen, (struct sockaddr_in *)sa);
	case AF_INET6:
		return sa_format_inet6(s, maxlen, (struct sockaddr_in6 *)sa);
	default:
		break;
	}
	return snprintf(s, maxlen, "<af:%jd>", (intmax_t)sa->sa_family);
}

bool sa_equals(
	const struct sockaddr *restrict a, const struct sockaddr *restrict b)
{
	if (a->sa_family != b->sa_family) {
		return false;
	}
	switch (a->sa_family) {
	case AF_INET:
		return memcmp(a, b, sizeof(struct sockaddr_in)) == 0;
	case AF_INET6:
		return memcmp(a, b, sizeof(struct sockaddr_in6)) == 0;
	default:
		break;
	}
	return false;
}

static bool sa_matches_inet(
	const struct sockaddr_in *restrict bind,
	const struct sockaddr_in *restrict dest)
{
	/* port 0 means any port (skip check) */
	if (bind->sin_port != 0 && bind->sin_port != dest->sin_port) {
		return false;
	}
	if (bind->sin_addr.s_addr != INADDR_ANY &&
	    bind->sin_addr.s_addr != dest->sin_addr.s_addr) {
		return false;
	}
	return true;
}

static bool sa_matches_inet6(
	const struct sockaddr_in6 *restrict bind,
	const struct sockaddr_in6 *restrict dest)
{
	/* port 0 means any port (skip check) */
	if (bind->sin6_port != 0 && bind->sin6_port != dest->sin6_port) {
		return false;
	}
	if (!IN6_IS_ADDR_UNSPECIFIED(&bind->sin6_addr) &&
	    memcmp(&bind->sin6_addr, &dest->sin6_addr,
		   sizeof(struct in6_addr)) != 0) {
		return false;
	}
	return true;
}

bool sa_matches(
	const struct sockaddr *restrict bind,
	const struct sockaddr *restrict dest)
{
	const int domain = bind->sa_family;
	if (domain != dest->sa_family) {
		return false;
	}
	switch (domain) {
	case AF_INET:
		return sa_matches_inet(
			(const struct sockaddr_in *)bind,
			(const struct sockaddr_in *)dest);
	case AF_INET6:
		return sa_matches_inet6(
			(const struct sockaddr_in6 *)bind,
			(const struct sockaddr_in6 *)dest);
	default:
		break;
	}
	return false;
}

bool sa_is_unspecified(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET: {
		const in_addr_t addr = ntohl(
			((const struct sockaddr_in *)sa)->sin_addr.s_addr);
		return addr == INADDR_ANY;
	}
	case AF_INET6: {
		const struct in6_addr *addr =
			&((const struct sockaddr_in6 *)sa)->sin6_addr;
		return IN6_IS_ADDR_UNSPECIFIED(addr);
	}
	default:
		break;
	}
	return false;
}

bool sa_is_multicast(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET: {
		const in_addr_t addr = ntohl(
			((const struct sockaddr_in *)sa)->sin_addr.s_addr);
		switch (addr & ((in_addr_t)0xf0000000)) {
		case 0xe0000000: /* 224.0.0.0/4 */
			return false;
		}
		switch (addr) {
		case INADDR_BROADCAST: /* 255.255.255.255/32 */
			return false;
		}
		return false;
	}
	case AF_INET6: {
		const struct in6_addr *addr =
			&((const struct sockaddr_in6 *)sa)->sin6_addr;
		return IN6_IS_ADDR_MULTICAST(addr);
	}
	default:
		break;
	}
	return false;
}

bool sa_is_local(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET: {
		const in_addr_t addr = ntohl(
			((const struct sockaddr_in *)sa)->sin_addr.s_addr);
		switch (addr & ((in_addr_t)0xff000000)) {
		case 0x00000000: /* 0.0.0.0/8 */
		case 0x0a000000: /* 10.0.0.0/8 */
		case 0x7f000000: /* 127.0.0.0/8 */
			return true;
		}
		switch (addr & ((in_addr_t)0xfff00000)) {
		case 0xac100000: /* 172.16.0.0/12 */
			return true;
		}
		switch (addr & ((in_addr_t)0xffff0000)) {
		case 0xa9fe0000: /* 169.254.0.0/16 */
		case 0xc0a80000: /* 192.168.0.0/16 */
			return true;
		}
		switch (addr & ((in_addr_t)0xffffff00)) {
		case 0xc0000000: /* 192.0.0.0/24 */
			return true;
		}
		return false;
	}
	case AF_INET6: {
		const struct in6_addr *addr =
			&((const struct sockaddr_in6 *)sa)->sin6_addr;
		if (IN6_IS_ADDR_LINKLOCAL(addr) ||
		    IN6_IS_ADDR_SITELOCAL(addr)) {
			return true;
		}
		if (IN6_IS_ADDR_UNSPECIFIED(addr) ||
		    IN6_IS_ADDR_LOOPBACK(addr)) {
			return true;
		}
		return false;
	}
	default:
		break;
	}
	return false;
}

static bool find_addrinfo(
	union sockaddr_max *restrict sa, const struct addrinfo *restrict node)
{
	for (const struct addrinfo *it = node; it != NULL; it = it->ai_next) {
		switch (it->ai_family) {
		case AF_INET:
			if (it->ai_addrlen != sizeof(struct sockaddr_in)) {
				LOGW_F("getaddrinfo: invalid ai_addrlen %ju (af=%d)",
				       (uintmax_t)it->ai_addrlen,
				       it->ai_family);
				continue;
			}
			sa->in = *(struct sockaddr_in *)it->ai_addr;
			break;
		case AF_INET6:
			if (it->ai_addrlen != sizeof(struct sockaddr_in6)) {
				LOGW_F("getaddrinfo: invalid ai_addrlen %ju (af=%d)",
				       (uintmax_t)it->ai_addrlen,
				       it->ai_family);
				continue;
			}
			sa->in6 = *(struct sockaddr_in6 *)it->ai_addr;
			break;
		default:
			continue;
		}
		return true;
	}
	return false;
}

static bool nsresolve(
	union sockaddr_max *restrict sa, const char *restrict name,
	const char *restrict service, const struct addrinfo *restrict hints)
{
	struct addrinfo *result = NULL;
	const int err = getaddrinfo(name, service, hints, &result);
	if (err != 0) {
		LOGE_F("getaddrinfo: resolve `%s' `%s': (%d) %s", name, service,
		       err, gai_strerror(err));
		return false;
	}
	const bool ok = find_addrinfo(sa, result);
	freeaddrinfo(result);
	return ok;
}

bool sa_resolve_tcp(
	union sockaddr_max *restrict sa, const char *restrict name,
	const char *restrict service, const int family)
{
	const struct addrinfo hints = {
		.ai_family = family,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = AI_ADDRCONFIG,
	};
	return nsresolve(sa, name, service, &hints);
}

bool sa_resolve_tcpbind(
	union sockaddr_max *restrict sa, const char *restrict name,
	const char *restrict service)
{
	if (name[0] == '\0') {
		name = NULL;
	}
	struct addrinfo hints = {
		.ai_family = PF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = AI_ADDRCONFIG | AI_PASSIVE,
	};
	return nsresolve(sa, name, service, &hints);
}

bool sa_resolve_udp(
	union sockaddr_max *restrict sa, const char *restrict name,
	const char *restrict service, const int family)
{
	const struct addrinfo hints = {
		.ai_family = family,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP,
		.ai_flags = AI_ADDRCONFIG,
	};
	return nsresolve(sa, name, service, &hints);
}

bool sa_resolve_udpbind(
	union sockaddr_max *restrict sa, const char *name, const char *service)
{
	if (name[0] == '\0') {
		name = NULL;
	}
	struct addrinfo hints = {
		.ai_family = PF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP,
		.ai_flags = AI_ADDRCONFIG | AI_PASSIVE,
	};
	return nsresolve(sa, name, service, &hints);
}
