/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "sockutil.h"
#include "utils/minmax.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "algo/hashtable.h"
#include "util.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>

bool socket_set_nonblock(const int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);
	return fcntl(fd, F_SETFL, flags | O_CLOEXEC | O_NONBLOCK) != -1;
}

void socket_set_reuseport(const int fd, const bool reuseport)
{
	int val = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val))) {
		const int err = errno;
		LOGW_F("SO_REUSEADDR: %s", strerror(err));
	}
#ifdef SO_REUSEPORT
	val = reuseport ? 1 : 0;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val))) {
		const int err = errno;
		LOGW_F("SO_REUSEPORT: %s", strerror(err));
	}
#else
	if (reuseport) {
		LOGW("reuseport: not supported in current build");
	}
#endif
}

void socket_set_tcp(const int fd, const bool nodelay, const bool keepalive)
{
	int val = nodelay ? 1 : 0;
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val))) {
		const int err = errno;
		LOGW_F("TCP_NODELAY: %s", strerror(err));
	}
	val = keepalive ? 1 : 0;
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val))) {
		const int err = errno;
		LOGW_F("SO_KEEPALIVE: %s", strerror(err));
	}
}

void socket_set_buffer(const int fd, const size_t send, const size_t recv)
{
	int val;
	if (send > 0) {
		CHECKMSGF(
			send <= INT_MAX, "invalid send buffer size: %zu", send);
		val = (int)send;
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val))) {
			const int err = errno;
			LOGW_F("SO_SNDBUF: %s", strerror(err));
		}
	}
	if (recv > 0) {
		CHECKMSGF(
			recv <= INT_MAX, "invalid recv buffer size: %zu", recv);
		val = (int)recv;
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val))) {
			const int err = errno;
			LOGW_F("SO_RCVBUF: %s", strerror(err));
		}
	}
}

void socket_bind_netdev(const int fd, const char *netdev)
{
#ifdef SO_BINDTODEVICE
	char ifname[IFNAMSIZ];
	(void)strncpy(ifname, netdev, sizeof(ifname) - 1);
	ifname[sizeof(ifname) - 1] = '\0';
	if (setsockopt(
		    fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, sizeof(ifname))) {
		const int err = errno;
		LOGW_F("SO_BINDTODEVICE: %s", strerror(err));
	}
#else
	UNUSED(fd);
	UNUSED(netdev);
	LOGW("netdev: not supported in current build");
#endif
}

socklen_t getsocklen(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	default:
		break;
	}
	FAIL();
}

void conv_make_key(
	hashkey_t *key, const struct sockaddr *sa, const uint32_t conv)
{
	memset(key, 0, sizeof(hashkey_t));
	struct {
		sockaddr_max_t sa;
		uint32_t conv;
	} *ep = (void *)key;
	memcpy(&ep->sa, sa, getsocklen(sa));
	ep->conv = conv;
}

bool sa_equals(const struct sockaddr *a, const struct sockaddr *b)
{
	const socklen_t na = getsocklen(a);
	const socklen_t nb = getsocklen(b);
	return na == nb && memcmp(a, b, na) == 0;
}

static bool sa_matches_inet(
	const struct sockaddr_in *restrict bind,
	const struct sockaddr_in *restrict dest)
{
	if (bind->sin_port != dest->sin_port) {
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
	if (bind->sin6_port != dest->sin6_port) {
		return false;
	}
	if (!IN6_IS_ADDR_UNSPECIFIED(&bind->sin6_addr) &&
	    memcmp(&bind->sin6_addr, &dest->sin6_addr,
		   sizeof(struct in6_addr)) != 0) {
		return false;
	}
	return true;
}

bool sa_matches(const struct sockaddr *bind, const struct sockaddr *dest)
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
	FAIL();
}

struct sockaddr *sa_clone(const struct sockaddr *src)
{
	const socklen_t len = getsocklen(src);
	struct sockaddr *dst = malloc(len);
	if (dst != NULL) {
		memcpy(dst, src, len);
	}
	return dst;
}

static int
format_sa_inet(const struct sockaddr_in *sa, char *buf, const size_t buf_size)
{
	char s[INET_ADDRSTRLEN];
	if (inet_ntop(AF_INET, &(sa->sin_addr), s, sizeof(s)) == NULL) {
		return -1;
	}
	const uint16_t port = ntohs(sa->sin_port);
	return snprintf(buf, buf_size, "%s:%" PRIu16, s, port);
}

static int
format_sa_inet6(const struct sockaddr_in6 *sa, char *buf, const size_t buf_size)
{
	char s[INET6_ADDRSTRLEN];
	if (inet_ntop(AF_INET6, &(sa->sin6_addr), s, sizeof(s)) == NULL) {
		return -1;
	}
	const uint16_t port = ntohs(sa->sin6_port);
	const uint32_t scope = sa->sin6_scope_id;
	if (scope == 0) {
		return snprintf(buf, buf_size, "[%s]:%" PRIu16, s, port);
	}
	return snprintf(
		buf, buf_size, "[%s%%%" PRIu32 "]:%" PRIu16, s, scope, port);
}

int format_sa(const struct sockaddr *sa, char *buf, const size_t buf_size)
{
	switch (sa->sa_family) {
	case AF_INET:
		return format_sa_inet((struct sockaddr_in *)sa, buf, buf_size);
	case AF_INET6:
		return format_sa_inet6(
			(struct sockaddr_in6 *)sa, buf, buf_size);
	default:
		break;
	}
	return snprintf(buf, buf_size, "<af:%jd>", (intmax_t)sa->sa_family);
}

struct sockaddr *
resolve_sa(const char *hostname, const char *service, const int flags)
{
	struct addrinfo hints = {
		.ai_family = PF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG,
	};
	if (flags & RESOLVE_UDP) {
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	}
	if (flags & RESOLVE_PASSIVE) {
		hints.ai_flags |= AI_PASSIVE;
	}
	struct addrinfo *result = NULL;
	if (getaddrinfo(hostname, service, &hints, &result) != 0) {
		const int err = errno;
		LOGE_F("resolve: %s", strerror(err));
		return NULL;
	}
	struct sockaddr *sa = NULL;
	for (const struct addrinfo *it = result; it; it = it->ai_next) {
		switch (it->ai_family) {
		case AF_INET:
		case AF_INET6:
			break;
		default:
			continue;
		}
		sa = sa_clone(it->ai_addr);
		break;
	}
	freeaddrinfo(result);
	return sa;
}
