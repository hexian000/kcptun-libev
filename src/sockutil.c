/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "sockutil.h"
#include "utils/minmax.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "net/addr.h"
#include "util.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>

#include <assert.h>
#include <errno.h>
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
		LOGW_F("SO_REUSEPORT: %s", "not supported in current build");
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
			recv <= INT_MAX, "SO_SNDBUF: %s", "value out of range");
		val = (int)send;
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val))) {
			const int err = errno;
			LOGW_F("SO_SNDBUF: %s", strerror(err));
		}
	}
	if (recv > 0) {
		CHECKMSGF(
			recv <= INT_MAX, "SO_RCVBUF: %s", "value out of range");
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
	if (netdev[0] != '\0') {
		LOGW_F("SO_BINDTODEVICE: %s", "not supported in current build");
	}
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

static bool find_addrinfo(sockaddr_max_t *sa, const struct addrinfo *it)
{
	for (; it != NULL; it = it->ai_next) {
		switch (it->ai_family) {
		case AF_INET:
			CHECK(it->ai_addrlen == sizeof(struct sockaddr_in));
			sa->in = *(struct sockaddr_in *)it->ai_addr;
			break;
		case AF_INET6:
			CHECK(it->ai_addrlen == sizeof(struct sockaddr_in6));
			sa->in6 = *(struct sockaddr_in6 *)it->ai_addr;
			break;
		default:
			continue;
		}
		return true;
	}
	return false;
}

/* RFC 1035: Section 2.3.4 */
#define FQDN_MAX_LENGTH ((size_t)(255))

bool resolve_addr(sockaddr_max_t *sa, const char *s, const int flags)
{
	const size_t addrlen = strlen(s);
	assert(addrlen <= FQDN_MAX_LENGTH + 1 + 5);
	char buf[addrlen + 1];
	if (addrlen >= sizeof(buf)) {
		return false;
	}
	memcpy(buf, s, addrlen);
	buf[addrlen] = '\0';
	char *hoststr, *portstr;
	if (!splithostport(buf, &hoststr, &portstr)) {
		return false;
	}
	if (hoststr[0] == '\0') {
		hoststr = NULL;
	}
	struct addrinfo hints = {
		.ai_family = PF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = AI_ADDRCONFIG,
	};
	if (flags & RESOLVE_UDP) {
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	}
	if (flags & RESOLVE_PASSIVE) {
		hints.ai_flags |= AI_PASSIVE;
	}
	struct addrinfo *result = NULL;
	const int err = getaddrinfo(hoststr, portstr, &hints, &result);
	if (err != 0) {
		LOGE_F("getaddrinfo: %s", gai_strerror(err));
		return false;
	}
	const bool ok = find_addrinfo(sa, result);
	freeaddrinfo(result);
	return ok;
}
