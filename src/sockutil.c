#include "sockutil.h"
#include "hashtable.h"
#include "slog.h"
#include "util.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

int socket_setup(int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);
	return fcntl(fd, F_SETFL, flags | O_CLOEXEC | O_NONBLOCK);
}

void socket_set_reuseport(const int fd, const bool reuseport)
{
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int))) {
		const int err = errno;
		LOGW_F("SO_REUSEADDR: %s", strerror(err));
	}
#ifdef SO_REUSEPORT
	if (setsockopt(
		    fd, SOL_SOCKET, SO_REUSEPORT, &(int){ reuseport ? 1 : 0 },
		    sizeof(int))) {
		const int err = errno;
		LOGW_F("SO_REUSEPORT: %s", strerror(err));
	}
#else
	UNUSED(fd);
	if (reuseport) {
		LOGW("reuseport not supported on this platform");
	}
#endif
}

void socket_set_tcp(const int fd, const bool nodelay, const bool keepalive)
{
	if (setsockopt(
		    fd, IPPROTO_TCP, TCP_NODELAY, &(int){ nodelay ? 1 : 0 },
		    sizeof(int))) {
		const int err = errno;
		LOGW_F("TCP_NODELAY: %s", strerror(err));
	}
	if (setsockopt(
		    fd, SOL_SOCKET, SO_KEEPALIVE, &(int){ keepalive ? 1 : 0 },
		    sizeof(int))) {
		const int err = errno;
		LOGW_F("SO_KEEPALIVE: %s", strerror(err));
	}
}

void socket_set_buffer(int fd, size_t send, size_t recv)
{
	if (send > 0) {
		if (setsockopt(
			    fd, SOL_SOCKET, SO_SNDBUF, &(int){ (int)send },
			    sizeof(int))) {
			const int err = errno;
			LOGW_F("SO_SNDBUF: %s", strerror(err));
		}
	}
	if (recv > 0) {
		if (setsockopt(
			    fd, SOL_SOCKET, SO_RCVBUF, &(int){ (int)recv },
			    sizeof(int))) {
			const int err = errno;
			LOGW_F("SO_RCVBUF: %s", strerror(err));
		}
	}
}

void conv_make_key(hashkey_t *key, const struct sockaddr *sa, uint32_t conv)
{
	memset(key, 0, sizeof(hashkey_t));
	struct {
		sockaddr_max_t sa;
		uint32_t conv;
	} *ep = (void *)key;
	switch (sa->sa_family) {
	case AF_INET: {
		memcpy(&ep->sa, sa, sizeof(struct sockaddr_in));
	} break;
	case AF_INET6: {
		memcpy(&ep->sa, sa, sizeof(struct sockaddr_in6));
	} break;
	}
	ep->conv = conv;
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
	LOGF("only IPv4/IPv6 addresses are supported");
	abort();
}

bool sa_equals(const struct sockaddr *a, const struct sockaddr *b)
{
	const socklen_t na = getsocklen(a);
	const socklen_t nb = getsocklen(b);
	return na == nb && memcmp(a, b, na) == 0;
}

struct sockaddr *clonesockaddr(const struct sockaddr *src)
{
	const socklen_t len = getsocklen(src);
	struct sockaddr *dst = util_malloc(len);
	if (dst != NULL) {
		memcpy(dst, src, len);
	}
	return dst;
}

static int
format_sa_inet(const struct sockaddr_in *addr, char *s, const size_t buf_size)
{
	char buf[INET_ADDRSTRLEN];
	if (inet_ntop(AF_INET, &(addr->sin_addr), buf, sizeof(buf)) == NULL) {
		return -1;
	}
	const uint16_t port = ntohs(addr->sin_port);
	return snprintf(s, buf_size, "%s:%" PRIu16, buf, port);
}

static int
format_sa_inet6(const struct sockaddr_in6 *addr, char *s, const size_t buf_size)
{
	char buf[INET6_ADDRSTRLEN];
	if (inet_ntop(AF_INET6, &(addr->sin6_addr), buf, sizeof(buf)) == NULL) {
		return -1;
	}
	const uint16_t port = ntohs(addr->sin6_port);
	return snprintf(s, buf_size, "[%s]:%" PRIu16, buf, port);
}

void format_sa(const struct sockaddr *sa, char *s, const size_t buf_size)
{
	int ret = -1;
	switch (sa->sa_family) {
	case AF_INET:
		ret = format_sa_inet((struct sockaddr_in *)sa, s, buf_size);
		break;
	case AF_INET6:
		ret = format_sa_inet6((struct sockaddr_in6 *)sa, s, buf_size);
		break;
	}
	if (ret < 0) {
		strncpy(s, "???", buf_size);
	}
}

struct sockaddr *
resolve(const char *hostname, const char *service, const int flags)
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
			sa = clonesockaddr(it->ai_addr);
			break;
		}
	}
	freeaddrinfo(result);
	return sa;
}
