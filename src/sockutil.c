#include "sockutil.h"
#include "hashtable.h"
#include "slog.h"
#include "util.h"

#include <asm-generic/socket.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

int socket_set_nonblock(int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void socket_set_reuseport(const int fd, const int reuseport)
{
#ifdef SO_REUSEPORT
	if (setsockopt(
		    fd, SOL_SOCKET, SO_REUSEPORT, &reuseport,
		    sizeof(reuseport))) {
		LOG_PERROR("SO_REUSEPORT");
	}
#else
	LOGE("reuseport not supported on this platform");
#endif
}

void socket_set_tcp(
	const int fd, const int nodelay, const int linger, const int keepalive)
{
	if (setsockopt(
		    fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay))) {
		LOG_PERROR("TCP_NODELAY");
	}
	if (setsockopt(
		    fd, SOL_SOCKET, SO_LINGER,
		    &(struct linger){
			    .l_onoff = 0,
			    .l_linger = linger,
		    },
		    sizeof(struct linger))) {
		LOG_PERROR("SO_LINGER");
	}
	if (setsockopt(
		    fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
		    sizeof(keepalive))) {
		LOG_PERROR("SO_KEEPALIVE");
	}
}

void socket_set_buffer(int fd, size_t send, size_t recv)
{
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &(int){ send }, sizeof(int))) {
		LOG_PERROR("SO_SNDBUF");
	}
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &(int){ recv }, sizeof(int))) {
		LOG_PERROR("SO_RCVBUF");
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
		LOGF("only IPv4/IPv6 addresses are supported");
		abort();
	}
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

void format_sa(const struct sockaddr *sa, char *s, size_t buf_size)
{
	switch (sa->sa_family) {
	case AF_INET: {
		char buf[INET_ADDRSTRLEN];
		struct sockaddr_in *addr = (struct sockaddr_in *)sa;
		inet_ntop(AF_INET, &(addr->sin_addr), buf, sizeof(buf));
		snprintf(
			s, buf_size, "%s:%" PRIu16, buf, ntohs(addr->sin_port));
	} break;
	case AF_INET6: {
		char buf[INET6_ADDRSTRLEN];
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *)sa;
		inet_ntop(AF_INET6, &(addr->sin6_addr), buf, sizeof(buf));
		snprintf(
			s, buf_size, "[%s]:%" PRIu16, buf,
			ntohs(addr->sin6_port));
	} break;
	default:
		strncpy(s, "???", buf_size);
	}
}

struct sockaddr *
resolve(const char *hostname, const char *service, const int socktype)
{
	struct addrinfo hints = {
		.ai_family = PF_UNSPEC,
		.ai_socktype = socktype,
		.ai_flags = 0,
	};
	struct addrinfo *result = NULL;
	if (getaddrinfo(hostname, service, &hints, &result) != 0) {
		LOG_PERROR("resolve");
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
