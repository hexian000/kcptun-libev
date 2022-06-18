#include "sockutil.h"
#include "hashtable.h"
#include "slog.h"
#include "util.h"

#include <stddef.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

int socket_set_nonblock(int fd)
{
	int flags;
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int socket_set_nodelay(int fd)
{
	return setsockopt(
		fd, IPPROTO_TCP, TCP_NODELAY, &(int){ 1 }, sizeof(int));
}

int socket_set_reuseport(int fd)
{
#ifdef SO_REUSEPORT
	return setsockopt(
		fd, SOL_SOCKET, SO_REUSEPORT, &(int){ 1 }, sizeof(int));
#else
	LOGE("reuseport not supported on this platform");
#endif
	return -1;
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
