#include "util.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdlib.h>

int socket_set_nonblock(int fd)
{
	int flags;
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int socket_set_reuseport(int fd)
{
	int optval = 1;
#if defined(WIN32) || defined(__MINGW32__) || defined(__MINGW64__)
	return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval,
			  sizeof(optval));
#else
	return setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval,
			  sizeof(optval));
#endif
}

void format_sa(const struct sockaddr *sa, char *s, size_t buf_size)
{
	switch (sa->sa_family) {
	case AF_INET: {
		char buf[INET_ADDRSTRLEN];
		struct sockaddr_in *addr = (struct sockaddr_in *)sa;
		inet_ntop(AF_INET, &(addr->sin_addr), buf, sizeof(buf));
		snprintf(s, buf_size, "%s:%" PRIu16, buf,
			 ntohs(addr->sin_port));
	} break;
	case AF_INET6: {
		char buf[INET6_ADDRSTRLEN];
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *)sa;
		inet_ntop(AF_INET6, &(addr->sin6_addr), buf, sizeof(buf));
		snprintf(s, buf_size, "%s:%" PRIu16, buf,
			 ntohs(addr->sin6_port));
	} break;
	default:
		strncpy(s, "<Unknown AF>", buf_size);
	}
}

uint32_t xorshift32_state;

/* The state word must be initialized to non-zero */
static inline uint32_t xorshift32(uint32_t x)
{
	/* Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs" */
	x ^= x << 13U;
	x ^= x >> 17U;
	x ^= x << 5U;
	return x;
}

void srand_uint32(uint32_t seed)
{
	/* 0 is invalid for xorshift32 */
	UTIL_ASSERT(seed != 0);
	xorshift32_state = seed;
}

uint32_t rand_uint32()
{
	return xorshift32_state = xorshift32(xorshift32_state);
}
