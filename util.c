#include "util.h"

#include <fcntl.h>
#include <sys/socket.h>

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
#if defined(__MINGW32__) || defined(__MINGW64__)
	UNUSED(fd);
	LOG_W("reuse port not supported on mingw");
	return -1;
#else
	int optval = 1;
	return setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval,
			  sizeof(optval));
#endif
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
