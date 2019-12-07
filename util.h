#ifndef UTIL_H
#define UTIL_H

#include "endian.h"
#include "log.h"

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <time.h>

struct sockaddr;

#ifndef NDEBUG

static inline void print_bin(const char *b, const size_t n)
{
	printf("[%zu] ", n);
	for (size_t i = 0; i < n; i++) {
		printf("%02" PRIX8, (uint8_t)b[i]);
	}
	printf("\n");
}

#endif

#define UNUSED(x) (void)(x)

#define UTIL_ASSERT(x)                                                         \
	do {                                                                   \
		if (!(x))                                                      \
			LOG_WTF("assertion failed: " #x);                      \
	} while (0)

static inline void *util_malloc(size_t n)
{
	void *p = malloc(n);
	if (p == NULL) {
		LOGF_E("failed allocating %zu bytes of memory", n);
	}
	return p;
}

static inline void util_free(void *p)
{
	free(p);
}

#define UTIL_SAFE_FREE(x)                                                      \
	do {                                                                   \
		if ((x) != NULL) {                                             \
			util_free(x);                                          \
			(x) = NULL;                                            \
		}                                                              \
	} while (0)

int socket_set_nonblock(int fd);
int socket_set_reuseport(int fd);

void format_sa(const struct sockaddr *sa, char *s, size_t buf_size);

void srand_uint32(uint32_t /*seed*/);
uint32_t rand_uint32();

static inline uint64_t now()
{
	const uint64_t nanos = 1000000000;
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * nanos + (uint64_t)t.tv_nsec;
}

#endif /* UTIL_H */
