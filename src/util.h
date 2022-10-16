#ifndef UTIL_H
#define UTIL_H

#include "slog.h"

#include <ev.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

#define UNUSED(x) (void)(x)

#ifndef NDEBUG
#define UTIL_ASSERT(cond)                                                      \
	do {                                                                   \
		if (!(cond)) {                                                 \
			LOGF("assertion failed: " #cond);                      \
			abort();                                               \
		}                                                              \
	} while (0)
#else
#define UTIL_ASSERT(cond) (void)(cond)
#endif /* NDEBUG */

#define countof(array) (sizeof(array) / sizeof((array)[0]))

static inline void *util_malloc(size_t n)
{
	return malloc(n);
}

static inline void util_free(void *p)
{
	free(p);
}

static inline void *must_malloc(size_t n)
{
	void *p = util_malloc(n);
	if (p == NULL) {
		LOGF("fatal: out of memory");
		exit(EXIT_FAILURE);
	}
	return p;
}

#define UTIL_SAFE_FREE(x)                                                      \
	do {                                                                   \
		if ((x) != NULL) {                                             \
			util_free((void *)(x));                                \
			(x) = NULL;                                            \
		}                                                              \
	} while (0)

char *util_strndup(const char *, size_t);
char *util_strdup(const char *);

void print_bin(const void *b, size_t n);

/* Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs" */
static inline uint32_t xorshift32(uint32_t x)
{
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return x;
}

uint32_t rand32(void);

static inline uint32_t tstamp2ms(const ev_tstamp t)
{
	return (uint32_t)fmod(t * 1e+3, UINT32_MAX + 1.0);
}

#endif /* UTIL_H */
