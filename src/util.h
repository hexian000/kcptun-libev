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
	void *p = malloc(n);
	if (p == NULL) {
		LOGF("fatal: out of memory");
		exit(EXIT_FAILURE);
	}
	return p;
}

#define UTIL_SAFE_FREE(x)                                                      \
	do {                                                                   \
		if ((x) != NULL) {                                             \
			util_free(x);                                          \
			(x) = NULL;                                            \
		}                                                              \
	} while (0)

void print_bin(const void *b, const size_t n);

uint32_t rand32();

static inline uint32_t tstamp2ms(const ev_tstamp t)
{
	return (uint32_t)fmod(t * 1e+3, UINT32_MAX + 1.0);
}

#endif /* UTIL_H */
