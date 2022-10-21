#ifndef UTIL_H
#define UTIL_H

#include "slog.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

#define UNUSED(x) (void)(x)

#define check(cond)                                                            \
	do {                                                                   \
		if (!(cond)) {                                                 \
			LOGF("assertion failed: " #cond);                      \
			abort();                                               \
		}                                                              \
	} while (0)

#define countof(array) (sizeof(array) / sizeof((array)[0]))

static inline void *util_malloc(size_t n)
{
	return malloc(n);
}

static inline void util_free(void *p)
{
	free(p);
}

static inline void *util_realloc(void *p, size_t n)
{
	return realloc(p, n);
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

uint32_t rand32(void);

uint32_t tstamp2ms(const ev_tstamp t);

void init(void);

void genpsk(const char *method);

#endif /* UTIL_H */
