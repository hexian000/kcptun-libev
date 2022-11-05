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

#ifdef NDEBUG
#define CHECK_FAILED() exit(EXIT_FAILURE)
#else
#define CHECK_FAILED() abort()
#endif

#define CHECKMSGF(cond, format, ...)                                           \
	do {                                                                   \
		if (!(cond)) {                                                 \
			LOGF_F("runtime check failed: " format, __VA_ARGS__);  \
			CHECK_FAILED();                                        \
		}                                                              \
	} while (0)

#define CHECKMSG(cond, msg) CHECKMSGF(cond, "%s", msg)

#define CHECK(cond) CHECKMSGF(cond, "\"%s\"", #cond)

#define CHECKERR(cond, msg)                                                    \
	do {                                                                   \
		if (!(cond)) {                                                 \
			const int err = errno;                                 \
			CHECKMSGF("%s, [%d] %s", msg, err, strerror(err));     \
			CHECK_FAILED();                                        \
		}                                                              \
	} while (0)

#define LOGOOM() LOGE("out of memory")

#define countof(array) (sizeof(array) / sizeof((array)[0]))

#define TSTAMP_NIL (-1.0)

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
		LOGOOM();
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
