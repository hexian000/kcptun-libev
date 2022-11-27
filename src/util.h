#ifndef UTIL_H
#define UTIL_H

#include "utils/slog.h"

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
			LOGF_F(format, __VA_ARGS__);                           \
			CHECK_FAILED();                                        \
		}                                                              \
	} while (0)

#define CHECKMSG(cond, msg) CHECKMSGF(cond, "%s", msg)

#define CHECK(cond) CHECKMSGF(cond, "runtime check failed: \"%s\"", #cond)

#define CHECKOOM(ptr)                                                          \
	do {                                                                   \
		if (ptr == NULL) {                                             \
			LOGF("out of memory");                                 \
			CHECK_FAILED();                                        \
		}                                                              \
	} while (0)

#define LOGOOM() LOGE("out of memory")

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

#define TSTAMP_NIL (-1.0)

static inline void *must_malloc(size_t n)
{
	void *p = malloc(n);
	CHECKOOM(p);
	return p;
}

extern struct mcache msgcache;

#define UTIL_SAFE_FREE(x)                                                      \
	do {                                                                   \
		if ((x) != NULL) {                                             \
			free((void *)(x));                                     \
			(x) = NULL;                                            \
		}                                                              \
	} while (0)

char *util_strndup(const char *, size_t);
char *util_strdup(const char *);

void print_bin(const void *b, size_t n);

uint32_t rand32(void);

uint32_t tstamp2ms(ev_tstamp t);

void init(void);
void uninit(void);

void drop_privileges(const char *user);

void genpsk(const char *method);

#endif /* UTIL_H */
