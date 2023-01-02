/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

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

#define CHECKMSGF(cond, format, ...)                                           \
	do {                                                                   \
		if (!(cond)) {                                                 \
			LOGF_F(format, __VA_ARGS__);                           \
			exit(EXIT_FAILURE);                                    \
		}                                                              \
	} while (0)

#define CHECKMSG(cond, msg) CHECKMSGF(cond, "%s", msg)

#define CHECK(cond) CHECKMSGF(cond, "runtime check failed: \"%s\"", #cond)

#define LOGOOM() LOGE("out of memory")

#define TSTAMP_NIL (-1.0)

static inline void *must_malloc(size_t n)
{
	void *p = malloc(n);
	CHECKMSG(p != NULL, "out of memory");
	return p;
}

extern struct mcache *msgpool;

#define UTIL_SAFE_FREE(x)                                                      \
	do {                                                                   \
		if ((x) != NULL) {                                             \
			free((void *)(x));                                     \
			(x) = NULL;                                            \
		}                                                              \
	} while (0)

void print_bin(const void *b, size_t n);

uint32_t tstamp2ms(ev_tstamp t);

void init(void);
void uninit(void);

void drop_privileges(const char *user);

void genpsk(const char *method);

#endif /* UTIL_H */
