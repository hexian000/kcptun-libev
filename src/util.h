/* kcptun-libev (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTIL_H
#define UTIL_H

#include "utils/arraysize.h"
#include "utils/slog.h"
#include "utils/buffer.h"
#include "utils/debug.h"

#include <ev.h>
#include <unistd.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define UNUSED(x) (void)(x)

#define CONSTSTREQUAL(s, len, literal)                                         \
	((len) == (ARRAY_SIZE(literal) - 1) &&                                 \
	 strncmp((s), literal "",                                              \
		 (ARRAY_SIZE(literal) - 1) * sizeof((literal)[0])) == 0)

#define TSTAMP_NIL (-1.0)

#define CLOSE_FD(fd)                                                           \
	do {                                                                   \
		if (close(fd) != 0) {                                          \
			const int close_err = errno;                           \
			LOGW_F("close: %s", strerror(close_err));              \
		}                                                              \
	} while (0)

extern struct mcache *msgpool;

#define UTIL_SAFE_FREE(x)                                                      \
	do {                                                                   \
		if ((x) != NULL) {                                             \
			free((void *)(x));                                     \
			(x) = NULL;                                            \
		}                                                              \
	} while (0)

#define TSTAMP2MS(t) ((uint32_t)fmod((t)*1e+3, UINT32_MAX + 1.0))

bool check_rate_limit(ev_tstamp *last, ev_tstamp now, double interval);

#define RATELIMIT(now, interval, expr)                                         \
	do {                                                                   \
		static ev_tstamp last = TSTAMP_NIL;                            \
		if (check_rate_limit(&last, (now), (interval))) {              \
			expr;                                                  \
		}                                                              \
	} while (0)

void init(int argc, char **argv);
void loadlibs(void);

#if WITH_CRYPTO
void genpsk(const char *method);
#endif

void drop_privileges(const char *user);
void daemonize(const char *user, bool nochdir, bool noclose);

#endif /* UTIL_H */
