/* kcptun-libev (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTIL_H
#define UTIL_H

#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define UNUSED(x) ((void)(x))

#define TSTAMP_NIL (-1.0)

#define CLOSE_FD(fd)                                                           \
	do {                                                                   \
		if (close(fd) != 0) {                                          \
			LOGW_F("close: %s", strerror(errno));                  \
		}                                                              \
	} while (0)

extern struct mcache *msgpool;

#define UTIL_SAFE_FREE(x)                                                      \
	do {                                                                   \
		if ((x) != NULL) {                                             \
			free((x));                                             \
			(x) = NULL;                                            \
		}                                                              \
	} while (0)

static inline uint32_t tstamp2ms(const ev_tstamp t)
{
	ASSERT(!signbit(t) && isnormal(t));
	return (uint32_t)fmod(t * 1e+3, 0x1p32);
}

#define CHECK_REVENTS(revents, accept)                                         \
	do {                                                                   \
		if (((revents)&EV_ERROR) != 0) {                               \
			const int err = errno;                                 \
			LOGE_F("error event: [errno=%d] %s", err,              \
			       strerror(err));                                 \
		}                                                              \
		ASSERT(((revents) & ((accept) | EV_ERROR)) == (revents));      \
		if (((revents) & (accept)) == 0) {                             \
			return;                                                \
		}                                                              \
	} while (0)

bool check_rate_limit(ev_tstamp *last, ev_tstamp now, double interval);

#define RATELIMIT(now, interval, expr)                                         \
	do {                                                                   \
		static ev_tstamp last = TSTAMP_NIL;                            \
		if (check_rate_limit(&last, (now), (interval))) {              \
			expr;                                                  \
		}                                                              \
	} while (0)

#define LOG_RATELIMITED_F(level, now, rate, format, ...)                       \
	RATELIMIT(now, rate, LOG_F(level, format, __VA_ARGS__))

#define LOG_RATELIMITED(level, now, rate, message)                             \
	LOG_RATELIMITED_F(level, now, rate, "%s", message)

void init(int argc, char **argv);
void loadlibs(void);
void unloadlibs(void);

#if WITH_CRYPTO
void genpsk(const char *method);
#endif

struct user_ident {
	uid_t uid;
	gid_t gid;
};
bool parse_user(struct user_ident *ident, const char *s);
void drop_privileges(const struct user_ident *ident);
void daemonize(const struct user_ident *ident, bool nochdir, bool noclose);

double thread_load(void);

#endif /* UTIL_H */
