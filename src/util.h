/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
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

/**
 * @brief Mark a variable as intentionally unused and silence compiler warnings.
 * @param x Variable expression to be marked unused.
 */
#define UNUSED(x) ((void)(x))

/**
  * @brief Sentinel value representing an invalid or unavailable timestamp.
  */
#define TSTAMP_NIL (-1.0)

/**
 * @brief Close a file descriptor and log a warning on failure.
 * @param fd File descriptor to close.
 */
#define CLOSE_FD(fd)                                                           \
	do {                                                                   \
		if (close((fd)) != 0) {                                        \
			const int err = errno;                                 \
			LOGW_F("close [fd:%d]: (%d) %s", (fd), err,            \
			       strerror(err));                                 \
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

/**
 * @brief Validate revents against accepted mask, log EV_ERROR, and early-return.
 *
 * If `revents` contains EV_ERROR, logs the error; asserts that only
 * `(accept | EV_ERROR)` bits are present; returns from the current function
 * when none of the accepted bits are set.
 *
 * @param revents Event bits received from libev callbacks.
 * @param accept Accepted event mask (subset of EV_READ | EV_WRITE).
 */
#define CHECK_REVENTS(revents, accept)                                         \
	do {                                                                   \
		if (((revents) & EV_ERROR) != 0) {                             \
			const int err = errno;                                 \
			LOGE_F("io error: (%d) %s", err, strerror(err));       \
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

/** Process-level initializations. */
void init(int argc, char **argv);

/** Load libraries and initialize global subsystems. */
void loadlibs(void);

/** Clean up and unload global subsystems and resources. */
void unloadlibs(void);

#if WITH_CRYPTO
void genpsk(const char *method);
#endif

/** User and group identifiers. */
struct user_ident {
	uid_t uid;
	gid_t gid;
};

/** Parse a "[user][:[group]]" spec into numeric IDs using passwd/group DBs. */
bool parse_user(struct user_ident *ident, const char *s);

/**
 * @brief Drop real and effective privileges to the specified identifiers.
 * @param ident Target user and group IDs. Unspecified fields may be -1.
 */
void drop_privileges(const struct user_ident *ident);

/**
 * @brief Daemonize the current process using the double-fork pattern.
 *
 * Optionally avoid changing directory and/or closing stdio, then drop
 * privileges if `ident` is provided. On success, the parent exits after
 * receiving a readiness message from the daemon.
 *
 * @param ident Optional identifiers to drop to after daemonizing.
 * @param nochdir Do not chdir to "/" when true.
 * @param noclose Do not redirect stdio to /dev/null when true.
 */
void daemonize(const struct user_ident *ident, bool nochdir, bool noclose);

/**
 * @brief Per-thread CPU load since the previous call.
 * @return Fraction in [0,1] when available, or -1 when unavailable.
 */
double thread_load(void);

#endif /* UTIL_H */
