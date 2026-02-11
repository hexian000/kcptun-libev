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

/* RFC 1035: Section 2.3.4 */
#define FQDN_MAX_LENGTH ((size_t)(255))

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

/* socket utilities */
void socket_bind_netdev(int fd, const char *netdev);

#define RESOLVE_ADDR(addr, addrstr, type, error)                               \
	do {                                                                   \
		const size_t addrlen = strlen((addrstr));                      \
		ASSERT(addrlen < FQDN_MAX_LENGTH + sizeof(":65535"));          \
		char buf[addrlen + 1];                                         \
		memcpy(buf, (addrstr), addrlen);                               \
		buf[addrlen] = '\0';                                           \
		char *hoststr, *portstr;                                       \
		if (!splithostport(buf, &hoststr, &portstr)) {                 \
			error;                                                 \
		}                                                              \
		if (!sa_resolve_##type((addr), hoststr, portstr, PF_UNSPEC)) { \
			error;                                                 \
		}                                                              \
	} while (0)

#define RESOLVE_BINDADDR(addr, addrstr, type, error)                           \
	do {                                                                   \
		const size_t addrlen = strlen((addrstr));                      \
		ASSERT(addrlen < FQDN_MAX_LENGTH + sizeof(":65535"));          \
		char buf[addrlen + 1];                                         \
		memcpy(buf, (addrstr), addrlen);                               \
		buf[addrlen] = '\0';                                           \
		char *hoststr, *portstr;                                       \
		if (!splithostport(buf, &hoststr, &portstr)) {                 \
			error;                                                 \
		}                                                              \
		if (!sa_resolve_##type((addr), hoststr, portstr)) {            \
			error;                                                 \
		}                                                              \
	} while (0)

/**
 * @brief Per-thread CPU load since the previous call.
 * @return Fraction in [0,1] when available, or -1 when unavailable.
 */
double thread_load(void);

#endif /* UTIL_H */
