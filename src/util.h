/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTIL_H
#define UTIL_H

#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
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

/* owned by loadlibs(); freed and reset to NULL by unloadlibs() */
extern struct mcache *msgpool;

#define UTIL_SAFE_FREE(x)                                                      \
	do {                                                                   \
		if ((x) != NULL) {                                             \
			free((x));                                             \
			(x) = NULL;                                            \
		}                                                              \
	} while (0)

/* Report a best-effort socket option failure at the call site. The csnippets
 * option setters now return 0 or an errno and no longer log themselves (see
 * contrib/csnippets os/socket), so a caller that discards the result must log
 * it here. Stay quiet when the option is simply unsupported on this platform
 * (ENOPROTOOPT), which is expected rather than an error. */
#define LOG_SOCKOPT(what, expr)                                                \
	do {                                                                   \
		const int sockopt_err_ = (expr);                               \
		if (sockopt_err_ != 0 && sockopt_err_ != ENOPROTOOPT) {        \
			LOGW_F("%s: (%d) %s", (what), sockopt_err_,            \
			       strerror(sockopt_err_));                        \
		}                                                              \
	} while (0)

/* t is always derived from a trusted internal clock (ev_now()/ev_time()),
 * never external input, so ASSERT (not CHECK) is the correct guard here */
static inline uint32_t tstamp2ms(const ev_tstamp t)
{
	ASSERT(!signbit(t) && isnormal(t));
	return (uint32_t)fmod(t * 1e+3, 0x1p32);
}

/**
 * @brief Validate revents against accepted mask, log EV_ERROR, and early-return.
 *
 * If `revents` contains EV_ERROR, logs the unspecified watcher error and
 * returns immediately. Otherwise, asserts that only accepted bits are present
 * and returns when none of them are set.
 *
 * @param revents Event bits received from libev callbacks.
 * @param accept Accepted event mask (any libev event-type bitmask, e.g.
 * EV_READ, EV_WRITE, EV_TIMER, EV_SIGNAL, EV_IDLE).
 */
#define CHECK_REVENTS(revents, accept)                                         \
	do {                                                                   \
		if (((revents) & EV_ERROR) != 0) {                             \
			LOGE("libev watcher error");                           \
			return;                                                \
		}                                                              \
		ASSERT(((revents) & (accept)) == (revents));                   \
		if (((revents) & (accept)) == 0) {                             \
			return;                                                \
		}                                                              \
	} while (0)

bool check_rate_limit(ev_tstamp *restrict last, ev_tstamp now, double interval);

#define RATELIMIT(now, interval, expr)                                         \
	do {                                                                   \
		static ev_tstamp last = TSTAMP_NIL;                            \
		if (check_rate_limit(&last, (now), (interval))) {              \
			expr;                                                  \
		}                                                              \
	} while (0)

#define LOG_RATELIMITED_F(level, now, rate, format, ...)                       \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		RATELIMIT(now, rate, LOG_F(level, format, __VA_ARGS__));       \
	} while (0)

#define LOG_RATELIMITED(level, now, rate, message)                             \
	LOG_RATELIMITED_F(level, now, rate, "%s", message)

/**
 * @brief Declare a fixed 16-byte stack buffer `name` and fill it with `value`
 * formatted as IEC bytes (KiB/MiB/...). Expands format_iec_bytes() from
 * strings/format.h, which the including source must have available.
 */
#define FORMAT_IEC_BYTES(name, value)                                          \
	char name[16];                                                         \
	(void)format_iec_bytes(name, sizeof(name), (value))

/* Borrowed process-lifetime writer for stdout or stderr. */
struct io_stream *log_filewriter(FILE *f);

/** Process-level initializations. */
void init(void);

/** Load libraries and initialize global subsystems. */
void loadlibs(void);

/** Clean up and unload global subsystems and resources. */
void unloadlibs(void);

#if WITH_CRYPTO
void genpsk(const char *restrict method);
#endif

/* socket utilities */
bool socket_bind_netdev(int fd, const char *restrict netdev);

struct config;

/**
 * @brief Make fd non-blocking, closing it on failure.
 * @return True on success, false on failure (fd is already closed).
 */
bool socket_nonblock_or_close(int fd);

/** @brief Apply per-connection TCP tuning (nodelay, keepalive, buffers) from conf. */
void tcp_apply_conf(int fd, const struct config *restrict conf);

/* Per-connection failures leave the listener ready to accept another peer. */
static inline bool accept_retry(const int err)
{
	switch (err) {
	case EINTR:
	case ECONNABORTED:
	case ENETDOWN:
	case EPROTO:
	case ENOPROTOOPT:
#ifdef EHOSTDOWN
	case EHOSTDOWN:
#endif
#ifdef ENONET
	case ENONET:
#endif
	case EHOSTUNREACH:
	case EOPNOTSUPP:
	case ENETUNREACH:
		return true;
	default:
		return false;
	}
}

/**
 * @brief Back off after a hard accept() error: log it, stop the accept
 * watcher, and arm the listener timer so its callback retries accept later.
 * @param err The errno captured from the failed accept().
 */
void accept_backoff(
	struct ev_loop *loop, ev_io *restrict w_accept,
	ev_timer *restrict w_timer, int err);

bool resolve_addr(
	union sockaddr_max *restrict addr, const char *restrict addrstr,
	enum sa_resolve_type type);

bool resolve_bindaddr(
	union sockaddr_max *restrict addr, const char *restrict addrstr,
	enum sa_resolve_type type);

/**
 * @brief Per-thread CPU load since the previous call.
 * @return Fraction in [0,1] when available, or -1 when unavailable.
 */
double thread_load(void);

#endif /* UTIL_H */
