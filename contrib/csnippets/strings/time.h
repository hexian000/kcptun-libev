/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef STRINGS_TIME_H
#define STRINGS_TIME_H

#include <stddef.h>
#include <time.h>

/**
 * @brief Format a time_t as a fixed-length RFC 3339 stamp.
 * @param tzoff Timezone offset in seconds east of UTC, truncated to whole
 * minutes -- RFC 3339 §5.6 has no finer grain -- and required to be under 24 h
 * in magnitude. An offset that truncates to zero renders 'Z'; any other renders
 * '±HH:MM'.
 * @return Same as snprintf, except that -1 is returned (with `s` set to "" when
 * maxlen > 0) if the time cannot be represented as a conforming RFC 3339 stamp:
 * t plus the offset overflows time_t, does not fit a struct tm, its year falls
 * outside [1000, 9999], or |tzoff| is 24 h or more.
 * @details On success the output length depends only on whether the offset
 * renders as 'Z'.
 */
int format_rfc3339(char *restrict s, size_t maxlen, time_t t, int tzoff);

/**
 * @brief Format a timespec as a fixed-length RFC 3339 stamp with nanosecond
 * precision.
 * @param tzoff Timezone offset in seconds east of UTC, truncated to whole
 * minutes -- RFC 3339 §5.6 has no finer grain -- and required to be under 24 h
 * in magnitude. An offset that truncates to zero renders 'Z'; any other renders
 * '±HH:MM'.
 * @return Same as snprintf, except that -1 is returned (with `s` set to "" when
 * maxlen > 0) if the time cannot be represented as a conforming RFC 3339 stamp:
 * tv_sec plus the offset overflows time_t or does not fit a struct tm, its year
 * falls outside [1000, 9999], |tzoff| is 24 h or more, or tv_nsec is outside the
 * POSIX-required [0, 999999999].
 */
int format_rfc3339nano(
	char *restrict s, size_t maxlen, const struct timespec *restrict tp,
	int tzoff);

/**
 * @brief Local timezone offset in seconds east of UTC, in effect at instant t.
 * @details DST-correct for the given instant. Thread-safe where localtime_r is
 * available; otherwise it falls back to the thread-unsafe localtime.
 * @return The offset, or 0 when the instant cannot be broken down (which is
 * indistinguishable from a genuine UTC zone; there is no error channel here,
 * and the callers -- timestamp formatting -- have no better answer than UTC).
 */
int local_tzoff(time_t t);

/**
 * @brief Parse an RFC 3339 timestamp into a time_t.
 * @details The stamp's own offset ('Z' or '±HH[:MM]') is applied and any
 * fractional seconds are dropped; the result is independent of the local
 * timezone. As with mktime, (time_t)-1 is both the error value and the valid
 * instant one second before the epoch -- use parse_rfc3339nano to disambiguate.
 * @return The absolute time, or (time_t)-1 if tstamp is not a valid stamp.
 */
time_t parse_rfc3339(const char *restrict tstamp);

/**
 * @brief Parse an RFC 3339 timestamp into a timespec with fractional seconds.
 * @param tp Filled with the absolute time on success. The stamp's own offset is
 * applied; the result is independent of the local timezone. Fractional digits
 * beyond nanosecond precision are ignored.
 * @details The 'T' and 'Z' separators are accepted in either case, as RFC 3339
 * section 5.6 permits. A stamp of 64 bytes or more is rejected outright: the
 * grammar puts no bound on time-secfrac, but an unbounded parse over untrusted
 * input is not worth the digits past nanoseconds, which are discarded anyway.
 * @return 0 on success, -1 if tstamp is not a valid stamp.
 */
int parse_rfc3339nano(struct timespec *restrict tp, const char *restrict tstamp);

#endif /* STRINGS_TIME_H */
