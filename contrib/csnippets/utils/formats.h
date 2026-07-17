/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_FORMATS_H
#define UTILS_FORMATS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/*
 * Note: the numeric formatters below go through the C stdio conversions
 * (%g/%f), so the decimal separator in their output follows the active
 * LC_NUMERIC locale (e.g. a comma under some locales). Set LC_NUMERIC to "C"
 * around the call if locale-independent '.' output is required.
 */

/**
 * @brief Format the value with human-readable SI metric prefix.
 * @return Same as snprintf.
 */
int format_si_prefix(char *restrict s, size_t maxlen, double value);

/**
 * @brief Format byte count as a human-readable string in IEC unit.
 * @return Same as snprintf.
 */
int format_iec_bytes(char *restrict s, size_t maxlen, double value);

struct duration {
	signed int sign; /* +1 or -1, 0 is null, otherwise undefined */
	unsigned int day;
	unsigned int hour;
	unsigned int minute;
	unsigned int second;
	unsigned int milli;
	unsigned int micro;
	unsigned int nano;
};

/**
 * @brief Create a duration struct from seconds.
 * @param seconds Seconds. If struct duration cannot represent the value,
 * the behavior is undefined.
 */
struct duration make_duration(double seconds);

/**
 * @brief Create a duration struct from nanoseconds.
 * @param nanos Nanoseconds. If struct duration cannot represent the value,
 * the behavior is undefined.
 */
struct duration make_duration_nanos(int_fast64_t nanos);

/**
 * @brief Format duration in seconds.
 * @details The duration value is truncated.
 * @return Same as snprintf.
 */
int format_duration_seconds(char *restrict s, size_t maxlen, struct duration d);

/**
 * @brief Format duration in milliseconds.
 * @details The duration value is truncated.
 * @return Same as snprintf.
 */
int format_duration_millis(char *restrict s, size_t maxlen, struct duration d);

/**
 * @brief Format duration in nanoseconds.
 * @details The duration value remains accurate.
 * @return Same as snprintf.
 */
int format_duration_nanos(char *restrict s, size_t maxlen, struct duration d);

/**
 * @brief Format duration into a human-readable format.
 * @details The duration value is rounded.
 * @return Same as snprintf.
 */
int format_duration(char *restrict s, size_t maxlen, struct duration d);

/**
 * @brief Format timespec into RFC3339 format.
 * @param utc If true, the time is formatted in UTC and the timezone offset is replaced with 'Z'.
 * Otherwise, the time is formatted in local time and the timezone offset is included.
 * @return Same as snprintf, except that -1 is returned (with `s` set to "" when
 * maxlen > 0) if the time cannot be represented as a conforming RFC 3339 stamp:
 * the time_t does not fit a struct tm, or its year falls outside [1000, 9999].
 * @details On success the output string has a fixed length regardless of the
 * time value.
 */
int format_rfc3339(char *restrict s, size_t maxlen, time_t t, bool utc);

/**
 * @brief Format timespec into RFC3339 format with nanosecond precision.
 * @param utc If true, the time is formatted in UTC and the timezone offset is replaced with 'Z'.
 * Otherwise, the time is formatted in local time and the timezone offset is included.
 * @return Same as snprintf, except that -1 is returned (with `s` set to "" when
 * maxlen > 0) if the time cannot be represented as a conforming RFC 3339 stamp:
 * the time_t does not fit a struct tm, its year falls outside [1000, 9999], or
 * tv_nsec is outside the POSIX-required [0, 999999999].
 * @details On success the output string has a fixed length regardless of the
 * time value.
 */
int format_rfc3339nano(
	char *restrict s, size_t maxlen, const struct timespec *restrict tp,
	bool utc);

#endif /* UTILS_FORMATS_H */
