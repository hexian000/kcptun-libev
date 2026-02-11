/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_FORMATS_H
#define UTILS_FORMATS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/**
 * @brief Format the value with human-readable SI metric prefix.
 * @return Same as snprintf.
 */
int format_si_prefix(char *s, size_t maxlen, double value);

/**
 * @brief Format byte count as a human-readable string in IEC unit.
 * @return Same as snprintf.
 */
int format_iec_bytes(char *s, size_t maxlen, double value);

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
 * @param nanos Nanoseconds. struct duration can represent any int_least64_t.
 */
struct duration make_duration_nanos(int_least64_t nanos);

/**
 * @brief Format duration in seconds.
 * @details The duration value is truncated.
 * @return Same as snprintf.
 */
int format_duration_seconds(char *s, size_t maxlen, struct duration d);

/**
 * @brief Format duration in milliseconds.
 * @details The duration value is truncated.
 * @return Same as snprintf.
 */
int format_duration_millis(char *s, size_t maxlen, struct duration d);

/**
 * @brief Format duration in nanoseconds.
 * @details The duration value remains accurate.
 * @return Same as snprintf.
 */
int format_duration_nanos(char *s, size_t maxlen, struct duration d);

/**
 * @brief Format duration into a human-readable format.
 * @details The duration value is rounded.
 * @return Same as snprintf.
 */
int format_duration(char *s, size_t maxlen, struct duration d);

/**
 * @brief Format timespec into RFC3339 format.
 * @param utc If true, the time is formatted in UTC and the timezone offset is replaced with 'Z'.
 * Otherwise, the time is formatted in local time and the timezone offset is included.
 * @return Same as snprintf.
 * @details The output string always has a fixed length regardless of the time value.
 */
int format_rfc3339(char *s, size_t maxlen, time_t t, bool utc);

/**
 * @brief Format timespec into RFC3339 format with nanosecond precision.
 * @param utc If true, the time is formatted in UTC and the timezone offset is replaced with 'Z'.
 * Otherwise, the time is formatted in local time and the timezone offset is included.
 * @return Same as snprintf.
 * @details The output string always has a fixed length regardless of the time value.
 */
int format_rfc3339nano(
	char *s, size_t maxlen, const struct timespec *tp, bool utc);

#endif /* UTILS_FORMATS_H */
