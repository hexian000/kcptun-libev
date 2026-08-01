/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef STRINGS_FORMAT_H
#define STRINGS_FORMAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

#endif /* STRINGS_FORMAT_H */
