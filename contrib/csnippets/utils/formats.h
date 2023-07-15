/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_FORMATS_H
#define UTILS_FORMATS_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Format the value with human-readable SI metric prefix.
 * @return Same as snprintf.
 */
int format_si_metric(char *buf, size_t bufsize, double value);

/**
 * @brief Format byte count as a human-readable string in IEC unit.
 * @return Same as snprintf.
 */
int format_iec_bytes(char *buf, size_t bufsize, double value);

struct duration {
	signed int sign; /* +1 or -1, 0 is null, otherwise undefined */
	unsigned int days;
	unsigned int hours;
	unsigned int minutes;
	unsigned int seconds;
	unsigned int millis;
	unsigned int micros;
	unsigned int nanos;
};

/**
 * @brief Create a duration struct from seconds.
 * @param seconds Seconds. If struct duration cannot represent the value,
 * the behavior is undefined.
 */
struct duration make_duration(double seconds);

/**
 * @brief Create a duration struct from nanoseconds.
 * @param nanos Nanoseconds. struct duration can represent any int64_t.
 */
struct duration make_duration_nanos(int64_t nanos);

/**
 * @brief Format duration in seconds.
 * @details The duration value is truncated.
 * @return Same as snprintf.
 */
int format_duration_seconds(char *b, size_t size, struct duration d);

/**
 * @brief Format duration in milliseconds.
 * @details The duration value is truncated.
 * @return Same as snprintf.
 */
int format_duration_millis(char *b, size_t size, struct duration d);

/**
 * @brief Format duration in nanoseconds.
 * @details The duration value remains accurate.
 * @return Same as snprintf.
 */
int format_duration_nanos(char *b, size_t size, struct duration d);

/**
 * @brief Format duration into a human-readable format.
 * @details The duration value is rounded.
 * @return Same as snprintf.
 */
int format_duration(char *b, size_t size, struct duration d);

#endif /* UTILS_FORMATS_H */
