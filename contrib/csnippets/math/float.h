/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef MATH_FLOAT_H
#define MATH_FLOAT_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @defgroup float
 * @brief IEEE 754 binary64 utilities without libc dependencies.
 * @details All functions are pure computations on the caller's arguments:
 * allocation-free, locale-independent, thread-safe and async-signal-safe.
 * @{
 */

enum float_class {
	FLOAT_ZERO,
	FLOAT_SUBNORMAL,
	FLOAT_NORMAL,
	FLOAT_INF,
	FLOAT_NAN,
};

/**
 * @brief Reinterpret a double as its IEEE 754 binary64 bit pattern.
 * @param x Any double.
 * @return The 64-bit object representation.
 */
uint64_t float_tobits(double x);

/**
 * @brief Reinterpret an IEEE 754 binary64 bit pattern as a double.
 * @param bits The 64-bit object representation.
 * @return The represented double.
 */
double float_frombits(uint64_t bits);

/**
 * @brief Classify a double from its bit pattern.
 * @param x Any double.
 * @return The floating-point class of x.
 */
enum float_class float_classify(double x);

/**
 * @brief Test the sign bit, including negative zero and NaN.
 * @param x Any double.
 * @return true iff the sign bit is set.
 */
bool float_signbit(double x);

/**
 * @brief Decompose a finite double exactly: |x| == frac * 2^e2.
 * @param x A finite double.
 * @param[out] e2 Base-2 exponent.
 * @return Integer significand in [0, 2^53); 0 iff x is a zero.
 */
uint64_t float_decompose(double x, int *e2);

/** Maximum significant decimal digits of an exact binary64 expansion. */
#define FLOAT_DECIMAL_DIGITS 767

/**
 * @brief Convert |x| to decimal digits, correctly rounded (round-half-even).
 *
 * Writes up to ndigits significant digits ('0'-'9', no sign or radix point,
 * no trailing zeros) into digits[] and sets *dec_exp = K such that
 * |x| rounded at 10^(K-ndigits) equals 0.d1..dn * 10^K. A rounding carry may
 * increase K. ndigits <= 0 is allowed: the value rounds to zero (returns 0)
 * unless ndigits == 0 and |x| rounds up to 10^K (returns the single digit 1).
 * Digits beyond the returned count are zeros; callers zero-extend.
 *
 * @param x A finite nonzero double; the sign is ignored.
 * @param ndigits Requested significant digits.
 * @param[out] digits Output buffer with room for FLOAT_DECIMAL_DIGITS bytes.
 * @param[out] dec_exp Decimal exponent K.
 * @return Number of digits written, in [0, FLOAT_DECIMAL_DIGITS].
 */
int float_todecimal(double x, int ndigits, char *digits, int *dec_exp);

/** @} */

#endif /* MATH_FLOAT_H */
