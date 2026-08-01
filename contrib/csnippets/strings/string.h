/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef STRINGS_STRING_H
#define STRINGS_STRING_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <uchar.h>

/**
 * @defgroup string
 * @brief libc-style string utilities for NUL-terminated UTF-8 strings.
 *
 * A char32_t/UTF-8 companion to <string.h> for plain `char *` strings, filling
 * the gap left by utf8.h (codec) and uctype.h (classification + case mapping).
 * Every function treats an invalid byte as a one-byte unit, so no input stalls
 * or reads past the terminator. Copy/concatenate follow snprintf(3) semantics:
 * always NUL-terminated when the buffer is non-empty, truncation never splits a
 * codepoint, and the return is the length that would be needed.
 *
 * Most functions mirror a <string.h> counterpart under a `u8str` prefix
 * (u8strchr, u8strspn, ...); the prefix keeps every symbol distinct from libc,
 * so plain byte operations already correct for UTF-8 (strcmp, strstr, memchr)
 * are left to <string.h> and only the codepoint-aware additions live here. The
 * header also carries u8snprintf/u8vsnprintf and u8sscanf/u8vsscanf, locale-
 * independent snprintf(3)/vsnprintf(3) formatters and sscanf(3) scanners. Where
 * the shared root would mislead, the semantics
 * still differ: u8strlen/u8strnlen count codepoints rather than bytes,
 * u8strlcpy/u8strlcat take snprintf-style arguments and return an int rather
 * than following BSD strlcpy/strlcat, and u8strlower/u8strupper write to a
 * separate buffer with the same snprintf-style truncation because a simple
 * Unicode case fold can change the encoded length.
 *
 * The case-aware operations (u8strcasecmp, u8strncasecmp, u8strcasestr,
 * u8strlower, u8strupper), u8strwidth and u8strftime are backed by libicu and
 * are only declared in the WITH_ICU build; the codec, copy/search/trim, and the
 * locale-independent format/scan/number-parse helpers are always available.
 * @{
 */

/** @brief Count the codepoints of a NUL-terminated UTF-8 string.
 *  @param[in] s NUL-terminated UTF-8 string.
 *  @return Number of codepoints (invalid bytes count as one each). */
size_t u8strlen(const char *restrict s);

/** @brief Count codepoints that end within the first @p n bytes of @p s.
 *  @param[in] s NUL-terminated UTF-8 string.
 *  @param n Byte limit; a unit straddling the limit is not counted.
 *  @return Number of whole codepoints in s[0..n). */
size_t u8strnlen(const char *restrict s, size_t n);

/**
 * @brief Copy a UTF-8 string with snprintf(3) semantics.
 * @param[out] dst Output buffer; may be NULL only when dstsize == 0.
 * @param dstsize Size of dst in bytes, including the NUL terminator.
 * @param[in] src NUL-terminated UTF-8 string.
 * @return Bytes needed excluding the NUL; a value >= dstsize indicates
 *         truncation (never mid-codepoint). Negative if the length > INT_MAX.
 */
int u8strlcpy(char *restrict dst, size_t dstsize, const char *restrict src);

/**
 * @brief Append a UTF-8 string with snprintf(3) semantics.
 * @see u8strlcpy
 * @return Bytes needed for the concatenation, excluding the NUL.
 */
int u8strlcat(char *restrict dst, size_t dstsize, const char *restrict src);

/** @brief Find the first occurrence of a codepoint.
 *  @param[in] s NUL-terminated UTF-8 string.
 *  @param cp Codepoint to find; 0 matches the terminator (as strchr).
 *  @return Pointer to the unit's first byte, or NULL if absent. */
char *u8strchr(char *restrict s, char32_t cp);

/** @brief Find the last occurrence of a codepoint.
 *  @see u8strchr */
char *u8strrchr(char *restrict s, char32_t cp);

/** @brief Test whether @p s begins with @p prefix (byte-wise).
 *  @param[in] s NUL-terminated string.
 *  @param[in] prefix NUL-terminated prefix.
 *  @return true if s starts with prefix. */
bool u8strhasprefix(const char *restrict s, const char *restrict prefix);

/** @brief Test whether @p s ends with @p suffix (byte-wise).
 *  @see u8strhasprefix */
bool u8strhassuffix(const char *restrict s, const char *restrict suffix);

/** @brief Skip a leading @p prefix if present.
 *  @param[in] s NUL-terminated string.
 *  @param[in] prefix NUL-terminated prefix.
 *  @return Pointer past prefix if s starts with it, otherwise s. */
char *u8strtrimprefix(char *restrict s, const char *restrict prefix);

/** @brief Drop a trailing @p suffix in place if present.
 *  @param[in,out] s NUL-terminated string; truncated when it ends with suffix.
 *  @param[in] suffix NUL-terminated suffix.
 *  @return s. */
char *u8strtrimsuffix(char *restrict s, const char *restrict suffix);

/**
 * @brief Trim leading whitespace codepoints, returning the new start.
 * @param[in] s NUL-terminated UTF-8 string.
 * @return A pointer into s past any leading isspace() codepoints.
 */
char *u8strtrimleftspace(char *restrict s);

/**
 * @brief Trim trailing whitespace codepoints in place.
 * @param[in,out] s NUL-terminated UTF-8 string; truncated with a NUL after the
 *                last non-whitespace codepoint.
 * @return s.
 */
char *u8strtrimrightspace(char *restrict s);

/**
 * @brief Trim leading and trailing whitespace codepoints.
 * @param[in,out] s NUL-terminated UTF-8 string; see u8strtrimrightspace.
 * @return u8strtrimrightspace(u8strtrimleftspace(s)).
 */
char *u8strtrimspace(char *restrict s);

#if WITH_ICU
/** @brief Compare two UTF-8 strings, case-insensitive (simple case mapping).
 *  @param[in] a First string.
 *  @param[in] b Second string.
 *  @return Sign of the codepoint difference at the first case-differing unit.
 *  @note Requires the WITH_ICU build; folds by the linked libicu Unicode
 *        version. */
int u8strcasecmp(const char *restrict a, const char *restrict b);

/** @brief Case-insensitive compare of the first @p n codepoints.
 *  @param[in] a First string.
 *  @param[in] b Second string.
 *  @param n Maximum codepoints to compare.
 *  @return As u8strcasecmp, considering at most n codepoints.
 *  @note Requires the WITH_ICU build. */
int u8strncasecmp(const char *restrict a, const char *restrict b, size_t n);

/** @brief Case-insensitive substring search (simple case mapping).
 *  @param[in] haystack String to search.
 *  @param[in] needle Substring to find; empty matches at the start.
 *  @return Pointer into haystack at the match, or NULL if absent.
 *  @note Requires the WITH_ICU build. */
char *u8strcasestr(char *restrict haystack, const char *restrict needle);

/**
 * @brief Lowercase a UTF-8 string using the simple Unicode case mapping.
 *
 * Unlike ctype_ascii.h's in-place strlower, the mapping may change the encoded
 * length, so output goes to a separate buffer with snprintf(3) semantics:
 * always NUL-terminated when maxlen > 0, and truncation never splits a codepoint.
 *
 * @param[out] buf Output buffer; may be NULL only when maxlen == 0.
 * @param maxlen Size of buf in bytes, including the NUL terminator.
 * @param[in] src NUL-terminated UTF-8 string.
 * @return Bytes needed excluding the NUL; a value >= maxlen indicates truncation.
 * @note Requires the WITH_ICU build.
 */
int u8strlower(char *restrict buf, size_t maxlen, const char *restrict src);

/**
 * @brief Uppercase a UTF-8 string using the simple Unicode case mapping.
 * @see u8strlower
 */
int u8strupper(char *restrict buf, size_t maxlen, const char *restrict src);

/**
 * @brief Display width of a codepoint, a locale-free wcwidth(3) analogue.
 * @return 2 for wide or fullwidth East Asian codepoints; 0 for zero-width ones
 *         (combining marks, format controls, Hangul conjoining jamo, and NUL);
 *         -1 for other non-printable codepoints (controls, surrogates, and
 *         values above U+10FFFF); 1 otherwise.
 * @note Requires the WITH_ICU build.
 */
int ucwidth(char32_t c);

/**
 * @brief Total display width of a UTF-8 string, a wcswidth(3) analogue.
 *
 * Sums ucwidth() over the codepoints, decoding an invalid byte as U+FFFD.
 * @param[in] s NUL-terminated UTF-8 string.
 * @return The number of terminal columns, saturated at INT_MAX, or -1 if any
 *         codepoint is non-printable (as wcswidth reports).
 * @note Requires the WITH_ICU build.
 */
int u8strwidth(const char *restrict s);

/**
 * @brief Format a timestamp as a UTF-8 string using a libicu date/time pattern.
 *
 * snprintf(3) semantics: always NUL-terminated when maxlen > 0, truncation never
 * splits a codepoint, and the return is the byte length needed.
 *
 * @param[out] buf Output buffer; may be NULL only when maxlen == 0.
 * @param maxlen Size of buf in bytes, including the NUL terminator.
 * @param[in] pattern A libicu date/time pattern (UDAT), e.g.
 *            "yyyy-MM-dd HH:mm:ss zzz". Must not be NULL.
 * @param[in] locale A libicu locale id, e.g. "en_US"; NULL selects the root
 *            (locale-independent) locale.
 * @param[in] tz A libicu time zone id, e.g. "America/New_York"; NULL selects
 *            UTC.
 * @param t Seconds since the Unix epoch.
 * @return Bytes needed excluding the NUL; a value >= maxlen indicates
 *         truncation. Negative if the length exceeds INT_MAX or on failure.
 * @note Requires the WITH_ICU build.
 */
int u8strftime(
	char *restrict buf, size_t maxlen, const char *restrict pattern,
	const char *restrict locale, const char *restrict tz, time_t t);
#endif /* WITH_ICU */

/** @brief Length in bytes of the initial run of codepoints in @p set.
 *  @param[in] s NUL-terminated UTF-8 string.
 *  @param[in] set UTF-8 string spelling the accepted codepoints.
 *  @return Byte length of the accepted prefix. */
size_t u8strspn(const char *restrict s, const char *restrict set);

/** @brief Length in bytes of the initial run of codepoints not in @p set.
 *  @see u8strspn */
size_t u8strcspn(const char *restrict s, const char *restrict set);

/** @brief Find the first codepoint that is in @p set.
 *  @param[in] s NUL-terminated UTF-8 string.
 *  @param[in] set UTF-8 string spelling the searched codepoints.
 *  @return Pointer to the first matching unit, or NULL if none. */
char *u8strpbrk(char *restrict s, const char *restrict set);

/**
 * @brief Split off the next token delimited by any codepoint in @p set.
 * @param[in,out] s Address of the cursor; the delimiter is overwritten with a
 *                NUL and the cursor advanced past it, or set to NULL at the end.
 * @param[in] set UTF-8 string spelling the delimiter codepoints.
 * @return The token (possibly empty), or NULL when *s is already NULL.
 */
char *u8strsep(char **restrict s, const char *restrict set);

/**
 * @brief Format a string like vsnprintf(3), independent of libc and locale.
 *
 * Allocation-free, thread-safe and async-signal-safe: no libc function is
 * called on any path. Supports the conversions d i o u x X c s p
 * f F e E g G a A %%, the flags `- + 0 #` and space, field width, precision,
 * `*`, and the length modifiers hh h l ll j z t L.
 *
 * Divergences from vsnprintf(3):
 * - Truncation never splits a multibyte UTF-8 sequence: the buffer always
 *   holds a valid UTF-8 prefix of the full output.
 * - For %%s, precision and field width count codepoints instead of bytes.
 * - %%p formats as "0x" followed by lowercase hex digits.
 * - %%n, %%lc and %%ls are unsupported; an unsupported or malformed
 *   conversion is echoed literally and consumes no argument.
 * - %%zd reads ptrdiff_t; long double arguments are narrowed to double.
 *
 * @param[out] buf Output buffer, always NUL-terminated when maxlen > 0;
 *             may be NULL only when maxlen == 0 (measuring pass).
 * @param maxlen Size of buf in bytes, including the NUL terminator.
 * @param[in] format printf-style format string.
 * @param args Conversion arguments.
 * @return Bytes needed excluding the NUL terminator; a value >= maxlen
 *         indicates truncation. Negative if the length exceeds INT_MAX.
 */
int u8vsnprintf(
	char *restrict buf, size_t maxlen, const char *restrict format,
	va_list args);

/**
 * @brief Format a string like snprintf(3), independent of libc and locale.
 * @see u8vsnprintf
 */
int u8snprintf(
	char *restrict buf, size_t maxlen, const char *restrict format, ...);

/**
 * @brief Parse a string like vsscanf(3), independent of libc and locale.
 *
 * Allocation-free, thread-safe and async-signal-safe: no libc function is
 * called on any path, and the decimal float parse is correctly rounded. Supports
 * the conversions d i u o x X c s p f F e E g G a A [ %%, assignment suppression
 * `*`, a maximum field width, and the length modifiers hh h l ll j z t L. A
 * whitespace directive matches zero or more input whitespace codepoints, and a
 * literal directive matches the same codepoint.
 *
 * Divergences from vsscanf(3):
 * - Whitespace and codepoint matching are Unicode-aware (any isspace()
 *   codepoint); for %%s, %%c and %%[, the field width counts codepoints not bytes.
 * - %%p reads "0x" followed by hex digits, the inverse of u8snprintf's %%p.
 * - %%n, %%ls, %%lc and other unsupported conversions stop the scan.
 * - A float conversion consumes the whole "nan(n-char-sequence)" spelling,
 *   which C11 7.21.6.2 calls for (the item is the strtod subject sequence) but
 *   glibc's scanf leaves after "nan". An unterminated or width-truncated
 *   sequence backs off to plain "nan" in both.
 * - Two hex-float shapes differ from glibc in opposite directions: "0xg"
 *   assigns 0 here, its strtod subject sequence being "0", where glibc reports
 *   a matching failure; and a width cutting the prefix short, %%3lf on "0x.5",
 *   is a matching failure here, where glibc assigns 0.
 * - A float conversion parses at double precision, so %%Lf assigns a long double
 *   carrying only the double result; glibc parses at long double precision.
 * - An exponent marker with no digits behind it, whether absent outright or cut
 *   off by the field width, is left unconsumed: "1ex" and %%2le on "1e10" both
 *   read 1 and stop at the 'e', as C11 7.21.6.2 calls for (the item is the
 *   strtod subject sequence). glibc absorbs the marker and any sign.
 *
 * @param[in] str NUL-terminated UTF-8 input string.
 * @param[in] format scanf-style format string.
 * @param args Pointers receiving the converted values.
 * @return Number of input items assigned; -1 (EOF) if the input ends before the
 *         first conversion succeeds.
 */
int u8vsscanf(
	const char *restrict str, const char *restrict format, va_list args);

/**
 * @brief Parse a string like sscanf(3), independent of libc and locale.
 * @see u8vsscanf
 */
int u8sscanf(const char *restrict str, const char *restrict format, ...);

/**
 * @brief Convert the initial part of a string to a long, like strtol(3).
 *
 * Locale-independent: leading whitespace is any Unicode isspace() codepoint and
 * the numeric syntax is ASCII. Follows the C library contract: optional leading
 * whitespace, an optional sign, a base prefix when @p base is 0 (`0x` -> 16,
 * leading `0` -> 8) or 16 (an optional `0x`), then the digits 0-9 and A-Z/a-z
 * valued 0..35 that are below @p base. Conversion stops at the first byte that
 * is not a valid digit.
 *
 * @param[in] s NUL-terminated UTF-8 string.
 * @param[out] endptr If non-NULL, receives a pointer to the first unconverted
 *             byte; set to @p s when no conversion is performed.
 * @param base 0, or a radix in 2..36; any other value converts nothing.
 * @return The converted value, 0 when no conversion is performed, or the clamped
 *         limit LONG_MIN/LONG_MAX with errno set to ERANGE on overflow.
 */
long u8strtol(const char *restrict s, char **restrict endptr, int base);

/**
 * @brief Convert the initial part of a string to an unsigned long, like
 *        strtoul(3).
 * @see u8strtol
 * @return The converted value; ULONG_MAX with errno set to ERANGE on overflow.
 *         As in strtoul(3), a leading minus sign is applied to the unsigned
 *         result by negation modulo ULONG_MAX+1.
 */
unsigned long
u8strtoul(const char *restrict s, char **restrict endptr, int base);

/**
 * @brief Convert the initial part of a string to a double, like strtod(3).
 *
 * Locale-independent and correctly rounded, sharing the async-signal-safe number
 * parsing of u8sscanf. Leading whitespace is any Unicode isspace() codepoint;
 * the number is a decimal or C99 hexadecimal float, or one of `inf`, `infinity`
 * and `nan(...)` (case-insensitive), the ASCII syntax of strtod(3).
 *
 * @param[in] s NUL-terminated UTF-8 string.
 * @param[out] endptr If non-NULL, receives a pointer to the first unconverted
 *             byte; set to @p s when no conversion is performed.
 * @return The converted value, 0 when no conversion is performed, or +-HUGE_VAL
 *         with errno set to ERANGE on overflow. A decimal value that underflows
 *         to zero likewise sets errno to ERANGE.
 */
double u8strtod(const char *restrict s, char **restrict endptr);

/** @} */

#endif /* STRINGS_STRING_H */
