/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef STRINGS_STRING_H
#define STRINGS_STRING_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <uchar.h>

/**
 * @defgroup string
 * @brief libc-style string utilities for NUL-terminated UTF-8 strings.
 *
 * A char32_t/UTF-8 companion to <string.h> for plain `char *` strings, filling
 * the gap left by utf8.h (codec) and ctype.h (classification + case mapping).
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
 * @brief Decode the next unit and advance the cursor.
 * @param[out] cp Decoded codepoint, or U+FFFD for an invalid byte.
 * @param[in,out] s Cursor into a NUL-terminated UTF-8 string; advanced past the
 *                decoded unit (always by >= 1 byte while one remains).
 * @return Bytes consumed (1-4), or 0 at the terminator without advancing.
 */
int utf8next(char32_t *restrict cp, const char **restrict s);

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

/** @brief Compare two UTF-8 strings, case-insensitive (simple Unicode fold).
 *  @param[in] a First string.
 *  @param[in] b Second string.
 *  @return Sign of the codepoint difference at the first fold-differing unit. */
int u8strcasecmp(const char *restrict a, const char *restrict b);

/** @brief Case-insensitive compare of the first @p n codepoints.
 *  @param[in] a First string.
 *  @param[in] b Second string.
 *  @param n Maximum codepoints to compare.
 *  @return As u8strcasecmp, considering at most n codepoints. */
int u8strncasecmp(const char *restrict a, const char *restrict b, size_t n);

/** @brief Find the first occurrence of a codepoint.
 *  @param[in] s NUL-terminated UTF-8 string.
 *  @param cp Codepoint to find; 0 matches the terminator (as strchr).
 *  @return Pointer to the unit's first byte, or NULL if absent. */
char *u8strchr(char *restrict s, char32_t cp);

/** @brief Find the last occurrence of a codepoint.
 *  @see u8strchr */
char *u8strrchr(char *restrict s, char32_t cp);

/** @brief Case-insensitive substring search (simple Unicode fold).
 *  @param[in] haystack String to search.
 *  @param[in] needle Substring to find; empty matches at the start.
 *  @return Pointer into haystack at the match, or NULL if absent. */
char *u8strcasestr(char *restrict haystack, const char *restrict needle);

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
 */
int u8strlower(char *restrict buf, size_t maxlen, const char *restrict src);

/**
 * @brief Uppercase a UTF-8 string using the simple Unicode case mapping.
 * @see u8strlower
 */
int u8strupper(char *restrict buf, size_t maxlen, const char *restrict src);

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

/** @} */

#endif /* STRINGS_STRING_H */
