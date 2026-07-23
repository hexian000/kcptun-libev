/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef STRINGS_CTYPE_H
#define STRINGS_CTYPE_H

#if defined(isdigit) || defined(isalpha) || defined(isalnum) ||                \
	defined(isspace) || defined(iscntrl) || defined(islower) ||            \
	defined(isupper) || defined(isprint) || defined(isgraph) ||            \
	defined(ispunct) || defined(isxdigit) || defined(isblank) ||           \
	defined(tolower) || defined(toupper)
#error "ctype.h is intended to be a standalone header and should not be included with ctype.h, ctype_ascii.h or similar headers that define character classification macros."
#endif

#include "ctype_data.gen.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <uchar.h>

/**
 * @defgroup ctype
 * @brief Locale-free Unicode character classification for char32_t and UTF-8.
 *
 * A char32_t/UTF-8 counterpart to ctype_ascii.h: the same operations, extended
 * from ASCII to the whole codepoint range using a pinned Unicode Character
 * Database (see scripts/gen_ctype.py, contrib/ucd/). Classification is
 * table-driven, locale-independent and async-signal-safe. The classifiers agree
 * with ctype_ascii.h on U+0000..U+007F.
 *
 * This header claims the standard <ctype.h> names, so it cannot be combined with
 * <ctype.h> or ctype_ascii.h -- include exactly one. The names are macros over
 * inline functions: the argument is evaluated once, and no external symbol
 * shadows the C library's own isdigit/tolower/...
 * @{
 */

/** @brief Property flags of a codepoint, or 0 outside U+0000..U+10FFFF. */
static inline uint_fast8_t uctype_flags(const char32_t c)
{
	if (c > 0x10FFFFu) {
		return 0;
	}
	const size_t block = uctype_stage1[c >> UCTYPE_BLOCK_BITS];
	return uctype_stage2
		[(block << UCTYPE_BLOCK_BITS) |
		 (c & ((1u << UCTYPE_BLOCK_BITS) - 1u))];
}

static inline bool uctype_isascii(const char32_t c)
{
	return c <= 0x7Fu;
}

static inline bool uctype_isalpha(const char32_t c)
{
	return (uctype_flags(c) & UCTYPE_ALPHA) != 0;
}

static inline bool uctype_isdigit(const char32_t c)
{
	return (uctype_flags(c) & UCTYPE_DIGIT) != 0;
}

static inline bool uctype_isalnum(const char32_t c)
{
	return (uctype_flags(c) & (UCTYPE_ALPHA | UCTYPE_DIGIT)) != 0;
}

static inline bool uctype_isspace(const char32_t c)
{
	return (uctype_flags(c) & UCTYPE_SPACE) != 0;
}

static inline bool uctype_isblank(const char32_t c)
{
	return (uctype_flags(c) & UCTYPE_BLANK) != 0;
}

static inline bool uctype_iscntrl(const char32_t c)
{
	return (uctype_flags(c) & UCTYPE_CNTRL) != 0;
}

static inline bool uctype_islower(const char32_t c)
{
	return (uctype_flags(c) & UCTYPE_LOWER) != 0;
}

static inline bool uctype_isupper(const char32_t c)
{
	return (uctype_flags(c) & UCTYPE_UPPER) != 0;
}

static inline bool uctype_isprint(const char32_t c)
{
	return (uctype_flags(c) & UCTYPE_PRINT) != 0;
}

static inline bool uctype_isgraph(const char32_t c)
{
	const uint_fast8_t f = uctype_flags(c);
	return (f & UCTYPE_PRINT) != 0 && (f & UCTYPE_SPACE) == 0;
}

static inline bool uctype_ispunct(const char32_t c)
{
	const uint_fast8_t f = uctype_flags(c);
	return (f & UCTYPE_PRINT) != 0 && (f & UCTYPE_SPACE) == 0 &&
	       (f & (UCTYPE_ALPHA | UCTYPE_DIGIT)) == 0;
}

/** @brief Hexadecimal digits stay ASCII (0-9 A-F a-f), matching ctype_ascii.h. */
static inline bool uctype_isxdigit(const char32_t c)
{
	return (U'0' <= c && c <= U'9') || (U'A' <= c && c <= U'F') ||
	       (U'a' <= c && c <= U'f');
}

static inline const struct uctype_case_entry *uctype_case_find(const char32_t c)
{
	size_t lo = 0;
	size_t hi = sizeof(uctype_case_table) / sizeof(uctype_case_table[0]);
	while (lo < hi) {
		const size_t mid = lo + (hi - lo) / 2;
		const char32_t cp = uctype_case_table[mid].cp;
		if (cp < c) {
			lo = mid + 1;
		} else if (cp > c) {
			hi = mid;
		} else {
			return &uctype_case_table[mid];
		}
	}
	return NULL;
}

/** @brief Simple Unicode lowercase mapping; returns c if it has none. */
static inline char32_t uctype_tolower(const char32_t c)
{
	const struct uctype_case_entry *restrict e = uctype_case_find(c);
	return e != NULL ? e->lower : c;
}

/** @brief Simple Unicode uppercase mapping; returns c if it has none. */
static inline char32_t uctype_toupper(const char32_t c)
{
	const struct uctype_case_entry *restrict e = uctype_case_find(c);
	return e != NULL ? e->upper : c;
}

#define isascii(c) uctype_isascii(c)
#define isalpha(c) uctype_isalpha(c)
#define isdigit(c) uctype_isdigit(c)
#define isalnum(c) uctype_isalnum(c)
#define isspace(c) uctype_isspace(c)
#define isblank(c) uctype_isblank(c)
#define iscntrl(c) uctype_iscntrl(c)
#define islower(c) uctype_islower(c)
#define isupper(c) uctype_isupper(c)
#define isprint(c) uctype_isprint(c)
#define isgraph(c) uctype_isgraph(c)
#define ispunct(c) uctype_ispunct(c)
#define isxdigit(c) uctype_isxdigit(c)
#define tolower(c) uctype_tolower(c)
#define toupper(c) uctype_toupper(c)

/** @brief Value of a hexadecimal digit (0-15), or -1 if c is not one. */
static inline int unhex(const char32_t c)
{
	if (U'0' <= c && c <= U'9') {
		return (int)(c - U'0');
	}
	if (U'A' <= c && c <= U'F') {
		return (int)(c - U'A') + 10;
	}
	if (U'a' <= c && c <= U'f') {
		return (int)(c - U'a') + 10;
	}
	return -1;
}

/**
 * @brief Trim leading whitespace codepoints, returning the new start.
 * @param[in] s NUL-terminated UTF-8 string.
 * @return A pointer into s past any leading isspace() codepoints.
 */
char *strtrimleftspace(char *restrict s);

/**
 * @brief Trim trailing whitespace codepoints in place.
 * @param[in,out] s NUL-terminated UTF-8 string; truncated with a NUL after the
 *                last non-whitespace codepoint.
 * @return s.
 */
char *strtrimrightspace(char *restrict s);

/**
 * @brief Trim leading and trailing whitespace codepoints.
 * @param[in,out] s NUL-terminated UTF-8 string; see strtrimrightspace.
 * @return strtrimrightspace(strtrimleftspace(s)).
 */
char *strtrimspace(char *restrict s);

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
int strlower(char *restrict buf, size_t maxlen, const char *restrict src);

/**
 * @brief Uppercase a UTF-8 string using the simple Unicode case mapping.
 * @see strlower
 */
int strupper(char *restrict buf, size_t maxlen, const char *restrict src);

/** @} */

#endif /* STRINGS_CTYPE_H */
