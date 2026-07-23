/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef STRINGS_UTF8_H
#define STRINGS_UTF8_H

#include <stddef.h>
#include <stdint.h>
#include <uchar.h>

/**
 * @defgroup utf8
 * @brief RFC 3629: UTF-8, a transformation format of ISO 10646
 * @{
 */

/** Maximum length in bytes of one encoded UTF-8 sequence. */
#define UTF8_MAX_LEN 4

/**
 * @brief Encode one Unicode codepoint as UTF-8.
 * @param[out] buf Output buffer with room for at least UTF8_MAX_LEN bytes.
 * @param cp Unicode codepoint.
 * @return Bytes written (1-4), or 0 if cp is a surrogate half
 *         (U+D800..U+DFFF) or exceeds U+10FFFF (nothing is written).
 */
int utf8_encode(char *restrict buf, char32_t cp);

/**
 * @brief Decode or validate one UTF-8 sequence starting at s[0].
 *
 * Strict RFC 3629: rejects overlong encodings, encoded surrogate halves,
 * codepoints beyond U+10FFFF, malformed continuation bytes, and sequences
 * running past len.
 *
 * @param[out] cp Decoded codepoint, or NULL to validate only.
 * @param[in] s Input buffer (at least 1 byte).
 * @param len Bytes available in s.
 * @return Sequence length (1-4), or 0 if invalid.
 */
int utf8_decode(char32_t *restrict cp, const char *restrict s, size_t len);

/** @} */

#endif /* STRINGS_UTF8_H */
