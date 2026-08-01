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

/**
 * @brief Decode the next unit of a NUL-terminated string and advance the cursor.
 * @param[out] cp Decoded codepoint, or U+FFFD for an invalid byte.
 * @param[in,out] s Cursor into a NUL-terminated UTF-8 string; advanced past the
 *                decoded unit (always by >= 1 byte while one remains).
 * @return Bytes consumed (1-4), or 0 at the terminator without advancing.
 */
int utf8_next(char32_t *restrict cp, const char **restrict s);

/**
 * @brief Load text in any UTF encoding into a UTF-8 string.
 *
 * Detects the encoding from a leading byte order mark -- UTF-8 (EF BB BF),
 * UTF-16 (FE FF or FF FE) or UTF-32 (00 00 FE FF or FF FE 00 00) -- strips it,
 * and transcodes the content to UTF-8. Data without a BOM is assumed to already
 * be UTF-8. Ill-formed input (a lone surrogate, an incomplete trailing unit, a
 * value beyond U+10FFFF, or an invalid UTF-8 sequence) is replaced with U+FFFD,
 * so the output is always well-formed UTF-8.
 *
 * snprintf(3) semantics: always NUL-terminated when maxlen > 0, truncation never
 * splits a codepoint, and the return is the byte length needed.
 *
 * @param[out] buf Output buffer; may be NULL only when maxlen == 0.
 * @param maxlen Size of buf in bytes, including the NUL terminator.
 * @param[in] data Input bytes in any supported UTF encoding; may be NULL only
 *            when len == 0.
 * @param len Length of @p data in bytes.
 * @return Bytes needed excluding the NUL; a value >= maxlen indicates
 *         truncation. Negative if the length exceeds INT_MAX.
 */
int utf8_load(
	char *restrict buf, size_t maxlen, const void *restrict data,
	size_t len);

/**
 * @brief Encode a UTF-32 string as a UTF-8 string.
 *
 * snprintf(3) semantics: always NUL-terminated when maxlen > 0, truncation never
 * splits a codepoint, and the return is the byte length needed. A surrogate half
 * or a value beyond U+10FFFF is encoded as U+FFFD.
 *
 * @param[out] buf Output UTF-8 buffer; may be NULL only when maxlen == 0.
 * @param maxlen Size of buf in bytes, including the NUL terminator.
 * @param[in] src NUL-terminated UTF-32 string.
 * @return Bytes needed excluding the NUL; a value >= maxlen indicates
 *         truncation. Negative if the length exceeds INT_MAX.
 */
int utf8_encode32(
	char *restrict buf, size_t maxlen, const char32_t *restrict src);

/**
 * @brief Decode a UTF-8 string into a UTF-32 string.
 *
 * snprintf(3) semantics in char32_t units: always NUL-terminated when maxlen >
 * 0, and the return is the number of units needed. An ill-formed UTF-8 sequence
 * is decoded as U+FFFD.
 *
 * @param[out] buf Output UTF-32 buffer; may be NULL only when maxlen == 0.
 * @param maxlen Capacity of buf in char32_t units, including the NUL terminator.
 * @param[in] src NUL-terminated UTF-8 string.
 * @return char32_t units needed excluding the NUL; a value >= maxlen indicates
 *         truncation. Negative if the length exceeds INT_MAX.
 */
int utf8_decode32(
	char32_t *restrict buf, size_t maxlen, const char *restrict src);

/**
 * @brief Encode a UTF-16 string as a UTF-8 string.
 *
 * snprintf(3) semantics: always NUL-terminated when maxlen > 0, truncation never
 * splits a codepoint, and the return is the byte length needed. An ill-formed
 * UTF-16 unit (a lone surrogate) is encoded as U+FFFD.
 *
 * @param[out] buf Output UTF-8 buffer; may be NULL only when maxlen == 0.
 * @param maxlen Size of buf in bytes, including the NUL terminator.
 * @param[in] src NUL-terminated UTF-16 string.
 * @return Bytes needed excluding the NUL; a value >= maxlen indicates
 *         truncation. Negative if the length exceeds INT_MAX.
 */
int utf8_encode16(
	char *restrict buf, size_t maxlen, const char16_t *restrict src);

/**
 * @brief Decode a UTF-8 string into a UTF-16 string.
 *
 * snprintf(3) semantics in char16_t units: always NUL-terminated when maxlen >
 * 0, truncation never splits a surrogate pair, and the return is the number of
 * units needed. An ill-formed UTF-8 sequence is decoded as U+FFFD.
 *
 * @param[out] buf Output UTF-16 buffer; may be NULL only when maxlen == 0.
 * @param maxlen Capacity of buf in char16_t units, including the NUL terminator.
 * @param[in] src NUL-terminated UTF-8 string.
 * @return char16_t units needed excluding the NUL; a value >= maxlen indicates
 *         truncation. Negative if the length exceeds INT_MAX.
 */
int utf8_decode16(
	char16_t *restrict buf, size_t maxlen, const char *restrict src);

#if WITH_ICU
/** @brief Target normal form for utf8_normalize(), per UAX #15. */
enum utf8_normalize_form {
	UTF8_NORMALIZE_NFC, /**< canonical composition */
	UTF8_NORMALIZE_NFD, /**< canonical decomposition */
	UTF8_NORMALIZE_NFKC, /**< compatibility composition */
	UTF8_NORMALIZE_NFKD, /**< compatibility decomposition */
};

/**
 * @brief Normalize a UTF-8 string to a Unicode normal form, per UAX #15.
 *
 * snprintf(3) semantics: always NUL-terminated when maxlen > 0, truncation never
 * splits a codepoint, and the return is the byte length needed. Backed by
 * libicu, so the result equals unicodedata.normalize(form, ...) of the linked
 * libicu Unicode version. An ill-formed input byte is replaced with U+FFFD.
 *
 * @param[out] buf Output buffer; may be NULL only when maxlen == 0.
 * @param maxlen Size of buf in bytes, including the NUL terminator.
 * @param[in] src NUL-terminated UTF-8 string.
 * @param form The target normal form.
 * @return Bytes needed excluding the NUL; a value >= maxlen indicates
 *         truncation. Negative if the length exceeds INT_MAX or on failure.
 * @note Requires the WITH_ICU build.
 */
int utf8_normalize(
	char *restrict buf, size_t maxlen, const char *restrict src,
	enum utf8_normalize_form form);
#endif /* WITH_ICU */

/** @} */

#endif /* STRINGS_UTF8_H */
