/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef CODEC_JSON_H
#define CODEC_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @defgroup json
 * @brief RFC 8259: The JavaScript Object Notation (JSON) Interchange Format
 * @{
 */

/** True if c is a JSON insignificant whitespace character (RFC 8259 §2):
 * SP (0x20), HT (0x09), LF (0x0A), CR (0x0D). */
static inline bool json_iswhitespace(unsigned char c)
{
	return c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D;
}

/** Byte-offset cursor into a JSON buffer.
 * An iter obtained from json_parse() is valid; any other value causes UB. */
typedef size_t json_iter;

/** Value type tag returned by json_parse(). */
enum json_type {
	/* parse error */
	JSON_ERROR = 0,
	/* null */
	JSON_NULL,
	/* bool: val.b */
	JSON_BOOL,
	/* number: val.str, val.len (raw text, NOT NUL-terminated) */
	JSON_NUMBER,
	/* string: val.str, val.len (decoded in-place, NUL-terminated) */
	JSON_STRING,
	/* array: val.iter = offset just past '[' */
	JSON_ARRAY,
	/* object: val.iter = offset just past '{' */
	JSON_OBJECT,
};

/** String fragment pointed into the original JSON buffer. */
struct json_string {
	size_t len;
	/* Not NUL-terminated */
	char *str;
};

/** Result of json_parse(). */
struct json_val {
	enum json_type type;
	union {
		/* JSON_BOOL */
		bool b;
		struct {
			/* JSON_NUMBER / JSON_STRING */
			char *str;
			size_t len;
		};
		/* JSON_ARRAY / JSON_OBJECT */
		json_iter iter;
	};
};

/**
 * @brief Parse one JSON value from the buffer in-place.
 *
 * Modifies the buffer. On entry *len is the number of bytes available in json.
 * On return *len is set to the number of bytes consumed:
 *   - NULL / BOOL / NUMBER / STRING: the offset just past the value token.
 *   - ARRAY / OBJECT: the offset just past the opening bracket (== .iter);
 *     the body is parsed lazily, so the container's true end is obtained from
 *     the final iterator returned by json_arr_next() / json_obj_next().
 *   - JSON_ERROR: the offset at which parsing stopped.
 *
 * To reject trailing content after a scalar value, skip JSON whitespace from
 * *len and check that the offset reached the end of the buffer.
 * Strings are decoded in-place: str points into json and is NUL-terminated.
 * Numbers: str points to the raw text in json (NOT NUL-terminated).
 *
 * @param[inout] json JSON buffer, modified in-place.
 * @param[inout] len On entry, bytes available in json; on return, bytes consumed.
 * @return A json_val; .type == JSON_ERROR on failure.
 */
struct json_val json_parse(char *restrict json, size_t *restrict len);

/**
 * @brief Interpret a raw JSON fragment as a string.
 *
 * Parses the entire fragment as a JSON string value.  Leading and trailing
 * JSON whitespace (SP, HT, LF, CR) is automatically skipped; the fragment
 * must consist of exactly one JSON string — any trailing non-whitespace
 * content causes the call to return false.
 *
 * Strings are decoded in-place on the mutable @p val buffer.
 *
 * @param[in] val Mutable JSON fragment (need not be NUL-terminated).
 * @param[in] vlen Bytes available in val.
 * @param[out] out Decoded string, NUL-terminated, points into val.
 * @param[out] outlen Length of the decoded string.
 * @return true on success; false if the fragment is not a valid JSON string
 *         or contains trailing non-whitespace content.
 */
bool json_parse_string(char *val, size_t vlen, char **out, size_t *outlen);

/**
 * @brief Interpret a raw JSON fragment as a boolean.
 *
 * Parses the entire fragment as a JSON boolean value.  Leading and trailing
 * JSON whitespace is automatically skipped; the fragment must consist of
 * exactly one JSON boolean — any trailing non-whitespace content causes the
 * call to return false.
 *
 * @param[in] val Mutable JSON fragment (need not be NUL-terminated).
 * @param[in] vlen Bytes available in val.
 * @param[out] out Parsed boolean value.
 * @return true on success; false if the fragment is not a valid JSON boolean
 *         or contains trailing non-whitespace content.
 */
bool json_parse_bool(char *val, size_t vlen, bool *out);

/**
 * @brief Interpret a raw JSON fragment as an int.
 *
 * Parses the entire fragment as a JSON integer value.  Leading and trailing
 * JSON whitespace is automatically skipped; the fragment must consist of
 * exactly one JSON number whose value is an integer within the range of
 * @c int — any trailing non-whitespace content, fractional part, or exponent
 * causes the call to return false.
 *
 * Number parsing is locale-independent.
 *
 * @param[in] val Mutable JSON fragment (need not be NUL-terminated).
 * @param[in] vlen Bytes available in val.
 * @param[out] out Parsed integer value.
 * @return true on success; false if the fragment is not a valid JSON integer
 *         or the value is out of range.
 */
bool json_parse_int(char *val, size_t vlen, int *out);

/**
 * @brief Interpret a raw JSON fragment as an intmax_t.
 *
 * Parses the entire fragment as a JSON integer value.  Leading and trailing
 * JSON whitespace is automatically skipped; the fragment must consist of
 * exactly one JSON number whose value is an integer within the range of
 * @c intmax_t — any trailing non-whitespace content, fractional part, or
 * exponent causes the call to return false.
 *
 * Number parsing is locale-independent.
 *
 * @param[in] val Mutable JSON fragment (need not be NUL-terminated).
 * @param[in] vlen Bytes available in val.
 * @param[out] out Parsed integer value.
 * @return true on success; false if the fragment is not a valid JSON integer
 *         or the value is out of range.
 */
bool json_parse_imax(char *val, size_t vlen, intmax_t *out);

/**
 * @brief Interpret a raw JSON fragment as an unsigned int.
 *
 * Parses the entire fragment as a JSON unsigned integer value.  Leading and
 * trailing JSON whitespace is automatically skipped; the fragment must
 * consist of exactly one non-negative JSON number whose value is an integer
 * within the range of @c unsigned — any trailing non-whitespace content,
 * negative sign, fractional part, or exponent causes the call to return
 * false.
 *
 * Number parsing is locale-independent.
 *
 * @param[in] val Mutable JSON fragment (need not be NUL-terminated).
 * @param[in] vlen Bytes available in val.
 * @param[out] out Parsed unsigned integer value.
 * @return true on success; false if the fragment is not a valid JSON
 *         unsigned integer or the value is out of range.
 */
bool json_parse_uint(char *val, size_t vlen, unsigned *out);

/**
 * @brief Interpret a raw JSON fragment as a uintmax_t.
 *
 * Parses the entire fragment as a JSON unsigned integer value.  Leading and
 * trailing JSON whitespace is automatically skipped; the fragment must
 * consist of exactly one non-negative JSON number whose value is an integer
 * within the range of @c uintmax_t — any trailing non-whitespace content,
 * negative sign, fractional part, or exponent causes the call to return
 * false.
 *
 * Number parsing is locale-independent.
 *
 * @param[in] val Mutable JSON fragment (need not be NUL-terminated).
 * @param[in] vlen Bytes available in val.
 * @param[out] out Parsed unsigned integer value.
 * @return true on success; false if the fragment is not a valid JSON
 *         unsigned integer or the value is out of range.
 */
bool json_parse_umax(char *val, size_t vlen, uintmax_t *out);

/**
 * @brief Interpret a raw JSON fragment as a double.
 *
 * Parses the entire fragment as a JSON number value.  Leading and trailing
 * JSON whitespace is automatically skipped; the fragment must consist of
 * exactly one JSON number — any trailing non-whitespace content causes the
 * call to return false.
 *
 * Number parsing is locale-independent.
 *
 * @param[in] val Mutable JSON fragment (need not be NUL-terminated).
 * @param[in] vlen Bytes available in val.
 * @param[out] out Parsed double value.
 * @return true on success; false if the fragment is not a valid JSON number
 *         or the value is out of range.
 */
bool json_parse_double(char *val, size_t vlen, double *out);

/**
 * @brief Write a JSON-encoded string (with surrounding quotes) to a buffer.
 *
 * Follows snprintf semantics: if buf is NULL, returns the required length
 * (excluding NUL) without writing anything.
 *
 * @param[out] buf Output buffer, or NULL to query length.
 * @param bufsz Size of the output buffer.
 * @param s Input string to encode (need not be NUL-terminated).
 * @param len Byte length of s.
 * @return Number of bytes written (excluding NUL), or a negative value on error.
 *         If the return value is >= bufsz, the output was truncated.
 */
int json_marshal_string(
	char *restrict buf, size_t bufsz, const char *restrict s, size_t len);

/** Step results returned by json_obj_next() / json_arr_next().
 * Iterate with `while ((r = json_*_next(...)) == JSON_NEXT_ITEM)`, then
 * check `r == JSON_NEXT_END` to distinguish a properly terminated
 * container from malformed or truncated input. */
enum {
	/* malformed or truncated input; *iter is unchanged */
	JSON_NEXT_ERROR = -1,
	/* the closing bracket was reached; *iter points just past it */
	JSON_NEXT_END = 0,
	/* an element was produced; *iter points just past its value */
	JSON_NEXT_ITEM = 1,
};

/**
 * @brief Advance an object iterator to the next key-value pair.
 * @param[inout] json The same buffer passed to json_parse().
 * @param[in] len Total bytes available in json (the original buffer length,
 * not the position). This value must remain the same across repeated calls.
 * @param[inout] iter Byte offset, updated to point past the current value
 * (JSON_NEXT_ITEM) or past the closing '}' (JSON_NEXT_END).
 * @param[out] key Decoded key, NUL-terminated, points into json.
 * @param[out] key_len Length of the decoded key.
 * @param[out] val Raw JSON fragment, points into json (NOT NUL-terminated).
 * @param[out] val_len Length of the raw JSON fragment.
 * @return JSON_NEXT_ITEM when a pair was produced; JSON_NEXT_END at the
 * closing '}'; JSON_NEXT_ERROR on malformed or truncated input.
 */
int json_obj_next(
	char *restrict json, const size_t *len, json_iter *restrict iter,
	char **restrict key, size_t *restrict key_len, char **restrict val,
	size_t *restrict val_len);

/**
 * @brief Advance an array iterator to the next element.
 * @param[inout] json The same buffer passed to json_parse().
 * @param[in] len Total bytes available in json (the original buffer length,
 * not the position). This value must remain the same across repeated calls.
 * @param[inout] iter Byte offset, updated to point past the current value
 * (JSON_NEXT_ITEM) or past the closing ']' (JSON_NEXT_END).
 * @param[out] val Raw JSON fragment, points into json (NOT NUL-terminated).
 * @param[out] val_len Length of the raw JSON fragment.
 * @return JSON_NEXT_ITEM when an element was produced; JSON_NEXT_END at the
 * closing ']'; JSON_NEXT_ERROR on malformed or truncated input.
 */
int json_arr_next(
	char *restrict json, const size_t *len, json_iter *restrict iter,
	char **restrict val, size_t *restrict val_len);

/** @} */

#endif /* CODEC_JSON_H */
