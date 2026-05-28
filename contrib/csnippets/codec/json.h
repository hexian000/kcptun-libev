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

/* Byte-offset cursor into a JSON buffer.
 * An iter obtained from json_parse() is valid; any other value causes UB. */
typedef size_t json_iter;

/* Value type tag returned by json_parse(). */
enum json_type {
	JSON_ERROR = 0, /* parse error */
	JSON_NULL, /* null */
	JSON_BOOL, /* bool: val.b */
	JSON_NUMBER, /* number: val.str, val.len (raw text, NOT NUL-terminated) */
	JSON_STRING, /* string: val.str, val.len (decoded in-place, NUL-terminated) */
	JSON_ARRAY, /* array:  val.iter = offset just past '[' */
	JSON_OBJECT, /* object: val.iter = offset just past '{' */
};

/* String fragment. Pointed into the original JSON buffer. */
struct json_string {
	size_t len;
	char *str; /* Not NUL-terminated */
};

/* Result of json_parse(). */
struct json_val {
	enum json_type type;
	union {
		bool b; /* JSON_BOOL */
		struct {
			char *str; /* JSON_NUMBER / JSON_STRING */
			size_t len;
		};
		json_iter iter; /* JSON_ARRAY / JSON_OBJECT */
	};
};

/* Parse one JSON value from json[0..len-1] in-place (modifies the buffer).
 * Strings are decoded in-place: str points into json, NUL-terminated.
 * Numbers:  str points to the raw text in json (NOT NUL-terminated).
 * Arrays / objects: iter is the byte offset just past the opening bracket.
 * Does NOT check for trailing content after the value.
 * Returns a json_val; .type == JSON_ERROR on failure. */
struct json_val json_parse(char *restrict json, size_t len);

/* Parse helpers — interpret a raw JSON fragment (as returned by
 * json_obj_next / json_arr_next) into a typed C value.
 * val/vlen: raw JSON fragment (NOT NUL-terminated).
 * Returns true on success; false if the fragment is not a valid JSON value
 * of the expected type, or if the numeric value is out of range. */
bool json_parse_string(char *val, size_t vlen, char **out, size_t *outlen);
bool json_parse_bool(char *val, size_t vlen, bool *out);
bool json_parse_int(char *val, size_t vlen, int *out);
bool json_parse_imax(char *val, size_t vlen, intmax_t *out);
bool json_parse_uint(char *val, size_t vlen, unsigned *out);
bool json_parse_umax(char *val, size_t vlen, uintmax_t *out);
bool json_parse_double(char *val, size_t vlen, double *out);

/* Write a JSON-encoded string (with surrounding quotes) to a buffer.
 * Returns the number of bytes written (excluding NUL), or a negative
 * value on error. If buf is NULL, returns the required buffer size
 * (including NUL) without writing anything — snprintf semantics.
 * len is the byte length of s (need not be NUL-terminated). */
int json_marshal_string(
	char *restrict buf, size_t bufsz, const char *restrict s, size_t len);

/* Advance an object iterator to the next key-value pair.
 * json/len: the same buffer and length passed to json_parse().
 * iter: byte offset updated to point past the current value on success.
 * key/key_len: decoded key, NUL-terminated, points into json.
 * val/val_len: raw JSON fragment, points into json (NOT NUL-terminated).
 * Returns true on success; false at end-of-object or on a parse error. */
bool json_obj_next(
	char *restrict json, size_t len, json_iter *restrict iter,
	char **restrict key, size_t *restrict key_len, char **restrict val,
	size_t *restrict val_len);

/* Advance an array iterator to the next element.
 * json/len: the same buffer and length passed to json_parse().
 * iter: byte offset updated to point past the current value on success.
 * val/val_len: raw JSON fragment, points into json (NOT NUL-terminated).
 * Returns true on success; false at end-of-array or on a parse error. */
bool json_arr_next(
	char *restrict json, size_t len, json_iter *restrict iter,
	char **restrict val, size_t *restrict val_len);

/** @} */

#endif /* CODEC_JSON_H */
