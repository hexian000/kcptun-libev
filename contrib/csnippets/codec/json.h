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

/** Length-bearing bytes; the enclosing API defines their storage lifetime. */
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
 *   - JSON_ERROR: the offset where parsing attempted the value, after leading
 *     whitespace (or the end of the buffer for empty/whitespace-only input).
 *
 * To reject trailing content after a scalar value, skip JSON whitespace from
 * *len and check that the offset reached the end of the buffer.
 * Strings are decoded in-place: str points into json and is NUL-terminated.
 * Numbers: str points to the raw text in json (NOT NUL-terminated).
 *
 * Decoding is destructive: the NUL that terminates a decoded string overwrites
 * its input (usually the closing quote), so once a string -- a key or a value,
 * decoded by this function, json_parse_string() or json_obj_next() -- has been
 * returned, its bytes and those of every container enclosing it are no longer
 * valid JSON. Parse or iterate each value at most once, e.g. do not scan an
 * object for one key and then iterate it again; to re-scan, parse a copy.
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
 * Strings are decoded in-place on the mutable @p val buffer, which then no
 * longer holds valid JSON: see json_parse() on destructive decoding.
 *
 * @param[in] val Mutable JSON fragment (need not be NUL-terminated).
 * @param[in] vlen Bytes available in val.
 * @param[out] out Decoded string, NUL-terminated, points into val.
 * @param[out] outlen Length of the decoded string.
 * @return true on success; false if the fragment is not a valid JSON string
 *         or contains trailing non-whitespace content.
 */
bool json_parse_string(
	char *restrict val, size_t vlen, char **restrict out,
	size_t *restrict outlen);

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
bool json_parse_bool(char *restrict val, size_t vlen, bool *restrict out);

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
bool json_parse_int(char *restrict val, size_t vlen, int *restrict out);

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
bool json_parse_imax(char *restrict val, size_t vlen, intmax_t *restrict out);

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
bool json_parse_uint(char *restrict val, size_t vlen, unsigned *restrict out);

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
bool json_parse_umax(char *restrict val, size_t vlen, uintmax_t *restrict out);

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
bool json_parse_double(char *restrict val, size_t vlen, double *restrict out);

/**
 * @brief Write a JSON-encoded string (with surrounding quotes) to a buffer.
 *
 * Follows snprintf semantics: if buf is NULL, returns the required length
 * (excluding NUL) without writing anything.
 *
 * RFC 8259 §8.1 requires UTF-8, so @p s must be well-formed UTF-8; ill-formed
 * input is rejected instead of emitted.  utf8_load() sanitizes it beforehand
 * where the caller prefers U+FFFD substitution to an error.
 *
 * @param[out] buf Output buffer, or NULL to query length.
 * @param bufsz Size of the output buffer.
 * @param s Input string to encode (need not be NUL-terminated).
 * @param len Byte length of s.
 * @return Number of bytes written (excluding NUL), or a negative value on error
 *         (ill-formed UTF-8, or a length beyond INT_MAX).
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
 *
 * Each key is decoded in-place, so a pass over the object is destructive:
 * iterate it once. A second pass over the same buffer, even from a fresh
 * json_parse(), is invalid: it usually fails with JSON_NEXT_ERROR at the
 * first decoded key, but a key that held escapes can leave bytes that parse
 * as different members (see json_parse()).
 *
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
	char *restrict json, const size_t *restrict len,
	json_iter *restrict iter, char **restrict key, size_t *restrict key_len,
	char **restrict val, size_t *restrict val_len);

/**
 * @brief Advance an array iterator to the next element.
 *
 * The iterator itself decodes nothing, but an element string the caller has
 * decoded (or a key of a nested object it has iterated) leaves the array no
 * longer valid JSON, so iterate it once: a second pass usually fails, but may
 * instead yield different elements (see json_parse()).
 *
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
	char *restrict json, const size_t *restrict len,
	json_iter *restrict iter, char **restrict val,
	size_t *restrict val_len);

/** @} */

/**
 * @defgroup json_codec
 * @brief Table-driven JSON (un)marshalling, driven by descriptor tables.
 *
 * The tables are produced by scripts/gen_schema.py from a JSON Schema; the
 * generic interpreters below consume them so the generated code stays small.
 * @{
 */

/** Representation of an unconstrained map value. Numbers retain their exact
 * JSON spelling; containers retain complete, undecoded JSON fragments. */
struct json_value {
	enum json_type type;
	union {
		bool b;
		struct json_string text;
	};
};

/** A borrowed path, ordered from this segment back to its parent. Map keys
 * carry both their decoded bytes and their position, preserving duplicates.
 * All pointers are valid only for the synchronous callback. */
struct json_path {
	const struct json_path *parent;
	enum { JSON_PATH_PROPERTY, JSON_PATH_INDEX, JSON_PATH_MAP } kind;
	struct json_string key;
	size_t index;
};

enum json_error_kind {
	JSON_E_SYNTAX,
	JSON_E_TYPE,
	JSON_E_CONSTRAINT,
	JSON_E_RANGE,
	JSON_E_REQUIRED,
	JSON_E_UNKNOWN,
	JSON_E_ALLOCATION
};

struct json_error {
	enum json_error_kind kind;
	const struct json_path *path;
	const struct json_constraint *constraint;
	bool has_offset;
	size_t offset;
};

/** Filter actual map entries, before typed parsing or output. The path names
 * the owning map. Return true to retain. Output predicates must be stable
 * across sizing and writing. No prefix has a built-in comment meaning. */
struct json_options {
	bool (*filter)(
		void *context, const struct json_path *map, const char *key,
		size_t key_len);
	void (*error)(void *context, const struct json_error *error);
	void *context;
};

/** Render an escaped JSON path (snprintf semantics), including map positions.
 * Empty keys and embedded NULs are escaped without C-string assumptions. */
int json_format_path(char *buf, size_t bufsz, const struct json_path *path);

enum json_type_kind {
	JSON_K_STRING,
	JSON_K_INT,
	JSON_K_IMAX,
	JSON_K_UINT,
	JSON_K_UMAX,
	JSON_K_DOUBLE,
	JSON_K_BOOL,
	JSON_K_OBJECT,
	JSON_K_DYNAMIC,
	JSON_K_NULL,
	JSON_K_VALUE
};

/** Presence bits for json_constraint.flags. */
enum {
	JSON_C_MIN = 1 << 0,
	JSON_C_MAX = 1 << 1,
	JSON_C_EXCL_MIN = 1 << 2,
	JSON_C_EXCL_MAX = 1 << 3,
	JSON_C_MULT = 1 << 4,
	JSON_C_CONST = 1 << 5,
	JSON_C_ENUM = 1 << 6,
	JSON_C_MIN_LEN = 1 << 7,
	JSON_C_MAX_LEN = 1 << 8,
	JSON_C_MIN_ITEMS = 1 << 9,
	JSON_C_MAX_ITEMS = 1 << 10,
};

/** Schema constraints attached to a field (or, for arrays, to its items plus
 * the array length).  The active union member is selected by the field kind;
 * the flags bitmask records which constraints are present. */
struct json_constraint {
	uint_least32_t flags;
	/* array length (orthogonal to the element kind) */
	size_t min_items, max_items;
	union {
		struct {
			size_t min_len, max_len;
			const struct json_string *enums;
			size_t n_enum;
			struct json_string konst;
		} str;
		struct {
			intmax_t min, max, excl_min, excl_max, mult, konst;
			const intmax_t *enums;
			size_t n_enum;
		} i;
		struct {
			uintmax_t min, max, excl_min, excl_max, mult, konst;
			const uintmax_t *enums;
			size_t n_enum;
		} u;
		struct {
			double min, max, excl_min, excl_max, mult, konst;
			const double *enums;
			size_t n_enum;
		} d;
		struct {
			int konst; /* 0 false, 1 true (JSON_C_CONST gates use) */
		} b;
	};
};

/** Description of a fixed member, array element, map value, or typed extra.
 * Array pointer slots are accessed using the matching element pointer type. */
struct json_field {
	const char *name;
	size_t name_len;
	enum json_type_kind kind;
	bool is_array;
	bool required;
	int_least8_t req_bit;
	size_t offset;
	size_t count_offset;
	const struct json_schema *child;
	const struct json_constraint *constraint;
	/* JSON_ERROR accepts any fragment; otherwise enforces this raw type. */
	enum json_type raw_type;
};

struct json_context;
struct json_output;

/** Immutable object descriptor. Regenerate codecs when this layout changes.
 * Zero initialization allows unknown fields. Presence callbacks access typed
 * bitfields; no bit layout, address, or offsetof of a bitfield is assumed. */
struct json_schema {
	const struct json_field *fields;
	size_t n_fields;
	size_t obj_size;
	int (*lookup)(const char *str, size_t len);
	uint_least64_t required_mask;
	enum { JSON_EXTRA_ALLOW, JSON_EXTRA_REJECT, JSON_EXTRA_TYPED } extra;
	const struct json_field *extra_value;
	bool is_map;
	size_t entry_size;
	size_t entries_offset;
	size_t count_offset;
	const struct json_field *map_value;
	bool (*get_present)(const void *obj, size_t field);
	void (*set_present)(void *obj, size_t field, bool present);
	const char *default_json;
	size_t default_len;
	bool has_default_storage;
	size_t default_storage_offset;
	/* Optional fast-backend object implementations; size tables omit these. */
	bool (*read)(
		const struct json_schema *, void *, char *, size_t,
		struct json_context *, const struct json_path *, bool);
	void (*release)(const struct json_schema *, void *);
	void (*write)(
		const struct json_schema *, const void *, struct json_output *,
		const struct json_path *, int);
};

/** Unmarshal modifies input once and borrows its strings/fragments. Keep the
 * input alive until the object is freed. Default backing and entry/array
 * allocations are owned independently per instance. Input must not alias obj.
 * The error callback runs once on the first failure, before cleanup. Default
 * mode resets the complete object on failure. Presence mode clears only its
 * flags and releases initialized resources; absent member storage is untouched.
 * Do not parse over a live object without freeing it first. */
bool json_unmarshal_ex(
	const struct json_schema *schema, void *obj, char *json, size_t length,
	const struct json_options *options);
bool json_unmarshal(
	const struct json_schema *restrict schema, void *obj, char *json,
	size_t length);

/** Marshal uses snprintf semantics; NULL buf queries length. Default mode
 * emits every field. Presence mode reads/emits only flagged members. Caller
 * construction in presence mode must initialize a member before setting its
 * flag. Map filters never mutate the source; sizing/writing use the same rule. */
int json_marshal_ex(
	const struct json_schema *schema, char *buf, size_t bufsz,
	const void *obj, const char *indent,
	const struct json_options *options);
int json_marshal(
	const struct json_schema *restrict schema, char *restrict buf,
	size_t bufsz, const void *restrict obj, const char *restrict indent);
void json_free(const struct json_schema *restrict schema, void *restrict obj);

/** Shared generated-code machinery. Fast codecs supply object dispatch and
 * direct named presence accesses; size codecs interpret the same value tables.
 * Applications normally use the entry points above or generated wrappers. */
struct json_context {
	char *root;
	size_t length;
	const struct json_options *options;
	bool reported;
	bool fallback;
};
struct json_output {
	char *buf;
	size_t size, length;
	const char *indent;
	const struct json_options *options;
};
bool json_codec_error(
	struct json_context *context, const struct json_path *path,
	enum json_error_kind kind, const struct json_constraint *constraint,
	const char *position);
bool json_codec_init(
	const struct json_schema *schema, void *obj,
	struct json_context *context, const struct json_path *path,
	bool fallback);
bool json_codec_read(
	const struct json_schema *schema, void *obj, char *json, size_t length,
	struct json_context *context, const struct json_path *path,
	bool fallback);
bool json_codec_field(
	const struct json_field *field, void *obj, char *json, size_t length,
	struct json_context *context, const struct json_path *path);
bool json_codec_extra(
	const struct json_schema *schema, char *json, size_t length,
	struct json_context *context, const struct json_path *path);
void json_codec_release(const struct json_field *field, void *obj);
void json_codec_storage(const struct json_schema *schema, void *obj);
void json_codec_write(
	const struct json_schema *schema, const void *obj,
	struct json_output *output, const struct json_path *path, int depth);
void json_codec_write_field(
	const struct json_field *field, const void *obj,
	struct json_output *output, const struct json_path *path, int depth);
void json_codec_open(struct json_output *output, char bracket);
void json_codec_key(
	struct json_output *output, const char *key, size_t length, int depth,
	bool *first);
void json_codec_close(
	struct json_output *output, char bracket, int depth, bool first);

/** @} */

#endif /* CODEC_JSON_H */
