/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "json.h"

#include "utils/slog.h"

#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* JSON insignificant whitespace: SP, HT, LF, CR (RFC 8259 §2) */
#define json_isws(c)                                                           \
	((unsigned char)(c) == 0x20 || (unsigned char)(c) == 0x09 ||           \
	 (unsigned char)(c) == 0x0A || (unsigned char)(c) == 0x0D)

static bool parse_hex4(const char *restrict s, uint_fast32_t *restrict out)
{
	uint_fast32_t val = 0;
	for (int j = 0; j < 4; j++) {
		const unsigned char c = (unsigned char)s[j];
		uint_fast32_t digit;
		if (c >= '0' && c <= '9') {
			digit = c - '0';
		} else if (c >= 'a' && c <= 'f') {
			digit = (uint_fast32_t)(c - 'a') + 10;
		} else if (c >= 'A' && c <= 'F') {
			digit = (uint_fast32_t)(c - 'A') + 10;
		} else {
			return false;
		}
		val = (val << 4) | digit;
	}
	*out = val;
	return true;
}

/* encode_utf8: encode a Unicode codepoint to UTF-8
 * buf must have room for at least 4 bytes.
 * Returns bytes written (1-4), or 0 for an invalid codepoint. */
static int encode_utf8(uint_fast32_t cp, char *restrict buf)
{
	if (cp < 0x80) {
		buf[0] = (char)cp;
		return 1;
	}
	if (cp < 0x800) {
		buf[0] = (char)(0xC0 | (cp >> 6));
		buf[1] = (char)(0x80 | (cp & 0x3F));
		return 2;
	}
	if (cp < 0x10000) {
		buf[0] = (char)(0xE0 | (cp >> 12));
		buf[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
		buf[2] = (char)(0x80 | (cp & 0x3F));
		return 3;
	}
	if (cp <= 0x10FFFF) {
		buf[0] = (char)(0xF0 | (cp >> 18));
		buf[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
		buf[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
		buf[3] = (char)(0x80 | (cp & 0x3F));
		return 4;
	}
	return 0;
}

/* scan_string_inplace: decode a JSON string in-place on a mutable buffer
 *
 * s        - input pointer (first char after the opening quote)
 * len      - remaining bytes in input
 * out_slen - receives the decoded string length
 * consumed - receives bytes consumed from s (including the closing '"')
 *
 * Decodes directly over the input buffer; output length <= input length.
 * Returns true on success, false on error. */
static bool scan_string_inplace(
	char *restrict s, const size_t len, size_t *restrict out_slen,
	size_t *restrict consumed)
{
	size_t opos = 0;
	size_t i = 0;
	for (;;) {
		if (i >= len) {
			LOGE("jsonutil: unterminated string");
			return false;
		}
		const unsigned char c = (unsigned char)s[i];
		if (c == '"') {
			s[opos] = '\0';
			*out_slen = opos;
			*consumed = i + 1;
			return true;
		}
		if (c < 0x20) {
			LOGE("jsonutil: unescaped control character in string");
			return false;
		}
		if (c != '\\') {
			s[opos++] = (char)c;
			i++;
			continue;
		}
		/* escape sequence */
		i++;
		if (i >= len) {
			LOGE("jsonutil: truncated escape sequence");
			return false;
		}
		const unsigned char ec = (unsigned char)s[i];
		i++;
		switch (ec) {
		case '"':
			s[opos++] = '"';
			break;
		case '\\':
			s[opos++] = '\\';
			break;
		case '/':
			s[opos++] = '/';
			break;
		case 'b':
			s[opos++] = '\b';
			break;
		case 'f':
			s[opos++] = '\f';
			break;
		case 'n':
			s[opos++] = '\n';
			break;
		case 'r':
			s[opos++] = '\r';
			break;
		case 't':
			s[opos++] = '\t';
			break;
		case 'u': {
			if (i + 4 > len) {
				LOGE("jsonutil: truncated \\uXXXX escape");
				return false;
			}
			uint_fast32_t cp;
			if (!parse_hex4(s + i, &cp)) {
				LOGE("jsonutil: invalid \\uXXXX escape");
				return false;
			}
			i += 4;
			/* handle surrogate pair */
			if (cp >= 0xD800 && cp <= 0xDBFF) {
				if (i + 6 > len || s[i] != '\\' ||
				    s[i + 1] != 'u') {
					LOGE("jsonutil: high surrogate without low surrogate");
					return false;
				}
				i += 2;
				uint_fast32_t low;
				if (!parse_hex4(s + i, &low)) {
					LOGE("jsonutil: invalid low surrogate escape");
					return false;
				}
				if (low < 0xDC00 || low > 0xDFFF) {
					LOGE("jsonutil: invalid surrogate pair");
					return false;
				}
				i += 4;
				cp = 0x10000 + ((cp - 0xD800) << 10) +
				     (low - 0xDC00);
			} else if (cp >= 0xDC00 && cp <= 0xDFFF) {
				LOGE("jsonutil: lone low surrogate");
				return false;
			}
			const int nbytes = encode_utf8(cp, s + opos);
			if (nbytes <= 0) {
				LOGE("jsonutil: invalid Unicode codepoint");
				return false;
			}
			opos += (size_t)nbytes;
			break;
		}
		default:
			LOGE_F("jsonutil: invalid escape '\\%c'", (char)ec);
			return false;
		}
	}
}

/* scan_number: measure a JSON number token starting at s[0]
 * Returns the byte length of the token, or 0 on failure. */
static size_t scan_number(const char *restrict s, const size_t len)
{
	size_t i = 0;
	if (i < len && s[i] == '-') {
		i++;
	}
	if (i >= len || !isdigit((unsigned char)s[i])) {
		return 0;
	}
	if (s[i] == '0') {
		i++;
	} else {
		while (i < len && isdigit((unsigned char)s[i])) {
			i++;
		}
	}
	if (i < len && s[i] == '.') {
		i++;
		if (i >= len || !isdigit((unsigned char)s[i])) {
			return 0;
		}
		while (i < len && isdigit((unsigned char)s[i])) {
			i++;
		}
	}
	if (i < len && (s[i] == 'e' || s[i] == 'E')) {
		i++;
		if (i < len && (s[i] == '+' || s[i] == '-')) {
			i++;
		}
		if (i >= len || !isdigit((unsigned char)s[i])) {
			return 0;
		}
		while (i < len && isdigit((unsigned char)s[i])) {
			i++;
		}
	}
	return i;
}

/* -------------------------------------------------------------------------
 * json_parse
 * ---------------------------------------------------------------------- */

struct json_val json_parse(char *restrict json, const size_t len)
{
	const struct json_val err = { .type = JSON_ERROR };
	/* skip leading whitespace */
	size_t i = 0;
	while (i < len && json_isws(json[i])) {
		i++;
	}
	if (i >= len) {
		LOGE("jsonutil: empty input");
		return err;
	}
	const unsigned char c = (unsigned char)json[i];
	switch (c) {
	case 'n':
		if (len - i >= 4 && memcmp(json + i, "null", 4) == 0) {
			return (struct json_val){ .type = JSON_NULL };
		}
		LOGE("jsonutil: invalid value 'n...'");
		return err;
	case 't':
		if (len - i >= 4 && memcmp(json + i, "true", 4) == 0) {
			return (struct json_val){ .type = JSON_BOOL,
						  .b = true };
		}
		LOGE("jsonutil: invalid value 't...'");
		return err;
	case 'f':
		if (len - i >= 5 && memcmp(json + i, "false", 5) == 0) {
			return (struct json_val){ .type = JSON_BOOL,
						  .b = false };
		}
		LOGE("jsonutil: invalid value 'f...'");
		return err;
	case '"': {
		size_t slen, consumed;
		if (!scan_string_inplace(
			    json + i + 1, len - i - 1, &slen, &consumed)) {
			return err;
		}
		return (struct json_val){
			.type = JSON_STRING,
			.str = json + i + 1,
			.len = slen,
		};
	}
	case '{':
		return (struct json_val){ .type = JSON_OBJECT, .iter = i + 1 };
	case '[':
		return (struct json_val){ .type = JSON_ARRAY, .iter = i + 1 };
	default: {
		const size_t nlen = scan_number(json + i, len - i);
		if (nlen == 0) {
			LOGE_F("jsonutil: unexpected character '%c'", (char)c);
			return err;
		}
		return (struct json_val){
			.type = JSON_NUMBER,
			.str = json + i,
			.len = nlen,
		};
	}
	}
}

bool json_parse_string(char *val, const size_t vlen, char **out, size_t *outlen)
{
	const struct json_val sv = json_parse(val, vlen);
	if (sv.type != JSON_STRING) {
		return false;
	}
	*out = sv.str;
	*outlen = sv.len;
	return true;
}

bool json_parse_bool(char *val, const size_t vlen, bool *out)
{
	const struct json_val bv = json_parse(val, vlen);
	if (bv.type != JSON_BOOL) {
		return false;
	}
	*out = bv.b;
	return true;
}

bool json_parse_int(char *val, const size_t vlen, int *out)
{
	const struct json_val nv = json_parse(val, vlen);
	if (nv.type != JSON_NUMBER) {
		return false;
	}
	char *ep;
	const intmax_t n = strtoimax(nv.str, &ep, 10);
	if (ep == nv.str || n < INT_MIN || n > INT_MAX) {
		return false;
	}
	*out = (int)n;
	return true;
}

bool json_parse_imax(char *val, const size_t vlen, intmax_t *out)
{
	const struct json_val nv = json_parse(val, vlen);
	if (nv.type != JSON_NUMBER) {
		return false;
	}
	char *ep;
	const intmax_t n = strtoimax(nv.str, &ep, 10);
	if (ep == nv.str) {
		return false;
	}
	*out = n;
	return true;
}

bool json_parse_uint(char *val, const size_t vlen, unsigned *out)
{
	const struct json_val nv = json_parse(val, vlen);
	if (nv.type != JSON_NUMBER) {
		return false;
	}
	char *ep;
	const uintmax_t n = strtoumax(nv.str, &ep, 10);
	if (ep == nv.str || n > UINT_MAX) {
		return false;
	}
	*out = (unsigned)n;
	return true;
}

bool json_parse_umax(char *val, const size_t vlen, uintmax_t *out)
{
	const struct json_val nv = json_parse(val, vlen);
	if (nv.type != JSON_NUMBER) {
		return false;
	}
	char *ep;
	const uintmax_t n = strtoumax(nv.str, &ep, 10);
	if (ep == nv.str) {
		return false;
	}
	*out = n;
	return true;
}

bool json_parse_double(char *val, const size_t vlen, double *out)
{
	const struct json_val nv = json_parse(val, vlen);
	if (nv.type != JSON_NUMBER) {
		return false;
	}
	char *ep;
	const double n = strtod(nv.str, &ep);
	if (ep == nv.str) {
		return false;
	}
	*out = n;
	return true;
}

/* -------------------------------------------------------------------------
 * json_escape_string
 * ---------------------------------------------------------------------- */

int json_marshal_string(
	char *restrict buf, const size_t bufsz, const char *restrict s,
	const size_t len)
{
	/* two-pass: first pass counts, second pass writes */
	size_t need = 2; /* opening and closing quotes */
	for (size_t i = 0; i < len; i++) {
		const unsigned char c = (unsigned char)s[i];
		if (c == '"' || c == '\\' || c == '\b' || c == '\f' ||
		    c == '\n' || c == '\r' || c == '\t') {
			need += 2;
		} else if (c < 0x20) {
			need += 6; /* \uXXXX */
		} else {
			need += 1;
		}
	}
	need += 1; /* NUL terminator */

	if (buf == NULL) {
		return (int)need;
	}

	size_t pos = 0;
	if (bufsz > 0 && pos < bufsz) {
		buf[pos] = '"';
	}
	pos++;
	for (size_t i = 0; i < len; i++) {
		const unsigned char c = (unsigned char)s[i];
		if (c == '"') {
			if (pos + 2 <= bufsz) {
				buf[pos] = '\\';
				buf[pos + 1] = '"';
			}
			pos += 2;
		} else if (c == '\\') {
			if (pos + 2 <= bufsz) {
				buf[pos] = '\\';
				buf[pos + 1] = '\\';
			}
			pos += 2;
		} else if (c == '\b') {
			if (pos + 2 <= bufsz) {
				buf[pos] = '\\';
				buf[pos + 1] = 'b';
			}
			pos += 2;
		} else if (c == '\f') {
			if (pos + 2 <= bufsz) {
				buf[pos] = '\\';
				buf[pos + 1] = 'f';
			}
			pos += 2;
		} else if (c == '\n') {
			if (pos + 2 <= bufsz) {
				buf[pos] = '\\';
				buf[pos + 1] = 'n';
			}
			pos += 2;
		} else if (c == '\r') {
			if (pos + 2 <= bufsz) {
				buf[pos] = '\\';
				buf[pos + 1] = 'r';
			}
			pos += 2;
		} else if (c == '\t') {
			if (pos + 2 <= bufsz) {
				buf[pos] = '\\';
				buf[pos + 1] = 't';
			}
			pos += 2;
		} else if (c < 0x20) {
			if (pos + 6 <= bufsz) {
				const int n = snprintf(
					buf + pos, bufsz - pos, "\\u%04x",
					(unsigned)c);
				if (n < 0 || (size_t)n >= bufsz - pos) {
					return -1;
				}
			}
			pos += 6;
		} else {
			if (pos < bufsz) {
				buf[pos] = (char)c;
			}
			pos++;
		}
	}
	if (pos < bufsz) {
		buf[pos] = '"';
	}
	pos++;
	if (pos < bufsz) {
		buf[pos] = '\0';
	}
	pos++;
	return (int)pos - 1; /* snprintf semantics: exclude NUL */
}

/* -------------------------------------------------------------------------
 * Object and array iterators
 * ---------------------------------------------------------------------- */

/* Scan one JSON value starting at buf[0] without decoding.
 * Returns the byte length of the value, or -1 on syntax error. */
static ptrdiff_t skip_raw_value(const char *restrict buf, const size_t len)
{
	if (len == 0) {
		return -1;
	}
	switch ((unsigned char)buf[0]) {
	case 'n':
		if (len >= 4 && memcmp(buf, "null", 4) == 0) {
			return 4;
		}
		return -1;
	case 't':
		if (len >= 4 && memcmp(buf, "true", 4) == 0) {
			return 4;
		}
		return -1;
	case 'f':
		if (len >= 5 && memcmp(buf, "false", 5) == 0) {
			return 5;
		}
		return -1;
	case '"': {
		size_t i = 1;
		while (i < len) {
			if (buf[i] == '\\') {
				i += 2;
				continue;
			}
			if (buf[i] == '"') {
				return (ptrdiff_t)(i + 1);
			}
			i++;
		}
		return -1;
	}
	case '[':
	case '{': {
		const char open = buf[0];
		const char close = (open == '[') ? ']' : '}';
		int depth = 1;
		size_t i = 1;
		while (i < len && depth > 0) {
			if (buf[i] == '"') {
				i++;
				while (i < len) {
					if (buf[i] == '\\') {
						i += 2;
						continue;
					}
					if (buf[i] == '"') {
						i++;
						break;
					}
					i++;
				}
				continue;
			}
			if (buf[i] == open) {
				depth++;
			} else if (buf[i] == close) {
				depth--;
			}
			i++;
		}
		return (depth == 0) ? (ptrdiff_t)i : -1;
	}
	default:
		break;
	}
	/* number */
	size_t i = 0;
	if (buf[i] == '-') {
		i++;
	}
	if (i >= len || !isdigit((unsigned char)buf[i])) {
		return -1;
	}
	while (i < len && isdigit((unsigned char)buf[i])) {
		i++;
	}
	if (i < len && buf[i] == '.') {
		i++;
		while (i < len && isdigit((unsigned char)buf[i])) {
			i++;
		}
	}
	if (i < len && (buf[i] == 'e' || buf[i] == 'E')) {
		i++;
		if (i < len && (buf[i] == '+' || buf[i] == '-')) {
			i++;
		}
		while (i < len && isdigit((unsigned char)buf[i])) {
			i++;
		}
	}
	return (ptrdiff_t)i;
}

bool json_obj_next(
	char *restrict json, const size_t len, json_iter *restrict iter,
	char **restrict key, size_t *restrict key_len, char **restrict val,
	size_t *restrict val_len)
{
	size_t i = *iter;
	while (i < len && json_isws(json[i])) {
		i++;
	}
	if (i >= len) {
		LOGE("jsonutil: unterminated object");
		return false;
	}
	if (json[i] == '}') {
		*iter = i + 1;
		return false;
	}
	if (json[i] == ',') {
		i++;
		while (i < len && json_isws(json[i])) {
			i++;
		}
	}
	if (i >= len || json[i] != '"') {
		LOGE("jsonutil: expected object key string");
		return false;
	}
	size_t slen, consumed;
	if (!scan_string_inplace(json + i + 1, len - i - 1, &slen, &consumed)) {
		return false;
	}
	*key = json + i + 1;
	*key_len = slen;
	i += 1 + consumed;
	while (i < len && json_isws(json[i])) {
		i++;
	}
	if (i >= len || json[i] != ':') {
		LOGE("jsonutil: expected ':' after object key");
		return false;
	}
	i++;
	while (i < len && json_isws(json[i])) {
		i++;
	}
	if (i >= len) {
		LOGE("jsonutil: expected value after ':'");
		return false;
	}
	const ptrdiff_t vlen = skip_raw_value(json + i, len - i);
	if (vlen < 0) {
		LOGE("jsonutil: invalid JSON value");
		return false;
	}
	*val = json + i;
	*val_len = (size_t)vlen;
	*iter = i + (size_t)vlen;
	return true;
}

bool json_arr_next(
	char *restrict json, const size_t len, json_iter *restrict iter,
	char **restrict val, size_t *restrict val_len)
{
	size_t i = *iter;
	while (i < len && json_isws(json[i])) {
		i++;
	}
	if (i >= len) {
		LOGE("jsonutil: unterminated array");
		return false;
	}
	if (json[i] == ']') {
		*iter = i + 1;
		return false;
	}
	if (json[i] == ',') {
		i++;
		while (i < len && json_isws(json[i])) {
			i++;
		}
	}
	if (i >= len) {
		LOGE("jsonutil: expected array element");
		return false;
	}
	const ptrdiff_t vlen = skip_raw_value(json + i, len - i);
	if (vlen < 0) {
		LOGE("jsonutil: invalid JSON value in array");
		return false;
	}
	*val = json + i;
	*val_len = (size_t)vlen;
	*iter = i + (size_t)vlen;
	return true;
}
