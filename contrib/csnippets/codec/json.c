/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "json.h"

#include "utils/arraysize.h"
#include "utils/ascii.h"
#include "utils/slog.h"

#include <errno.h>
#include <float.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool parse_hex4(const char *restrict s, uint_fast32_t *restrict out)
{
	uint_fast32_t val = 0;
	for (int j = 0; j < 4; j++) {
		const unsigned char c = (unsigned char)s[j];
		uint_fast32_t digit;
		if (c >= '0' && c <= '9') {
			digit = (uint_fast32_t)(c - '0');
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
		/* RFC 8259 §6: after a leading zero the next character must
		 * be '.', 'e', 'E', or end-of-number — not another digit. */
		if (i < len && isdigit((unsigned char)s[i])) {
			return 0;
		}
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

struct json_val json_parse(char *restrict json, size_t *restrict len)
{
	const size_t buflen = *len;
	/* skip leading whitespace */
	size_t i = 0;
	while (i < buflen && json_iswhitespace(json[i])) {
		i++;
	}
	if (i >= buflen) {
		LOGE("jsonutil: empty input");
		*len = i;
		return (struct json_val){ .type = JSON_ERROR };
	}
	const unsigned char c = (unsigned char)json[i];
	switch (c) {
	case 'n':
		if (buflen - i >= 4 && memcmp(json + i, "null", 4) == 0) {
			*len = i + 4;
			return (struct json_val){ .type = JSON_NULL };
		}
		LOGE("jsonutil: invalid value 'n...'");
		break;
	case 't':
		if (buflen - i >= 4 && memcmp(json + i, "true", 4) == 0) {
			*len = i + 4;
			return (struct json_val){
				.type = JSON_BOOL,
				.b = true,
			};
		}
		LOGE("jsonutil: invalid value 't...'");
		break;
	case 'f':
		if (buflen - i >= 5 && memcmp(json + i, "false", 5) == 0) {
			*len = i + 5;
			return (struct json_val){
				.type = JSON_BOOL,
				.b = false,
			};
		}
		LOGE("jsonutil: invalid value 'f...'");
		break;
	case '"': {
		size_t slen, consumed;
		if (scan_string_inplace(
			    json + i + 1, buflen - i - 1, &slen, &consumed)) {
			*len = i + 1 + consumed;
			return (struct json_val){
				.type = JSON_STRING,
				.str = json + i + 1,
				.len = slen,
			};
		}
		break;
	}
	case '{':
		*len = i + 1;
		return (struct json_val){
			.type = JSON_OBJECT,
			.iter = i + 1,
		};
	case '[':
		*len = i + 1;
		return (struct json_val){
			.type = JSON_ARRAY,
			.iter = i + 1,
		};
	default: {
		const size_t nlen = scan_number(json + i, buflen - i);
		if (nlen > 0) {
			*len = i + nlen;
			return (struct json_val){
				.type = JSON_NUMBER,
				.str = json + i,
				.len = nlen,
			};
		}
		LOGE_F("jsonutil: unexpected character '%c'", (char)c);
		break;
	}
	}
	*len = i;
	return (struct json_val){ .type = JSON_ERROR };
}

/* Maximum size of the stack buffer used to NUL-terminate a number token before
 * handing it to the strto*() family.  A token longer than this is necessarily
 * out of range for any supported integer type. */
#define JSON_NUM_BUFSIZE 64

/* num_to_buf: copy a non-NUL-terminated number token into a NUL-terminated
 * stack buffer so the strto*() family can be used without reading past the
 * fragment.  Returns false if the token is empty or does not fit. */
static bool num_to_buf(
	char *restrict dst, const size_t dstsz, const char *restrict src,
	const size_t srclen)
{
	if (srclen == 0 || srclen >= dstsz) {
		return false;
	}
	memcpy(dst, src, srclen);
	dst[srclen] = '\0';
	return true;
}

/* json_rest_is_ws: return true if every byte in val[pos..vlen-1] is JSON
 * whitespace.  Used by json_parse_* helpers for the "whole fragment" check. */
static bool
json_rest_is_ws(const char *restrict val, size_t pos, const size_t vlen)
{
	while (pos < vlen && json_iswhitespace((unsigned char)val[pos])) {
		pos++;
	}
	return pos == vlen;
}

bool json_parse_string(char *val, size_t vlen, char **out, size_t *outlen)
{
	size_t pos = vlen;
	const struct json_val sv = json_parse(val, &pos);
	if (sv.type != JSON_STRING || !json_rest_is_ws(val, pos, vlen)) {
		return false;
	}
	*out = sv.str;
	*outlen = sv.len;
	return true;
}

bool json_parse_bool(char *val, size_t vlen, bool *out)
{
	size_t pos = vlen;
	const struct json_val bv = json_parse(val, &pos);
	if (bv.type != JSON_BOOL || !json_rest_is_ws(val, pos, vlen)) {
		return false;
	}
	*out = bv.b;
	return true;
}

bool json_parse_int(char *val, size_t vlen, int *out)
{
	size_t pos = vlen;
	const struct json_val nv = json_parse(val, &pos);
	if (nv.type != JSON_NUMBER || !json_rest_is_ws(val, pos, vlen)) {
		return false;
	}
	char buf[JSON_NUM_BUFSIZE];
	if (!num_to_buf(buf, sizeof(buf), nv.str, nv.len)) {
		return false;
	}
	char *ep;
	errno = 0;
	const intmax_t n = strtoimax(buf, &ep, 10);
	if (*ep != '\0' || errno == ERANGE || n < INT_MIN || n > INT_MAX) {
		return false;
	}
	*out = (int)n;
	return true;
}

bool json_parse_imax(char *val, size_t vlen, intmax_t *out)
{
	size_t pos = vlen;
	const struct json_val nv = json_parse(val, &pos);
	if (nv.type != JSON_NUMBER || !json_rest_is_ws(val, pos, vlen)) {
		return false;
	}
	char buf[JSON_NUM_BUFSIZE];
	if (!num_to_buf(buf, sizeof(buf), nv.str, nv.len)) {
		return false;
	}
	char *ep;
	errno = 0;
	const intmax_t n = strtoimax(buf, &ep, 10);
	if (*ep != '\0' || errno == ERANGE) {
		return false;
	}
	*out = n;
	return true;
}

bool json_parse_uint(char *val, size_t vlen, unsigned *out)
{
	size_t pos = vlen;
	const struct json_val nv = json_parse(val, &pos);
	if (nv.type != JSON_NUMBER || !json_rest_is_ws(val, pos, vlen)) {
		return false;
	}
	if (nv.len > 0 && nv.str[0] == '-') {
		return false;
	}
	char buf[JSON_NUM_BUFSIZE];
	if (!num_to_buf(buf, sizeof(buf), nv.str, nv.len)) {
		return false;
	}
	char *ep;
	errno = 0;
	const uintmax_t n = strtoumax(buf, &ep, 10);
	if (*ep != '\0' || errno == ERANGE || n > UINT_MAX) {
		return false;
	}
	*out = (unsigned)n;
	return true;
}

bool json_parse_umax(char *val, size_t vlen, uintmax_t *out)
{
	size_t pos = vlen;
	const struct json_val nv = json_parse(val, &pos);
	if (nv.type != JSON_NUMBER || !json_rest_is_ws(val, pos, vlen)) {
		return false;
	}
	if (nv.len > 0 && nv.str[0] == '-') {
		return false;
	}
	char buf[JSON_NUM_BUFSIZE];
	if (!num_to_buf(buf, sizeof(buf), nv.str, nv.len)) {
		return false;
	}
	char *ep;
	errno = 0;
	const uintmax_t n = strtoumax(buf, &ep, 10);
	if (*ep != '\0' || errno == ERANGE) {
		return false;
	}
	*out = n;
	return true;
}

/* Exact powers of ten representable as double (10^0 .. 10^22). */
static const double json_pow10[] = {
	1e0,  1e1,  1e2,  1e3,	1e4,  1e5,  1e6,  1e7,	1e8,  1e9,  1e10, 1e11,
	1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22,
};

/* json_scale10: multiply m by 10^exp using exact powers of ten, saturating to
 * +/-inf on overflow and to +/-0 on underflow.  No libm dependency. */
static double json_scale10(double m, int exp)
{
	enum { max_step = (int)ARRAY_SIZE(json_pow10) - 1 };
	while (exp > 0) {
		const int step = exp < max_step ? exp : max_step;
		m *= json_pow10[step];
		if (m > DBL_MAX || m < -DBL_MAX) {
			return m; /* saturated to +/-inf */
		}
		exp -= step;
	}
	while (exp < 0) {
		const int step = -exp < max_step ? -exp : max_step;
		m /= json_pow10[step];
		if (m == 0.0) {
			return m; /* underflow to +/-0 */
		}
		exp += step;
	}
	return m;
}

/* json_strtod: locale-independent conversion of a JSON number token (as
 * produced by scan_number) into a double.  s[0..len-1] need not be
 * NUL-terminated.  Returns false if the token is not a valid number.
 * Up to 19 significant decimal digits are accumulated into a 64-bit mantissa;
 * any excess digits adjust the base-10 exponent instead. */
static bool
json_strtod(const char *restrict s, const size_t len, double *restrict out)
{
	size_t i = 0;
	bool neg = false;
	if (i < len && s[i] == '-') {
		neg = true;
		i++;
	}
	if (i >= len || !isdigit((unsigned char)s[i])) {
		return false;
	}
	uint_fast64_t mant = 0;
	int sig = 0; /* significant digits captured in mant (max 19) */
	int exp10 = 0; /* base-10 exponent of mant, clamped to ±100000 */
	bool seen_nonzero = false;
	/* integer part */
	while (i < len && isdigit((unsigned char)s[i])) {
		const unsigned d = (unsigned)(s[i] - '0');
		i++;
		if (d == 0 && !seen_nonzero) {
			continue; /* skip leading zeros */
		}
		seen_nonzero = true;
		if (sig < 19) {
			mant = mant * 10 + d;
			sig++;
		} else if (exp10 < 100000) {
			exp10++; /* digit too significant to keep */
		}
	}
	/* fractional part */
	if (i < len && s[i] == '.') {
		i++;
		if (i >= len || !isdigit((unsigned char)s[i])) {
			return false;
		}
		while (i < len && isdigit((unsigned char)s[i])) {
			const unsigned d = (unsigned)(s[i] - '0');
			i++;
			if (d == 0 && !seen_nonzero) {
				if (exp10 > -100000) {
					exp10--; /* leading fractional zero */
				}
				continue;
			}
			seen_nonzero = true;
			if (sig < 19) {
				mant = mant * 10 + d;
				sig++;
				exp10--;
			}
			/* else: drop insignificant fractional digit */
		}
	}
	/* exponent part */
	if (i < len && (s[i] == 'e' || s[i] == 'E')) {
		i++;
		bool eneg = false;
		if (i < len && (s[i] == '+' || s[i] == '-')) {
			eneg = (s[i] == '-');
			i++;
		}
		if (i >= len || !isdigit((unsigned char)s[i])) {
			return false;
		}
		int e = 0;
		while (i < len && isdigit((unsigned char)s[i])) {
			if (e < 100000) {
				e = e * 10 + (int)(s[i] - '0');
			}
			i++;
		}
		exp10 += eneg ? -e : e;
	}
	if (i != len) {
		return false;
	}
	const double m = json_scale10((double)mant, exp10);
	*out = neg ? -m : m;
	return true;
}

bool json_parse_double(char *val, size_t vlen, double *out)
{
	size_t pos = vlen;
	const struct json_val nv = json_parse(val, &pos);
	if (nv.type != JSON_NUMBER || !json_rest_is_ws(val, pos, vlen)) {
		return false;
	}
	return json_strtod(nv.str, nv.len, out);
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
		return (int)need - 1; /* snprintf semantics: exclude NUL */
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
			if (pos + 7 <= bufsz) {
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
	if (bufsz > 0) {
		buf[pos < bufsz ? pos : bufsz - 1] = '\0';
	}
	pos++;
	return (int)pos - 1; /* snprintf semantics: exclude NUL */
}

/* -------------------------------------------------------------------------
 * Object and array iterators
 * ---------------------------------------------------------------------- */

/* Advance past whitespace and an optional ',' separator.
 * Returns 0 if buffer exhausted, 1 if content follows without a comma,
 * 2 if a comma was consumed.  json[*i] is ready when non-zero. */
static int skip_delim(const char *restrict json, size_t len, size_t *restrict i)
{
	while (*i < len && json_iswhitespace(json[*i])) {
		(*i)++;
	}
	if (*i >= len) {
		return 0;
	}
	if (json[*i] == ',') {
		(*i)++;
		while (*i < len && json_iswhitespace(json[*i])) {
			(*i)++;
		}
		return 2;
	}
	return 1;
}

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
	{
		const size_t nlen = scan_number(buf, len);
		return nlen ? (ptrdiff_t)nlen : -1;
	}
}

int json_obj_next(
	char *restrict json, const size_t *len, json_iter *restrict iter,
	char **restrict key, size_t *restrict key_len, char **restrict val,
	size_t *restrict val_len)
{
	const size_t buflen = *len;
	size_t i = *iter;
	const int delim = skip_delim(json, buflen, &i);
	if (delim == 0) {
		LOGE("jsonutil: unterminated object");
		return JSON_NEXT_ERROR;
	}
	if (i >= buflen) {
		LOGE("jsonutil: unterminated object");
		return JSON_NEXT_ERROR;
	}
	if (json[i] == '}') {
		if (delim == 2) {
			LOGE("jsonutil: trailing comma in object");
			return JSON_NEXT_ERROR;
		}
		*iter = i + 1;
		return JSON_NEXT_END;
	}
	if (i >= buflen || json[i] != '"') {
		LOGE("jsonutil: expected object key string");
		return JSON_NEXT_ERROR;
	}
	size_t slen, consumed;
	if (!scan_string_inplace(
		    json + i + 1, buflen - i - 1, &slen, &consumed)) {
		return JSON_NEXT_ERROR;
	}
	*key = json + i + 1;
	*key_len = slen;
	i += 1 + consumed;
	while (i < buflen && json_iswhitespace(json[i])) {
		i++;
	}
	if (i >= buflen || json[i] != ':') {
		LOGE("jsonutil: expected ':' after object key");
		return JSON_NEXT_ERROR;
	}
	i++;
	while (i < buflen && json_iswhitespace(json[i])) {
		i++;
	}
	if (i >= buflen) {
		LOGE("jsonutil: expected value after ':'");
		return JSON_NEXT_ERROR;
	}
	const ptrdiff_t vlen = skip_raw_value(json + i, buflen - i);
	if (vlen < 0) {
		LOGE("jsonutil: invalid JSON value");
		return JSON_NEXT_ERROR;
	}
	*val = json + i;
	*val_len = (size_t)vlen;
	*iter = i + (size_t)vlen;
	return JSON_NEXT_ITEM;
}

int json_arr_next(
	char *restrict json, const size_t *len, json_iter *restrict iter,
	char **restrict val, size_t *restrict val_len)
{
	const size_t buflen = *len;
	size_t i = *iter;
	const int delim = skip_delim(json, buflen, &i);
	if (delim == 0) {
		LOGE("jsonutil: unterminated array");
		return JSON_NEXT_ERROR;
	}
	if (i >= buflen) {
		LOGE("jsonutil: unterminated array");
		return JSON_NEXT_ERROR;
	}
	if (json[i] == ']') {
		if (delim == 2) {
			LOGE("jsonutil: trailing comma in array");
			return JSON_NEXT_ERROR;
		}
		*iter = i + 1;
		return JSON_NEXT_END;
	}
	if (i >= buflen) {
		LOGE("jsonutil: expected array element");
		return JSON_NEXT_ERROR;
	}
	const ptrdiff_t vlen = skip_raw_value(json + i, buflen - i);
	if (vlen < 0) {
		LOGE("jsonutil: invalid JSON value in array");
		return JSON_NEXT_ERROR;
	}
	*val = json + i;
	*val_len = (size_t)vlen;
	*iter = i + (size_t)vlen;
	return JSON_NEXT_ITEM;
}

/* -------------------------------------------------------------------------
 * Table-driven codec
 * ---------------------------------------------------------------------- */

/* json_isfinite: libm-free finite test, matching the <float.h> style used by
 * json_scale10 so codec/json.c needs no <math.h> / libm dependency. */
static bool json_isfinite(double v)
{
	return v == v && v <= DBL_MAX && v >= -DBL_MAX;
}

/* json_fmod: libm-free remainder of x divided by y for finite x and finite
 * y > 0; returns a value with the sign of x and magnitude < y.  Exact in
 * IEEE-754 (classic shift-and-subtract), used only for multipleOf on doubles. */
static double json_fmod(double x, double y)
{
	bool neg = false;
	if (x < 0) {
		x = -x;
		neg = true;
	}
	if (x < y) {
		return neg ? -x : x;
	}
	double yy = y;
	while (yy <= x / 2.0) {
		yy *= 2.0;
	}
	while (yy >= y) {
		if (x >= yy) {
			x -= yy;
		}
		yy /= 2.0;
	}
	return neg ? -x : x;
}

/* json_elem_size: size of one array element for a field of the given kind. */
static size_t json_elem_size(const struct json_field *restrict f)
{
	switch (f->kind) {
	case JSON_K_STRING:
	case JSON_K_DYNAMIC:
		return sizeof(struct json_string);
	case JSON_K_INT:
		return sizeof(int);
	case JSON_K_IMAX:
		return sizeof(intmax_t);
	case JSON_K_UINT:
		return sizeof(unsigned);
	case JSON_K_UMAX:
		return sizeof(uintmax_t);
	case JSON_K_DOUBLE:
		return sizeof(double);
	case JSON_K_BOOL:
		return sizeof(bool);
	case JSON_K_OBJECT:
		return f->child->obj_size;
	}
	return 0;
}

/* json_free_array: release the heap owned by array elements (object elements
 * recurse; primitive and string elements own nothing). */
static void
json_free_array(const struct json_field *restrict f, void *base, size_t count)
{
	if (f->kind != JSON_K_OBJECT || base == NULL) {
		return;
	}
	char *const p = base;
	const size_t sz = f->child->obj_size;
	for (size_t i = 0; i < count; i++) {
		json_free(f->child, p + i * sz);
	}
}

void json_free(const struct json_schema *restrict schema, void *obj)
{
	char *const base = obj;
	for (size_t fi = 0; fi < schema->n_fields; fi++) {
		const struct json_field *const f = &schema->fields[fi];
		if (f->is_array) {
			void **const pp = (void **)(base + f->offset);
			size_t *const pc = (size_t *)(base + f->count_offset);
			json_free_array(f, *pp, *pc);
			free(*pp);
			*pp = NULL;
			*pc = 0;
		} else if (f->kind == JSON_K_OBJECT) {
			json_free(f->child, base + f->offset);
		}
	}
}

/* --- constraint checks ------------------------------------------------- */

static bool json_in_imax(const intmax_t *a, size_t n, intmax_t v)
{
	for (size_t i = 0; i < n; i++) {
		if (a[i] == v) {
			return true;
		}
	}
	return false;
}

static bool json_in_umax(const uintmax_t *a, size_t n, uintmax_t v)
{
	for (size_t i = 0; i < n; i++) {
		if (a[i] == v) {
			return true;
		}
	}
	return false;
}

static bool json_in_double(const double *a, size_t n, double v)
{
	for (size_t i = 0; i < n; i++) {
		if (a[i] == v) {
			return true;
		}
	}
	return false;
}

static bool
json_check_str(const struct json_constraint *c, const char *s, size_t len)
{
	if ((c->flags & JSON_C_MIN_LEN) && len < c->str.min_len) {
		return false;
	}
	if ((c->flags & JSON_C_MAX_LEN) && len > c->str.max_len) {
		return false;
	}
	if ((c->flags & JSON_C_CONST) &&
	    (len != c->str.konst.len ||
	     memcmp(s, c->str.konst.str, len) != 0)) {
		return false;
	}
	if (c->flags & JSON_C_ENUM) {
		bool ok = false;
		for (size_t i = 0; i < c->str.n_enum; i++) {
			if (len == c->str.enums[i].len &&
			    memcmp(s, c->str.enums[i].str, len) == 0) {
				ok = true;
				break;
			}
		}
		if (!ok) {
			return false;
		}
	}
	return true;
}

static bool json_check_int(const struct json_constraint *c, intmax_t v)
{
	if ((c->flags & JSON_C_MIN) && v < c->i.min) {
		return false;
	}
	if ((c->flags & JSON_C_MAX) && v > c->i.max) {
		return false;
	}
	if ((c->flags & JSON_C_EXCL_MIN) && v <= c->i.excl_min) {
		return false;
	}
	if ((c->flags & JSON_C_EXCL_MAX) && v >= c->i.excl_max) {
		return false;
	}
	if ((c->flags & JSON_C_MULT) && (v % c->i.mult) != 0) {
		return false;
	}
	if ((c->flags & JSON_C_CONST) && v != c->i.konst) {
		return false;
	}
	if ((c->flags & JSON_C_ENUM) &&
	    !json_in_imax(c->i.enums, c->i.n_enum, v)) {
		return false;
	}
	return true;
}

static bool json_check_uint(const struct json_constraint *c, uintmax_t v)
{
	if ((c->flags & JSON_C_MIN) && v < c->u.min) {
		return false;
	}
	if ((c->flags & JSON_C_MAX) && v > c->u.max) {
		return false;
	}
	if ((c->flags & JSON_C_EXCL_MIN) && v <= c->u.excl_min) {
		return false;
	}
	if ((c->flags & JSON_C_EXCL_MAX) && v >= c->u.excl_max) {
		return false;
	}
	if ((c->flags & JSON_C_MULT) && (v % c->u.mult) != 0) {
		return false;
	}
	if ((c->flags & JSON_C_CONST) && v != c->u.konst) {
		return false;
	}
	if ((c->flags & JSON_C_ENUM) &&
	    !json_in_umax(c->u.enums, c->u.n_enum, v)) {
		return false;
	}
	return true;
}

static bool json_check_double(const struct json_constraint *c, double v)
{
	if ((c->flags & JSON_C_MIN) && v < c->d.min) {
		return false;
	}
	if ((c->flags & JSON_C_MAX) && v > c->d.max) {
		return false;
	}
	if ((c->flags & JSON_C_EXCL_MIN) && v <= c->d.excl_min) {
		return false;
	}
	if ((c->flags & JSON_C_EXCL_MAX) && v >= c->d.excl_max) {
		return false;
	}
	if ((c->flags & JSON_C_MULT) && json_fmod(v, c->d.mult) != 0.0) {
		return false;
	}
	if ((c->flags & JSON_C_CONST) && v != c->d.konst) {
		return false;
	}
	if ((c->flags & JSON_C_ENUM) &&
	    !json_in_double(c->d.enums, c->d.n_enum, v)) {
		return false;
	}
	return true;
}

static bool json_check_bool(const struct json_constraint *c, bool v)
{
	if ((c->flags & JSON_C_CONST) && v != (c->b.konst != 0)) {
		return false;
	}
	return true;
}

/* json_parse_scalar: parse one scalar JSON fragment into *slot per the field
 * kind, then validate it against the field's constraint (if any). */
static bool json_parse_scalar(
	const struct json_field *restrict f, void *slot, char *val, size_t vlen)
{
	const struct json_constraint *const c = f->constraint;
	switch (f->kind) {
	case JSON_K_STRING: {
		struct json_string *const js = slot;
		if (!json_parse_string(val, vlen, &js->str, &js->len)) {
			return false;
		}
		return c == NULL || json_check_str(c, js->str, js->len);
	}
	case JSON_K_INT: {
		int *const p = slot;
		if (!json_parse_int(val, vlen, p)) {
			return false;
		}
		return c == NULL || json_check_int(c, *p);
	}
	case JSON_K_IMAX: {
		intmax_t *const p = slot;
		if (!json_parse_imax(val, vlen, p)) {
			return false;
		}
		return c == NULL || json_check_int(c, *p);
	}
	case JSON_K_UINT: {
		unsigned *const p = slot;
		if (!json_parse_uint(val, vlen, p)) {
			return false;
		}
		return c == NULL || json_check_uint(c, *p);
	}
	case JSON_K_UMAX: {
		uintmax_t *const p = slot;
		if (!json_parse_umax(val, vlen, p)) {
			return false;
		}
		return c == NULL || json_check_uint(c, *p);
	}
	case JSON_K_DOUBLE: {
		double *const p = slot;
		if (!json_parse_double(val, vlen, p)) {
			return false;
		}
		return c == NULL || json_check_double(c, *p);
	}
	case JSON_K_BOOL: {
		bool *const p = slot;
		if (!json_parse_bool(val, vlen, p)) {
			return false;
		}
		return c == NULL || json_check_bool(c, *p);
	}
	case JSON_K_OBJECT:
	case JSON_K_DYNAMIC:
		break;
	}
	return false;
}

/* json_unmarshal_array: parse a JSON array fragment into a freshly allocated
 * buffer (element pointer/count returned via out params).  Enforces
 * minItems/maxItems and per-item constraints; cleans up on any failure. */
static bool json_unmarshal_array(
	const struct json_field *restrict f, char *val, size_t vlen,
	void **out_buf, size_t *out_count)
{
	size_t buflen = vlen;
	const struct json_val arr = json_parse(val, &buflen);
	if (arr.type != JSON_ARRAY) {
		return false;
	}
	const struct json_constraint *const c = f->constraint;
	const size_t esz = json_elem_size(f);
	char *buf = NULL;
	size_t count = 0, cap = 0;
	json_iter it = arr.iter;
	char *av;
	size_t alen;
	int next;
	while ((next = json_arr_next(val, &vlen, &it, &av, &alen)) ==
	       JSON_NEXT_ITEM) {
		if (c != NULL && (c->flags & JSON_C_MAX_ITEMS) &&
		    count >= c->max_items) {
			goto fail;
		}
		if (count >= cap) {
			const size_t nc = cap ? cap * 2 : 4;
			char *const nb = realloc(buf, nc * esz);
			if (nb == NULL) {
				goto fail;
			}
			buf = nb;
			cap = nc;
		}
		void *const slot = buf + count * esz;
		memset(slot, 0, esz);
		if (f->kind == JSON_K_OBJECT) {
			if (!json_unmarshal(f->child, slot, av, alen)) {
				goto fail;
			}
		} else if (!json_parse_scalar(f, slot, av, alen)) {
			goto fail;
		}
		count++;
	}
	if (next != JSON_NEXT_END) {
		goto fail;
	}
	for (; it < vlen; it++) {
		if (!json_iswhitespace((unsigned char)val[it])) {
			goto fail;
		}
	}
	if (c != NULL && (c->flags & JSON_C_MIN_ITEMS) &&
	    count < c->min_items) {
		goto fail;
	}
	*out_buf = buf;
	*out_count = count;
	return true;

fail:
	json_free_array(f, buf, count);
	free(buf);
	return false;
}

bool json_unmarshal(
	const struct json_schema *restrict schema, void *obj, char *json,
	size_t length)
{
	char *const base = obj;
	if (schema->defaults != NULL) {
		memcpy(base, schema->defaults, schema->obj_size);
	} else {
		memset(base, 0, schema->obj_size);
	}
	size_t buflen = length;
	const struct json_val root = json_parse(json, &buflen);
	if (root.type != JSON_OBJECT) {
		return false;
	}
	json_iter iter = root.iter;
	char *key;
	char *val;
	size_t key_len;
	size_t val_len;
	uint_fast64_t required = 0;
	int next;
	while ((next = json_obj_next(
			json, &length, &iter, &key, &key_len, &val,
			&val_len)) == JSON_NEXT_ITEM) {
		const int k = schema->lookup(key, key_len);
		if (k < 0 || (size_t)k >= schema->n_fields) {
			if (schema->strict) {
				goto fail;
			}
			continue;
		}
		const struct json_field *const f = &schema->fields[k];
		void *const slot = base + f->offset;
		if (f->is_array) {
			void *nbuf;
			size_t ncount;
			if (!json_unmarshal_array(
				    f, val, val_len, &nbuf, &ncount)) {
				goto fail;
			}
			/* duplicate key: release any previous allocation */
			void **const pp = (void **)slot;
			size_t *const pc = (size_t *)(base + f->count_offset);
			json_free_array(f, *pp, *pc);
			free(*pp);
			*pp = nbuf;
			*pc = ncount;
		} else if (f->kind == JSON_K_OBJECT) {
			/* duplicate key: release the previous value first */
			json_free(f->child, slot);
			if (!json_unmarshal(f->child, slot, val, val_len)) {
				goto fail;
			}
		} else if (f->kind == JSON_K_DYNAMIC) {
			struct json_string *const js = slot;
			js->str = val;
			js->len = val_len;
		} else if (!json_parse_scalar(f, slot, val, val_len)) {
			goto fail;
		}
		if (f->req_bit >= 0) {
			required |= (uint_fast64_t)1 << f->req_bit;
		}
	}
	if (next != JSON_NEXT_END) {
		goto fail;
	}
	if (required != schema->required_mask) {
		goto fail;
	}
	for (; iter < length; iter++) {
		if (!json_iswhitespace((unsigned char)json[iter])) {
			goto fail;
		}
	}
	return true;

fail:
	json_free(schema, obj);
	memset(base, 0, schema->obj_size);
	return false;
}

/* --- marshal ----------------------------------------------------------- */

static int json_emit_ch(char *buf, size_t bufsz, int n, char c)
{
	if (buf != NULL && (size_t)n < bufsz) {
		buf[n] = c;
	}
	return n + 1;
}

static int
json_emit_raw(char *buf, size_t bufsz, int n, const char *s, size_t len)
{
	if (buf != NULL && (size_t)n < bufsz) {
		const size_t cap = bufsz - (size_t)n;
		memcpy(buf + n, s, len < cap ? len : cap);
	}
	return n + (int)len;
}

static int
json_emit_str(char *buf, size_t bufsz, int n, const char *s, size_t len)
{
	char *const dst = (buf != NULL && (size_t)n < bufsz) ? buf + n : NULL;
	const int r = json_marshal_string(
		dst, dst != NULL ? bufsz - (size_t)n : 0, s, len);
	if (r < 0) {
		return -1;
	}
	return n + r;
}

static int json_emit_indent(
	char *buf, size_t bufsz, int n, const char *indent, size_t ind_len,
	int d)
{
	if (indent == NULL) {
		return n;
	}
	n = json_emit_ch(buf, bufsz, n, '\n');
	for (int i = 0; i < d; i++) {
		n = json_emit_raw(buf, bufsz, n, indent, ind_len);
	}
	return n;
}

static int json_marshal_impl(
	const struct json_schema *restrict schema, char *buf, size_t bufsz,
	const void *obj, const char *indent, size_t ind_len, int depth);

/* json_emit_value: emit one field value (no key, no array brackets) of the
 * field's element kind.  Returns the new length, or -1 on error. */
static int json_emit_value(
	const struct json_field *restrict f, char *buf, size_t bufsz, int n,
	const void *slot, const char *indent, size_t ind_len, int depth)
{
	char tmp[32];
	int r;
	switch (f->kind) {
	case JSON_K_STRING: {
		const struct json_string *const js = slot;
		return json_emit_str(buf, bufsz, n, js->str, js->len);
	}
	case JSON_K_DYNAMIC: {
		const struct json_string *const js = slot;
		return json_emit_raw(buf, bufsz, n, js->str, js->len);
	}
	case JSON_K_INT:
		r = snprintf(tmp, sizeof(tmp), "%d", *(const int *)slot);
		break;
	case JSON_K_IMAX:
		r = snprintf(tmp, sizeof(tmp), "%jd", *(const intmax_t *)slot);
		break;
	case JSON_K_UINT:
		r = snprintf(tmp, sizeof(tmp), "%u", *(const unsigned *)slot);
		break;
	case JSON_K_UMAX:
		r = snprintf(tmp, sizeof(tmp), "%ju", *(const uintmax_t *)slot);
		break;
	case JSON_K_DOUBLE: {
		const double v = *(const double *)slot;
		/* NaN/Inf have no JSON representation */
		if (!json_isfinite(v)) {
			return -1;
		}
		r = snprintf(tmp, sizeof(tmp), "%.17g", v);
		break;
	}
	case JSON_K_BOOL:
		return *(const bool *)slot ?
			       json_emit_raw(buf, bufsz, n, "true", 4) :
			       json_emit_raw(buf, bufsz, n, "false", 5);
	case JSON_K_OBJECT: {
		char *const dst =
			(buf != NULL && (size_t)n < bufsz) ? buf + n : NULL;
		r = json_marshal_impl(
			f->child, dst, dst != NULL ? bufsz - (size_t)n : 0,
			slot, indent, ind_len, depth);
		if (r < 0) {
			return -1;
		}
		return n + r;
	}
	default:
		return -1;
	}
	if (r < 0) {
		return -1;
	}
	return json_emit_raw(buf, bufsz, n, tmp, (size_t)r);
}

static int json_marshal_impl(
	const struct json_schema *restrict schema, char *buf, size_t bufsz,
	const void *obj, const char *indent, size_t ind_len, int depth)
{
	const char *const base = obj;
	int n = 0;
	n = json_emit_ch(buf, bufsz, n, '{');
	const int n_start = n;
	for (size_t fi = 0; fi < schema->n_fields; fi++) {
		const struct json_field *const f = &schema->fields[fi];
		const void *const slot = base + f->offset;

		/* presence: scalars always emit; NULL marks an absent string,
		 * array, dynamic fragment, or optional nested object (via its
		 * sentinel sub-field). */
		bool emit = true;
		if (f->is_array) {
			emit = f->req_bit >= 0 ||
			       *(const void *const *)slot != NULL;
		} else if (f->kind == JSON_K_STRING || f->kind == JSON_K_DYNAMIC) {
			emit = ((const struct json_string *)slot)->str != NULL;
		} else if (f->kind == JSON_K_OBJECT && f->req_bit < 0) {
			const int pf = f->child->present_field;
			if (pf >= 0) {
				const struct json_field *const sf =
					&f->child->fields[pf];
				const struct json_string *const js =
					(const struct json_string
						 *)((const char *)slot +
						    sf->offset);
				emit = js->str != NULL;
			}
		}
		if (!emit) {
			continue;
		}

		/* key prefix: <newline+indent>"key":<sep> */
		n = json_emit_indent(buf, bufsz, n, indent, ind_len, depth + 1);
		n = json_emit_ch(buf, bufsz, n, '"');
		n = json_emit_raw(buf, bufsz, n, f->name, f->name_len);
		n = json_emit_ch(buf, bufsz, n, '"');
		n = json_emit_ch(buf, bufsz, n, ':');
		if (indent != NULL) {
			n = json_emit_ch(buf, bufsz, n, ' ');
		}

		if (f->is_array) {
			const void *const arr = *(const void *const *)slot;
			const size_t cnt =
				*(const size_t *)(base + f->count_offset);
			const size_t esz = json_elem_size(f);
			n = json_emit_ch(buf, bufsz, n, '[');
			for (size_t i = 0; i < cnt; i++) {
				if (i > 0) {
					n = json_emit_ch(buf, bufsz, n, ',');
				}
				n = json_emit_indent(
					buf, bufsz, n, indent, ind_len,
					depth + 2);
				n = json_emit_value(
					f, buf, bufsz, n,
					(const char *)arr + i * esz, indent,
					ind_len, depth + 2);
				if (n < 0) {
					return -1;
				}
			}
			if (cnt > 0) {
				n = json_emit_indent(
					buf, bufsz, n, indent, ind_len,
					depth + 1);
			}
			n = json_emit_ch(buf, bufsz, n, ']');
		} else {
			n = json_emit_value(
				f, buf, bufsz, n, slot, indent, ind_len,
				depth + 1);
			if (n < 0) {
				return -1;
			}
		}
		n = json_emit_ch(buf, bufsz, n, ',');
	}

	/* strip the trailing comma of the last emitted field, then close on
	 * its own line aligned with this object's level (compact: no-op). */
	if (n > n_start) {
		n--;
		n = json_emit_indent(buf, bufsz, n, indent, ind_len, depth);
	}
	n = json_emit_ch(buf, bufsz, n, '}');
	if (buf != NULL && bufsz > 0) {
		buf[(size_t)n < bufsz ? (size_t)n : bufsz - 1] = '\0';
	}
	return n;
}

int json_marshal(
	const struct json_schema *restrict schema, char *buf, size_t bufsz,
	const void *obj, const char *indent)
{
	const size_t ind_len = (indent != NULL) ? strlen(indent) : 0;
	return json_marshal_impl(schema, buf, bufsz, obj, indent, ind_len, 0);
}
