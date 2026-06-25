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
