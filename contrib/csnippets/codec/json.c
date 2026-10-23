/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "json.h"

#include "math/float.h"
#include "strings/string.h"
#include "strings/utf8.h"
#include "utils/ctype_ascii.h"
#include "utils/slog.h"

#include <assert.h>
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
#include <uchar.h>

/* log_char: the input is untrusted and slog does no escaping, so a logged
 * input byte is echoed only when it is printable ASCII; any other byte (NUL, a
 * control byte, LF/CR that would split the line, non-ASCII) shows as '?', and
 * the message carries its hex value beside it. */
static char log_char(const unsigned char c)
{
	return isprint(c) ? (char)c : '?';
}

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

/* check_escape: validate the escape sequence at s[0] == '\\' against RFC 8259,
 * decoding it to a single Unicode code point in *cp.  len is the bytes available
 * from the backslash.  Returns the input bytes consumed (>= 2), or 0 on a
 * malformed escape (logged).  A high surrogate consumes its paired low
 * surrogate, so a '\\uXXXX' run can span 12 bytes. */
static size_t check_escape(
	const char *restrict s, const size_t len, uint_fast32_t *restrict cp)
{
	assert(len >= 1 && s[0] == '\\');
	if (len < 2) {
		LOGE("json: truncated escape sequence");
		return 0;
	}
	const unsigned char ec = (unsigned char)s[1];
	switch (ec) {
	case '"':
		*cp = '"';
		return 2;
	case '\\':
		*cp = '\\';
		return 2;
	case '/':
		*cp = '/';
		return 2;
	case 'b':
		*cp = '\b';
		return 2;
	case 'f':
		*cp = '\f';
		return 2;
	case 'n':
		*cp = '\n';
		return 2;
	case 'r':
		*cp = '\r';
		return 2;
	case 't':
		*cp = '\t';
		return 2;
	case 'u':
		break;
	default:
		LOGE_F("json: invalid escape '\\%c' (0x%02x)", log_char(ec),
		       (unsigned)ec);
		return 0;
	}
	/* \uXXXX */
	if (len < 6) {
		LOGE("json: truncated \\uXXXX escape");
		return 0;
	}
	uint_fast32_t hi;
	if (!parse_hex4(s + 2, &hi)) {
		LOGE("json: invalid \\uXXXX escape");
		return 0;
	}
	if (hi >= 0xD800 && hi <= 0xDBFF) {
		/* handle surrogate pair */
		if (len < 12 || s[6] != '\\' || s[7] != 'u') {
			LOGE("json: high surrogate without low surrogate");
			return 0;
		}
		uint_fast32_t low;
		if (!parse_hex4(s + 8, &low)) {
			LOGE("json: invalid low surrogate escape");
			return 0;
		}
		if (low < 0xDC00 || low > 0xDFFF) {
			LOGE("json: invalid surrogate pair");
			return 0;
		}
		*cp = 0x10000 + ((hi - 0xD800) << 10) + (low - 0xDC00);
		return 12;
	}
	if (hi >= 0xDC00 && hi <= 0xDFFF) {
		LOGE("json: lone low surrogate");
		return 0;
	}
	*cp = hi;
	return 6;
}

/* scan_string_inplace: decode a JSON string in-place; s starts just past the
 * opening '"'.  *consumed counts through the closing '"'; output length is
 * always <= input length.  Returns false (and logs) on error. */
static bool scan_string_inplace(
	char *restrict s, const size_t len, size_t *restrict out_slen,
	size_t *restrict consumed)
{
	size_t opos = 0;
	size_t i = 0;
	for (;;) {
		if (i >= len) {
			LOGE("json: unterminated string");
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
			LOGE("json: unescaped control character in string");
			return false;
		}
		if (c != '\\') {
			/* ASCII (already known to be >= 0x20 here) is always a
			 * complete, valid single-byte sequence -- skip the
			 * cross-TU validator call for the overwhelmingly
			 * common case and reserve it for actual multi-byte
			 * lead bytes. */
			if (c < 0x80) {
				s[opos++] = s[i++];
				continue;
			}
			const int n = utf8_decode(NULL, s + i, len - i);
			if (n == 0) {
				LOGE("json: invalid UTF-8 sequence in string");
				return false;
			}
			for (int j = 0; j < n; j++) {
				s[opos++] = s[i++];
			}
			continue;
		}
		/* escape sequence */
		uint_fast32_t cp;
		const size_t adv = check_escape(s + i, len - i, &cp);
		if (adv == 0) {
			return false;
		}
		/* utf8_encode wants UTF8_MAX_LEN of room whatever the
		 * codepoint, but the in-place window is only as wide as the
		 * escape being replaced -- 2 bytes for "\n" -- so encode aside */
		char unit[UTF8_MAX_LEN];
		const int nbytes = utf8_encode(unit, (char32_t)cp);
		if (nbytes <= 0) {
			LOGE("json: invalid Unicode codepoint");
			return false;
		}
		/* the encoded form is never longer than the escape it came
		 * from (2 -> 1 byte, 6 -> <= 3, 12 -> 4), and opos <= i, so
		 * the copy stays within the len bytes check_escape spanned */
		assert(opos + (size_t)nbytes <= len);
		memcpy(s + opos, unit, (size_t)nbytes);
		opos += (size_t)nbytes;
		i += adv;
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
	while (i < buflen && json_iswhitespace((unsigned char)json[i])) {
		i++;
	}
	if (i >= buflen) {
		LOGE("json: empty input");
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
		LOGE("json: invalid value 'n...'");
		break;
	case 't':
		if (buflen - i >= 4 && memcmp(json + i, "true", 4) == 0) {
			*len = i + 4;
			return (struct json_val){
				.type = JSON_BOOL,
				.b = true,
			};
		}
		LOGE("json: invalid value 't...'");
		break;
	case 'f':
		if (buflen - i >= 5 && memcmp(json + i, "false", 5) == 0) {
			*len = i + 5;
			return (struct json_val){
				.type = JSON_BOOL,
				.b = false,
			};
		}
		LOGE("json: invalid value 'f...'");
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
		LOGE_F("json: unexpected character '%c' (0x%02x)", log_char(c),
		       (unsigned)c);
		break;
	}
	}
	*len = i;
	return (struct json_val){ .type = JSON_ERROR };
}

/* One decimal digit per representation bit is a conservative bound for every
 * supported integer, with room for a sign and NUL. This also covers the
 * double formatter's 17 significant digits, sign, radix, and exponent. */
#define JSON_NUM_BUFSIZE (sizeof(uintmax_t) * CHAR_BIT + 2)

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

bool json_parse_string(
	char *restrict val, size_t vlen, char **restrict out,
	size_t *restrict outlen)
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

bool json_parse_bool(char *restrict val, size_t vlen, bool *restrict out)
{
	size_t pos = vlen;
	const struct json_val bv = json_parse(val, &pos);
	if (bv.type != JSON_BOOL || !json_rest_is_ws(val, pos, vlen)) {
		return false;
	}
	*out = bv.b;
	return true;
}

bool json_parse_int(char *restrict val, size_t vlen, int *restrict out)
{
	intmax_t n;
	if (!json_parse_imax(val, vlen, &n) || n < INT_MIN || n > INT_MAX) {
		return false;
	}
	*out = (int)n;
	return true;
}

bool json_parse_imax(char *restrict val, size_t vlen, intmax_t *restrict out)
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

bool json_parse_uint(char *restrict val, size_t vlen, unsigned *restrict out)
{
	uintmax_t n;
	if (!json_parse_umax(val, vlen, &n) || n > UINT_MAX) {
		return false;
	}
	*out = (unsigned)n;
	return true;
}

bool json_parse_umax(char *restrict val, size_t vlen, uintmax_t *restrict out)
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

/* json_isfinite: libm-free finite test against the <float.h> bounds, so
 * codec/json.c needs no <math.h> / libm dependency. */
static bool json_isfinite(double v)
{
	return v == v && v <= DBL_MAX && v >= -DBL_MAX;
}

/* json_strtod: locale-independent conversion of a JSON number token (as
 * produced by scan_number) into the nearest double, with ties to even.
 * Integer-based float_fromdecimal keeps that policy independent of the caller's
 * rounding mode. Underflow to a subnormal or signed zero remains a success;
 * overflow to infinity fails. The bounded significant digit buffer retains a
 * nonzero guard for any dropped tail so ties still round on the correct side.
 * s[0..len-1] need not be NUL-terminated. */
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
	char digits[FLOAT_ROUND_DIGITS + 1];
	int ndig = 0; /* significant digits captured in digits[] */
	int_fast64_t exp10 =
		0; /* base-10 exponent of digits[] read as integer */
	bool seen_nonzero = false;
	bool nonzero_dropped = false;
	/* integer part */
	while (i < len && isdigit((unsigned char)s[i])) {
		const unsigned d = (unsigned)(s[i] - '0');
		i++;
		if (d == 0 && !seen_nonzero) {
			continue; /* skip leading zeros */
		}
		seen_nonzero = true;
		if (ndig < FLOAT_ROUND_DIGITS) {
			digits[ndig++] = (char)('0' + d);
		} else {
			exp10++; /* digit retained only as magnitude */
			nonzero_dropped = nonzero_dropped || d != 0;
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
				exp10--; /* leading fractional zero */
				continue;
			}
			seen_nonzero = true;
			if (ndig < FLOAT_ROUND_DIGITS) {
				digits[ndig++] = (char)('0' + d);
				exp10--;
			} else {
				nonzero_dropped = nonzero_dropped || d != 0;
			}
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
		int_fast64_t e = 0;
		while (i < len && isdigit((unsigned char)s[i])) {
			if (e < 1000000000) {
				e = e * 10 + (s[i] - '0');
			}
			i++;
		}
		exp10 += eneg ? -e : e;
	}
	if (i != len) {
		return false;
	}
	if (!seen_nonzero) {
		*out = neg ? -0.0 : 0.0;
		return true;
	}
	if (nonzero_dropped) {
		digits[ndig++] = '1';
		exp10--;
	}
	/* float_fromdecimal takes the exponent of 0.<digits>, rather than
	 * that of the integer significand. Extreme exponents need only retain
	 * their direction: the converter saturates outside binary64's range. */
	const int_fast64_t k = exp10 + ndig;
	int exp;
	if (k > INT_MAX) {
		exp = INT_MAX;
	} else if (k < INT_MIN) {
		exp = INT_MIN;
	} else {
		exp = (int)k;
	}
	const double m = float_fromdecimal(digits, ndig, exp);
	if (!json_isfinite(m)) {
		return false; /* magnitude overflows the double range */
	}
	*out = neg ? -m : m;
	return true;
}

bool json_parse_double(char *restrict val, size_t vlen, double *restrict out)
{
	size_t pos = vlen;
	const struct json_val nv = json_parse(val, &pos);
	if (nv.type != JSON_NUMBER || !json_rest_is_ws(val, pos, vlen)) {
		return false;
	}
	return json_strtod(nv.str, nv.len, out);
}

/* -------------------------------------------------------------------------
 * json_marshal_string
 * ---------------------------------------------------------------------- */

/* Clamp an internal size_t byte count to the public snprintf-style int
 * return, treating an unrepresentable or error-sentinel (SIZE_MAX) value
 * as failure rather than silently wrapping. */
static int marshal_checked_int(const size_t n)
{
	if (n > (size_t)INT_MAX) {
		return -1;
	}
	return (int)n;
}

/* Write a 2-byte "\X" escape at pos, one byte at a time so a truncated
 * write never skips a byte that does fit while leaving it uninitialized. */
static void marshal_escape2(
	char *restrict buf, const size_t bufsz, const size_t pos, const char c)
{
	if (pos < bufsz) {
		buf[pos] = '\\';
	}
	if (pos + 1 < bufsz) {
		buf[pos + 1] = c;
	}
}

int json_marshal_string(
	char *restrict buf, const size_t bufsz, const char *restrict s,
	const size_t len)
{
	/* two-pass: first pass counts and validates, second pass writes */
	size_t need = 2; /* opening and closing quotes */
	for (size_t i = 0; i < len;) {
		const unsigned char c = (unsigned char)s[i];
		if (c == '"' || c == '\\' || c == '\b' || c == '\f' ||
		    c == '\n' || c == '\r' || c == '\t') {
			need += 2;
			i++;
		} else if (c < 0x20) {
			need += 6; /* \uXXXX */
			i++;
		} else if (c < 0x80) {
			need += 1;
			i++;
		} else {
			/* RFC 8259 §7/§8.1 admit only UTF-8-encoded Unicode; an
			 * ill-formed sequence has neither a verbatim nor a
			 * \uXXXX form, so refuse what this codec cannot read
			 * back rather than emit it */
			const int n = utf8_decode(NULL, s + i, len - i);
			if (n == 0) {
				LOGE("json: invalid UTF-8 sequence in string");
				return -1;
			}
			need += (size_t)n;
			i += (size_t)n;
		}
		/* Stop as soon as the count passes what the int return can
		 * represent -- the answer is -1 from here on regardless. Testing
		 * every step is also what keeps need from wrapping: from a value
		 * no greater than INT_MAX, one more escape adds at most 6, which
		 * cannot carry past SIZE_MAX even where the two are the same
		 * width. Without this the counter wrapped to a small positive
		 * value and marshal_checked_int, which exists to catch exactly
		 * that, never fired. */
		if (need > (size_t)INT_MAX) {
			return -1;
		}
	}
	need += 1; /* NUL terminator */

	if (buf == NULL) {
		/* snprintf semantics: exclude NUL */
		return marshal_checked_int(need - 1);
	}

	size_t pos = 0;
	if (bufsz > 0 && pos < bufsz) {
		buf[pos] = '"';
	}
	pos++;
	for (size_t i = 0; i < len; i++) {
		const unsigned char c = (unsigned char)s[i];
		if (c == '"') {
			marshal_escape2(buf, bufsz, pos, '"');
			pos += 2;
		} else if (c == '\\') {
			marshal_escape2(buf, bufsz, pos, '\\');
			pos += 2;
		} else if (c == '\b') {
			marshal_escape2(buf, bufsz, pos, 'b');
			pos += 2;
		} else if (c == '\f') {
			marshal_escape2(buf, bufsz, pos, 'f');
			pos += 2;
		} else if (c == '\n') {
			marshal_escape2(buf, bufsz, pos, 'n');
			pos += 2;
		} else if (c == '\r') {
			marshal_escape2(buf, bufsz, pos, 'r');
			pos += 2;
		} else if (c == '\t') {
			marshal_escape2(buf, bufsz, pos, 't');
			pos += 2;
		} else if (c < 0x20) {
			/* let snprintf truncate on its own, matching every
			 * other branch here instead of skipping the write
			 * (and leaving a gap) whenever the full 6 bytes
			 * don't fit */
			if (pos < bufsz) {
				const int n = snprintf(
					buf + pos, bufsz - pos, "\\u%04x",
					(unsigned)c);
				(void)n;
				assert(n == 6);
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
	/* snprintf semantics: exclude NUL */
	return marshal_checked_int(pos - 1);
}

/* -------------------------------------------------------------------------
 * Object and array iterators
 * ---------------------------------------------------------------------- */

/* Advance past whitespace and an optional ',' separator.
 * Returns 0 if buffer exhausted, 1 if content follows without a comma,
 * 2 if a comma was consumed and content follows.  json[*i] is ready when
 * non-zero. */
static int skip_delim(const char *restrict json, size_t len, size_t *restrict i)
{
	while (*i < len && json_iswhitespace((unsigned char)json[*i])) {
		(*i)++;
	}
	if (*i >= len) {
		return 0;
	}
	if (json[*i] == ',') {
		(*i)++;
		while (*i < len && json_iswhitespace((unsigned char)json[*i])) {
			(*i)++;
		}
		if (*i >= len) {
			return 0;
		}
		return 2;
	}
	return 1;
}

/* scan_string_raw: validate the JSON string at s[0] == '"' against RFC 8259
 * without decoding it, returning the byte length through the closing '"', or -1
 * on error.  Enforces the same grammar as scan_string_inplace -- escape
 * sequences, control-byte rejection, and UTF-8 well-formedness -- but leaves the
 * bytes untouched, so a raw fragment can be stored or re-emitted verbatim. */
static ptrdiff_t scan_string_raw(const char *restrict s, const size_t len)
{
	size_t i = 1;
	for (;;) {
		if (i >= len) {
			LOGE("json: unterminated string");
			return -1;
		}
		const unsigned char c = (unsigned char)s[i];
		if (c == '"') {
			return (ptrdiff_t)(i + 1);
		}
		if (c < 0x20) {
			LOGE("json: unescaped control character in string");
			return -1;
		}
		if (c == '\\') {
			uint_fast32_t cp;
			const size_t adv = check_escape(s + i, len - i, &cp);
			if (adv == 0) {
				return -1;
			}
			i += adv;
			continue;
		}
		if (c < 0x80) {
			i++;
			continue;
		}
		const int n = utf8_decode(NULL, s + i, len - i);
		if (n == 0) {
			LOGE("json: invalid UTF-8 sequence in string");
			return -1;
		}
		i += (size_t)n;
	}
}

/* scan_scalar: validate one non-container JSON value (string, number, or a
 * null/true/false literal) at buf[0] without decoding, returning its byte
 * length, or -1 on a syntax error. */
static ptrdiff_t scan_scalar(const char *restrict buf, const size_t len)
{
	switch ((unsigned char)buf[0]) {
	case 'n':
		if (len >= 4 && memcmp(buf, "null", 4) == 0) {
			return 4;
		}
		LOGE("json: invalid value 'n...'");
		return -1;
	case 't':
		if (len >= 4 && memcmp(buf, "true", 4) == 0) {
			return 4;
		}
		LOGE("json: invalid value 't...'");
		return -1;
	case 'f':
		if (len >= 5 && memcmp(buf, "false", 5) == 0) {
			return 5;
		}
		LOGE("json: invalid value 'f...'");
		return -1;
	case '"':
		return scan_string_raw(buf, len);
	default:
		break;
	}
	const size_t nlen = scan_number(buf, len);
	if (nlen == 0) {
		const unsigned char c = (unsigned char)buf[0];
		LOGE_F("json: unexpected character '%c' (0x%02x)", log_char(c),
		       (unsigned)c);
		return -1;
	}
	return (ptrdiff_t)nlen;
}

/* Scan one JSON value starting at buf[0] without decoding it, validating the
 * complete RFC 8259 value grammar and returning the value's byte length, or -1
 * on a syntax error.  A container is walked with an explicit stack of expected
 * closers -- not recursion whose depth the input would control -- so a '}' can
 * only close a '{' and a ']' only a '[', and the member/element grammar
 * (separators and the object "key":value structure) is checked at every level.
 * The stack is a fixed automatic array: RFC 8259 §9 permits a maximum nesting
 * depth, and input past the bound is a syntax error. */
static ptrdiff_t skip_raw_value(const char *restrict buf, const size_t len)
{
	enum { max_depth = 256 };
	/* the token expected next as the scanner advances */
	enum vstate {
		V_VALUE, /* a value (top level, or after ':') */
		V_ARR_ELEM, /* an array element, or ']' to close an empty array */
		V_ARR_ELEM_REQ, /* an array element after ',' (']' would trail) */
		V_OBJ_KEY, /* an object key, or '}' to close an empty object */
		V_OBJ_KEY_REQ, /* an object key after ',' ('}' would trail) */
		V_OBJ_COLON, /* ':' after an object key */
		V_AFTER, /* a value just completed; ',' or the closer follows */
	};
	unsigned char closer[max_depth];
	size_t depth = 0;
	size_t i = 0;
	enum vstate state = V_VALUE;
	for (;;) {
		while (i < len && json_iswhitespace((unsigned char)buf[i])) {
			i++;
		}
		if (i >= len) {
			LOGE("json: unterminated value");
			return -1;
		}
		const unsigned char c = (unsigned char)buf[i];
		switch (state) {
		case V_VALUE:
		case V_ARR_ELEM:
		case V_ARR_ELEM_REQ:
			if (state == V_ARR_ELEM && c == ']') {
				i++;
				depth--;
				if (depth == 0) {
					return (ptrdiff_t)i;
				}
				state = V_AFTER;
				break;
			}
			if (c == '{' || c == '[') {
				if (depth >= max_depth) {
					LOGE("json: nesting too deep");
					return -1;
				}
				closer[depth++] = (c == '[') ? ']' : '}';
				i++;
				state = (c == '[') ? V_ARR_ELEM : V_OBJ_KEY;
				break;
			}
			{
				const ptrdiff_t n =
					scan_scalar(buf + i, len - i);
				if (n < 0) {
					return -1;
				}
				i += (size_t)n;
			}
			if (depth == 0) {
				return (ptrdiff_t)i;
			}
			state = V_AFTER;
			break;
		case V_OBJ_KEY:
		case V_OBJ_KEY_REQ:
			if (state == V_OBJ_KEY && c == '}') {
				i++;
				depth--;
				if (depth == 0) {
					return (ptrdiff_t)i;
				}
				state = V_AFTER;
				break;
			}
			if (c != '"') {
				LOGE("json: expected object key string");
				return -1;
			}
			{
				const ptrdiff_t n =
					scan_string_raw(buf + i, len - i);
				if (n < 0) {
					return -1;
				}
				i += (size_t)n;
			}
			state = V_OBJ_COLON;
			break;
		case V_OBJ_COLON:
			if (c != ':') {
				LOGE("json: expected ':' after object key");
				return -1;
			}
			i++;
			state = V_VALUE;
			break;
		case V_AFTER:
			if (c == closer[depth - 1]) {
				i++;
				depth--;
				if (depth == 0) {
					return (ptrdiff_t)i;
				}
				break;
			}
			if (c == ',') {
				i++;
				state = (closer[depth - 1] == '}') ?
						V_OBJ_KEY_REQ :
						V_ARR_ELEM_REQ;
				break;
			}
			LOGE("json: expected ',' or closing bracket");
			return -1;
		}
	}
}

int json_obj_next(
	char *restrict json, const size_t *restrict len,
	json_iter *restrict iter, char **restrict key, size_t *restrict key_len,
	char **restrict val, size_t *restrict val_len)
{
	const size_t buflen = *len;
	const size_t start = *iter;
	size_t i = start;
	const int delim = skip_delim(json, buflen, &i);
	if (delim == 0) {
		LOGE("json: unterminated object");
		return JSON_NEXT_ERROR;
	}
	/* The cursor sits just past '{' on the first member and just past the
	 * previous value otherwise; a JSON value never ends in '{', so the byte
	 * before the cursor is '{' exactly on the first member. A comma must
	 * separate members and must not precede the first. */
	const bool first = (start >= 1 && json[start - 1] == '{');
	if (json[i] == '}') {
		if (delim == 2) {
			LOGE("json: trailing comma in object");
			return JSON_NEXT_ERROR;
		}
		*iter = i + 1;
		return JSON_NEXT_END;
	}
	if (first && delim == 2) {
		LOGE("json: leading comma in object");
		return JSON_NEXT_ERROR;
	}
	if (!first && delim != 2) {
		LOGE("json: expected ',' between object members");
		return JSON_NEXT_ERROR;
	}
	if (i >= buflen || json[i] != '"') {
		LOGE("json: expected object key string");
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
	while (i < buflen && json_iswhitespace((unsigned char)json[i])) {
		i++;
	}
	if (i >= buflen || json[i] != ':') {
		LOGE("json: expected ':' after object key");
		return JSON_NEXT_ERROR;
	}
	i++;
	while (i < buflen && json_iswhitespace((unsigned char)json[i])) {
		i++;
	}
	if (i >= buflen) {
		LOGE("json: expected value after ':'");
		return JSON_NEXT_ERROR;
	}
	const ptrdiff_t vlen = skip_raw_value(json + i, buflen - i);
	if (vlen < 0) {
		LOGE("json: invalid JSON value");
		return JSON_NEXT_ERROR;
	}
	*val = json + i;
	*val_len = (size_t)vlen;
	*iter = i + (size_t)vlen;
	return JSON_NEXT_ITEM;
}

int json_arr_next(
	char *restrict json, const size_t *restrict len,
	json_iter *restrict iter, char **restrict val, size_t *restrict val_len)
{
	const size_t buflen = *len;
	const size_t start = *iter;
	size_t i = start;
	const int delim = skip_delim(json, buflen, &i);
	if (delim == 0) {
		LOGE("json: unterminated array");
		return JSON_NEXT_ERROR;
	}
	/* The cursor sits just past '[' on the first element and just past the
	 * previous value otherwise; a JSON value never ends in '[', so the byte
	 * before the cursor is '[' exactly on the first element. A comma must
	 * separate elements and must not precede the first. */
	const bool first = (start >= 1 && json[start - 1] == '[');
	if (json[i] == ']') {
		if (delim == 2) {
			LOGE("json: trailing comma in array");
			return JSON_NEXT_ERROR;
		}
		*iter = i + 1;
		return JSON_NEXT_END;
	}
	if (first && delim == 2) {
		LOGE("json: leading comma in array");
		return JSON_NEXT_ERROR;
	}
	if (!first && delim != 2) {
		LOGE("json: expected ',' between array elements");
		return JSON_NEXT_ERROR;
	}
	const ptrdiff_t vlen = skip_raw_value(json + i, buflen - i);
	if (vlen < 0) {
		LOGE("json: invalid JSON value in array");
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

/* json_fmod: libm-free remainder of x divided by y for finite x and finite
 * y > 0; returns a value with the sign of x and magnitude < y.  Exact in
 * IEEE-754 (classic shift-and-subtract), backing the multipleOf test below. */
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
		if (yy == y) {
			break;
		}
		yy /= 2.0;
	}
	return neg ? -x : x;
}

/* json_exact_below: the magnitude below which mult's multiples are all exact
 * doubles, when mult is exactly the decimal the schema wrote; 0.0 when it may
 * not be.  An integral divisor is the integer it was parsed from, and every
 * integer below 2^53 is a double.  A fractional one is a / 2^k with a odd, so
 * its exact decimal value has the significant digits of the integer a * 5^k;
 * when those number at most DBL_DIG, it is the decimal the schema wrote,
 * since every decimal of up to DBL_DIG significant digits survives the round
 * trip through a double and so no other one parses to it.  Its multiples lie
 * on the 2^-k grid, which doubles cover exactly below 2^(53-k).  A decimal
 * that no double holds (0.1) has a far longer exact value and yields 0.0.
 * Requires finite mult > 0. */
static double json_exact_below(const double mult)
{
	if (json_fmod(mult, 1.0) == 0.0) {
		return 0x1p53;
	}
	/* 10^DBL_DIG: the first integer with more than DBL_DIG digits */
	const double digits_max = 1e15;
	double a = mult;
	double pow5 = 1.0;
	double limit = 0x1p53;
	while (json_fmod(a, 1.0) != 0.0) {
		/* a ends up at least 1, so a * pow5 has outgrown DBL_DIG digits
		 * once pow5 alone has */
		pow5 *= 5.0;
		if (pow5 >= digits_max) {
			return 0.0;
		}
		a *= 2.0;
		limit /= 2.0;
	}
	/* a * pow5 is exact while below 2^53, and rounds to no less than
	 * digits_max when the exact product reaches it */
	return a * pow5 < digits_max ? limit : 0.0;
}

/* json_is_multiple: JSON Schema multipleOf test for doubles.  Where mult is
 * exactly the decimal the schema wrote and every multiple at v's magnitude is
 * a double (json_exact_below), a genuine multiple parses exactly and leaves no
 * remainder at all, so any remainder rejects.  Otherwise decimal operands
 * rarely divide exactly in binary (0.3 is not a binary multiple of 0.1, and
 * 9007199254740993, a multiple of 3, parses to 2^53), so a genuine multiple
 * leaves json_fmod a remainder shy of 0 or of the whole divisor by the
 * operands' rounding error; accept when the nearer exact multiple lies within
 * that error's bound rather than demanding an exact-zero binary remainder.
 * Requires finite v and finite mult > 0. */
static bool json_is_multiple(const double v, const double mult)
{
	double r = json_fmod(v, mult);
	if (r == 0.0) {
		return true;
	}
	if (r < 0.0) {
		r = -r;
	}
	const double mag = v < 0.0 ? -v : v;
	if (mag < json_exact_below(mult)) {
		return false;
	}
	/* distance to the nearer of the two exact multiples bracketing v, itself
	 * exact: mult - r is the nearer only when r > mult / 2 (Sterbenz) */
	const double dist = r < mult - r ? r : mult - r;
	/* for a genuine multiple d_v = q * d_m of the decimal values, v and mult
	 * each round theirs by at most DBL_EPSILON / 2 relative, so v lies within
	 * DBL_EPSILON * |d_v| of the binary multiple q * mult, and
	 * |d_v| <= |v| * (1 + DBL_EPSILON) bounds that by v alone.  Past the
	 * magnitude where it reaches mult / 2 the operands' rounding can explain
	 * any remainder, so every value passes: rejecting there would reject
	 * genuine multiples too (an integer as large as 5e16 already sits near
	 * the midpoint between two binary multiples of 0.01). */
	const double slack = mag * DBL_EPSILON * (1.0 + DBL_EPSILON);
	return dist <= slack;
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
	case JSON_K_NULL:
		return sizeof(bool);
	case JSON_K_VALUE:
		return sizeof(struct json_value);
	case JSON_K_OBJECT:
		return f->child->obj_size;
	}
	return 0;
}

/* Array members have typed pointers, so accessing them through void ** would
 * violate C11 6.5p7. Copy their representations through the matching pointer
 * type, then convert the value to/from void * (6.3.2.3p1). For object arrays,
 * 6.2.5p28 and footnote 48 guarantee interchangeable representations for all
 * struct pointers, not permission to alias their storage. The representative
 * struct needs only character alignment; its pointer is never dereferenced or
 * used for element arithmetic. Copy sizeof the typed pointer, not void *. */
struct json_array_object {
	char byte;
};

static void *
json_array_load(const struct json_field *restrict f, const void *slot)
{
	switch (f->kind) {
	case JSON_K_STRING:
	case JSON_K_DYNAMIC: {
		struct json_string *p;
		memcpy((void *)&p, slot, sizeof(struct json_string *));
		return p;
	}
	case JSON_K_INT: {
		int *p;
		memcpy((void *)&p, slot, sizeof(p));
		return p;
	}
	case JSON_K_IMAX: {
		intmax_t *p;
		memcpy((void *)&p, slot, sizeof(p));
		return p;
	}
	case JSON_K_UINT: {
		unsigned *p;
		memcpy((void *)&p, slot, sizeof(p));
		return p;
	}
	case JSON_K_UMAX: {
		uintmax_t *p;
		memcpy((void *)&p, slot, sizeof(p));
		return p;
	}
	case JSON_K_DOUBLE: {
		double *p;
		memcpy((void *)&p, slot, sizeof(p));
		return p;
	}
	case JSON_K_BOOL:
	case JSON_K_NULL: {
		bool *p;
		memcpy((void *)&p, slot, sizeof(p));
		return p;
	}
	case JSON_K_VALUE: {
		struct json_value *p;
		memcpy((void *)&p, slot, sizeof(struct json_value *));
		return p;
	}
	case JSON_K_OBJECT: {
		struct json_array_object *p;
		memcpy((void *)&p, slot, sizeof(struct json_array_object *));
		return p;
	}
	}
	return NULL;
}

static void
json_array_store(const struct json_field *restrict f, void *slot, void *value)
{
	switch (f->kind) {
	case JSON_K_STRING:
	case JSON_K_DYNAMIC: {
		struct json_string *const p = value;
		memcpy(slot, (const void *)&p, sizeof(struct json_string *));
		return;
	}
	case JSON_K_INT: {
		int *const p = value;
		memcpy(slot, (const void *)&p, sizeof(p));
		return;
	}
	case JSON_K_IMAX: {
		intmax_t *const p = value;
		memcpy(slot, (const void *)&p, sizeof(p));
		return;
	}
	case JSON_K_UINT: {
		unsigned *const p = value;
		memcpy(slot, (const void *)&p, sizeof(p));
		return;
	}
	case JSON_K_UMAX: {
		uintmax_t *const p = value;
		memcpy(slot, (const void *)&p, sizeof(p));
		return;
	}
	case JSON_K_DOUBLE: {
		double *const p = value;
		memcpy(slot, (const void *)&p, sizeof(p));
		return;
	}
	case JSON_K_BOOL:
	case JSON_K_NULL: {
		bool *const p = value;
		memcpy(slot, (const void *)&p, sizeof(p));
		return;
	}
	case JSON_K_VALUE: {
		struct json_value *p = value;
		memcpy(slot, (const void *)&p, sizeof(struct json_value *));
		return;
	}
	case JSON_K_OBJECT: {
		struct json_array_object *const p = value;
		memcpy(slot, (const void *)&p,
		       sizeof(struct json_array_object *));
		return;
	}
	}
}

/* json_free_array: release the heap owned by array elements (object elements
 * recurse; primitive and string elements own nothing). */
static void json_free_array(
	const struct json_field *restrict f, void *restrict base, size_t count)
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

/* --- constraint checks ------------------------------------------------- */

static bool json_in_imax(const intmax_t *restrict a, size_t n, intmax_t v)
{
	for (size_t i = 0; i < n; i++) {
		if (a[i] == v) {
			return true;
		}
	}
	return false;
}

static bool json_in_umax(const uintmax_t *restrict a, size_t n, uintmax_t v)
{
	for (size_t i = 0; i < n; i++) {
		if (a[i] == v) {
			return true;
		}
	}
	return false;
}

static bool json_in_double(const double *restrict a, size_t n, double v)
{
	for (size_t i = 0; i < n; i++) {
		if (a[i] == v) {
			return true;
		}
	}
	return false;
}

static bool json_check_str(
	const struct json_constraint *restrict c, const char *restrict s,
	size_t len)
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

static bool json_check_int(const struct json_constraint *restrict c, intmax_t v)
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
	/* multipleOf must be positive; a non-positive mult is a malformed
	 * constraint (the generator drops it, so it can only arrive via a
	 * hand-authored table). Skip it rather than divide by zero -- or, at
	 * mult == -1, invoke INTMAX_MIN % -1 overflow. */
	if ((c->flags & JSON_C_MULT) && c->i.mult > 0 && (v % c->i.mult) != 0) {
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

static bool
json_check_uint(const struct json_constraint *restrict c, uintmax_t v)
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
	/* skip a malformed (zero) divisor rather than divide by zero; see
	 * json_check_int */
	if ((c->flags & JSON_C_MULT) && c->u.mult > 0 && (v % c->u.mult) != 0) {
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

static bool
json_check_double(const struct json_constraint *restrict c, double v)
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
	/* multipleOf needs a finite positive divisor; a non-positive or infinite
	 * mult is a malformed constraint (the generator drops or refuses it) that
	 * would otherwise spin json_fmod forever, so skip it rather than hang */
	if ((c->flags & JSON_C_MULT) && c->d.mult > 0.0 &&
	    json_isfinite(c->d.mult) && !json_is_multiple(v, c->d.mult)) {
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

static bool json_check_bool(const struct json_constraint *restrict c, bool v)
{
	if ((c->flags & JSON_C_CONST) && v != (c->b.konst != 0)) {
		return false;
	}
	return true;
}

bool json_codec_error(
	struct json_context *context, const struct json_path *path,
	enum json_error_kind kind, const struct json_constraint *constraint,
	const char *position)
{
	if (!context->reported) {
		context->reported = true;
		if (context->options != NULL &&
		    context->options->error != NULL) {
			const struct json_error error = {
				.kind = kind,
				.path = path,
				.constraint = constraint,
				.has_offset =
					position != NULL && !context->fallback,
				.offset =
					position != NULL && !context->fallback ?
						(size_t)(position -
							 context->root) :
						0,
			};
			context->options->error(
				context->options->context, &error);
		}
	}
	return false;
}

static bool json_read_scalar(
	const struct json_field *f, void *slot, char *val, size_t len,
	struct json_context *context, const struct json_path *path)
{
	const struct json_constraint *c =
		context->fallback ? NULL : f->constraint;
	size_t start = 0;
	while (start < len && json_iswhitespace((unsigned char)val[start])) {
		start++;
	}
	enum json_type type = JSON_ERROR;
	if (start < len) {
		switch (val[start]) {
		case '"':
			type = JSON_STRING;
			break;
		case '{':
			type = JSON_OBJECT;
			break;
		case '[':
			type = JSON_ARRAY;
			break;
		case 't':
		case 'f':
			type = JSON_BOOL;
			break;
		case 'n':
			type = JSON_NULL;
			break;
		default:
			type = JSON_NUMBER;
			break;
		}
	}
	bool parsed = false, valid = true;
	enum json_type expected = JSON_ERROR;
	switch (f->kind) {
	case JSON_K_STRING: {
		expected = JSON_STRING;
		struct json_string *v = slot;
		parsed = json_parse_string(val, len, &v->str, &v->len);
		valid = !parsed || c == NULL ||
			json_check_str(c, v->str, v->len);
		break;
	}
	case JSON_K_INT:
		expected = JSON_NUMBER;
		parsed = json_parse_int(val, len, slot);
		valid = !parsed || c == NULL || json_check_int(c, *(int *)slot);
		break;
	case JSON_K_IMAX:
		expected = JSON_NUMBER;
		parsed = json_parse_imax(val, len, slot);
		valid = !parsed || c == NULL ||
			json_check_int(c, *(intmax_t *)slot);
		break;
	case JSON_K_UINT:
		expected = JSON_NUMBER;
		parsed = json_parse_uint(val, len, slot);
		valid = !parsed || c == NULL ||
			json_check_uint(c, *(unsigned *)slot);
		break;
	case JSON_K_UMAX:
		expected = JSON_NUMBER;
		parsed = json_parse_umax(val, len, slot);
		valid = !parsed || c == NULL ||
			json_check_uint(c, *(uintmax_t *)slot);
		break;
	case JSON_K_DOUBLE:
		expected = JSON_NUMBER;
		parsed = json_parse_double(val, len, slot);
		valid = !parsed || c == NULL ||
			json_check_double(c, *(double *)slot);
		break;
	case JSON_K_BOOL:
		expected = JSON_BOOL;
		parsed = json_parse_bool(val, len, slot);
		valid = !parsed || c == NULL ||
			json_check_bool(c, *(bool *)slot);
		break;
	case JSON_K_NULL:
		expected = JSON_NULL;
		parsed = type == JSON_NULL;
		if (parsed) {
			*(bool *)slot = false;
		}
		break;
	case JSON_K_DYNAMIC:
		expected = f->raw_type;
		parsed = expected == JSON_ERROR || expected == type;
		if (parsed) {
			*(struct json_string *)slot =
				(struct json_string){ len, val };
		}
		break;
	case JSON_K_VALUE: {
		struct json_value *v = slot;
		v->type = type;
		if (type == JSON_STRING) {
			parsed = json_parse_string(
				val, len, &v->text.str, &v->text.len);
		} else if (type == JSON_BOOL) {
			parsed = json_parse_bool(val, len, &v->b);
		} else {
			v->text = (struct json_string){ len, val };
			parsed = type != JSON_ERROR;
		}
		break;
	}
	case JSON_K_OBJECT:
		break;
	}
	if (!parsed) {
		return json_codec_error(
			context, path,
			expected != JSON_ERROR && type != expected ?
				JSON_E_TYPE :
				JSON_E_RANGE,
			NULL, val + start);
	}
	return valid ||
	       json_codec_error(
		       context, path, JSON_E_CONSTRAINT, c, val + start);
}

void json_codec_release(const struct json_field *field, void *obj)
{
	char *base = obj;
	if (field->is_array) {
		void *slot = base + field->offset;
		void *array = json_array_load(field, slot);
		size_t *count = (size_t *)(base + field->count_offset);
		json_free_array(field, array, *count);
		free(array);
		json_array_store(field, slot, NULL);
		*count = 0;
	} else if (field->kind == JSON_K_OBJECT) {
		json_free(field->child, base + field->offset);
	}
}

void json_codec_storage(const struct json_schema *schema, void *obj)
{
	if (schema->has_default_storage) {
		char **storage =
			(char **)((char *)obj + schema->default_storage_offset);
		free(*storage);
		*storage = NULL;
	}
}

bool json_codec_init(
	const struct json_schema *schema, void *obj,
	struct json_context *context, const struct json_path *path,
	bool fallback)
{
	if (schema->set_present != NULL) {
		for (size_t i = 0; i < schema->n_fields; i++) {
			schema->set_present(obj, i, false);
		}
		return true;
	}
	memset(obj, 0, schema->obj_size);
	if (fallback || schema->default_json == NULL) {
		return true;
	}
	char *storage = malloc(schema->default_len + 1);
	if (storage == NULL) {
		return json_codec_error(
			context, path, JSON_E_ALLOCATION, NULL, NULL);
	}
	memcpy(storage, schema->default_json, schema->default_len + 1);
	const bool previous = context->fallback;
	context->fallback = true;
	bool ok = json_codec_read(
		schema, obj, storage, schema->default_len, context, path, true);
	context->fallback = previous;
	if (!ok) {
		free(storage);
		return false;
	}
	assert(schema->has_default_storage);
	*(char **)((char *)obj + schema->default_storage_offset) = storage;
	return true;
}

bool json_codec_field(
	const struct json_field *field, void *obj, char *json, size_t length,
	struct json_context *context, const struct json_path *path)
{
	char *base = obj;
	void *slot = base + field->offset;
	if (!field->is_array) {
		if (field->kind == JSON_K_OBJECT) {
			return json_codec_read(
				field->child, slot, json, length, context, path,
				context->fallback);
		}
		return json_read_scalar(
			field, slot, json, length, context, path);
	}
	json_array_store(field, slot, NULL);
	size_t *out_count = (size_t *)(base + field->count_offset);
	*out_count = 0;
	size_t consumed = length;
	struct json_val array = json_parse(json, &consumed);
	if (array.type != JSON_ARRAY) {
		return json_codec_error(context, path, JSON_E_TYPE, NULL, json);
	}
	const struct json_constraint *c =
		context->fallback ? NULL : field->constraint;
	size_t count = 0, capacity = 0;
	size_t element_size = json_elem_size(field);
	char *items = NULL;
	json_iter iter = array.iter;
	char *value;
	size_t value_len;
	int next;
	while ((next = json_arr_next(
			json, &length, &iter, &value, &value_len)) ==
	       JSON_NEXT_ITEM) {
		struct json_path item_path = { .parent = path,
					       .kind = JSON_PATH_INDEX,
					       .index = count };
		if (c != NULL && (c->flags & JSON_C_MAX_ITEMS) &&
		    count >= c->max_items) {
			json_codec_error(
				context, &item_path, JSON_E_CONSTRAINT, c,
				value);
			goto fail;
		}
		if (count == capacity) {
			size_t grown = capacity == 0 ? 4 : capacity * 2;
			if (grown < capacity ||
			    grown > SIZE_MAX / element_size) {
				json_codec_error(
					context, &item_path, JSON_E_ALLOCATION,
					NULL, value);
				goto fail;
			}
			char *replacement =
				realloc(items, grown * element_size);
			if (replacement == NULL) {
				json_codec_error(
					context, &item_path, JSON_E_ALLOCATION,
					NULL, value);
				goto fail;
			}
			items = replacement;
			capacity = grown;
		}
		void *element = items + count * element_size;
		bool ok = field->kind == JSON_K_OBJECT ?
				  json_codec_read(
					  field->child, element, value,
					  value_len, context, &item_path,
					  context->fallback) :
				  json_read_scalar(
					  field, element, value, value_len,
					  context, &item_path);
		if (!ok) {
			goto fail;
		}
		count++;
	}
	if (next != JSON_NEXT_END) {
		json_codec_error(
			context, path, JSON_E_SYNTAX, NULL, json + iter);
		goto fail;
	}
	if (c != NULL && (c->flags & JSON_C_MIN_ITEMS) &&
	    count < c->min_items) {
		json_codec_error(context, path, JSON_E_CONSTRAINT, c, json);
		goto fail;
	}
	json_array_store(field, slot, items);
	*out_count = count;
	return true;
fail:
	json_free_array(field, items, count);
	free(items);
	return false;
}

bool json_codec_extra(
	const struct json_schema *schema, char *json, size_t length,
	struct json_context *context, const struct json_path *path)
{
	if (schema->extra == JSON_EXTRA_REJECT) {
		return json_codec_error(
			context, path, JSON_E_UNKNOWN, NULL, json);
	}
	if (schema->extra == JSON_EXTRA_TYPED) {
		union {
			struct json_string string;
			struct json_value value;
			int i;
			intmax_t imax;
			unsigned u;
			uintmax_t umax;
			double d;
			bool b;
		} value;
		return json_read_scalar(
			schema->extra_value, &value, json, length, context,
			path);
	}
	return true;
}

static bool json_read_map(
	const struct json_schema *schema, void *obj, char *json, size_t length,
	struct json_context *context, const struct json_path *path)
{
	/* A supplied map replaces the whole default, including owned entries. */
	json_free(schema, obj);
	char *base = obj;
	size_t *count = (size_t *)(base + schema->count_offset);
	struct json_field pointer_field = { .kind = JSON_K_OBJECT };
	size_t capacity = 0, retained = 0;
	char *entries = NULL;
	json_iter iter = json_parse(json, &(size_t){ length }).iter;
	char *key, *value;
	size_t key_len, value_len, position = 0;
	int next;
	while ((next = json_obj_next(
			json, &length, &iter, &key, &key_len, &value,
			&value_len)) == JSON_NEXT_ITEM) {
		struct json_path entry_path = { .parent = path,
						.kind = JSON_PATH_MAP,
						.key = { key_len, key },
						.index = position++ };
		if (!context->fallback && context->options != NULL &&
		    context->options->filter != NULL &&
		    !context->options->filter(
			    context->options->context, path, key, key_len)) {
			continue;
		}
		if (!context->fallback && schema->extra == JSON_EXTRA_REJECT) {
			return json_codec_error(
				context, &entry_path, JSON_E_UNKNOWN, NULL,
				value);
		}
		if (retained == capacity) {
			size_t grown = capacity == 0 ? 4 : capacity * 2;
			if (grown < capacity ||
			    grown > SIZE_MAX / schema->entry_size) {
				return json_codec_error(
					context, &entry_path, JSON_E_ALLOCATION,
					NULL, value);
			}
			char *replacement =
				realloc(entries, grown * schema->entry_size);
			if (replacement == NULL) {
				return json_codec_error(
					context, &entry_path, JSON_E_ALLOCATION,
					NULL, value);
			}
			entries = replacement;
			json_array_store(
				&pointer_field, base + schema->entries_offset,
				entries);
			capacity = grown;
		}
		char *entry = entries + retained * schema->entry_size;
		*(struct json_string *)entry =
			(struct json_string){ key_len, key };
		if (!json_codec_field(
			    schema->map_value, entry, value, value_len, context,
			    &entry_path)) {
			return false;
		}
		*count = ++retained;
	}
	if (next != JSON_NEXT_END) {
		return json_codec_error(
			context, path, JSON_E_SYNTAX, NULL, json + iter);
	}
	for (; iter < length; iter++) {
		if (!json_iswhitespace((unsigned char)json[iter])) {
			return json_codec_error(
				context, path, JSON_E_SYNTAX, NULL,
				json + iter);
		}
	}
	return true;
}

bool json_codec_read(
	const struct json_schema *schema, void *obj, char *json, size_t length,
	struct json_context *context, const struct json_path *path,
	bool fallback)
{
	if (schema->read != NULL) {
		return schema->read(
			schema, obj, json, length, context, path, fallback);
	}
	if (!json_codec_init(schema, obj, context, path, fallback)) {
		return false;
	}
	size_t consumed = length;
	const struct json_val root = json_parse(json, &consumed);
	if (root.type != JSON_OBJECT) {
		json_codec_error(
			context, path,
			root.type == JSON_ERROR ? JSON_E_SYNTAX : JSON_E_TYPE,
			NULL, root.type == JSON_ERROR ? json + consumed : json);
		goto fail;
	}
	if (schema->is_map) {
		if (!json_read_map(schema, obj, json, length, context, path)) {
			goto fail;
		}
		return true;
	}
	json_iter iter = root.iter;
	char *key, *value;
	size_t key_len, value_len;
	uint_least64_t required = 0;
	int next;
	while ((next = json_obj_next(
			json, &length, &iter, &key, &key_len, &value,
			&value_len)) == JSON_NEXT_ITEM) {
		struct json_path field_path = { .parent = path,
						.kind = JSON_PATH_PROPERTY,
						.key = { key_len, key } };
		int index = schema->lookup == NULL ?
				    -1 :
				    schema->lookup(key, key_len);
		if (index < 0 || (size_t)index >= schema->n_fields) {
			if (!json_codec_extra(
				    schema, value, value_len, context,
				    &field_path)) {
				goto fail;
			}
			continue;
		}
		const struct json_field *field = &schema->fields[index];
		if (schema->get_present == NULL ||
		    schema->get_present(obj, (size_t)index)) {
			json_codec_release(field, obj);
		}
		if (schema->set_present != NULL) {
			schema->set_present(obj, (size_t)index, false);
		}
		if (!json_codec_field(
			    field, obj, value, value_len, context,
			    &field_path)) {
			goto fail;
		}
		if (schema->set_present != NULL) {
			schema->set_present(obj, (size_t)index, true);
		}
		if (field->req_bit >= 0) {
			assert(field->req_bit < 64);
			required |= UINT64_C(1) << field->req_bit;
		}
	}
	if (next != JSON_NEXT_END) {
		json_codec_error(
			context, path, JSON_E_SYNTAX, NULL, json + iter);
		goto fail;
	}
	if (!context->fallback && required != schema->required_mask) {
		for (size_t i = 0; i < schema->n_fields; i++) {
			const struct json_field *field = &schema->fields[i];
			if (field->req_bit >= 0 &&
			    !(required & (UINT64_C(1) << field->req_bit))) {
				struct json_path missing = {
					.parent = path,
					.kind = JSON_PATH_PROPERTY,
					.key = { field->name_len,
						 (char *)field->name }
				};
				json_codec_error(
					context, &missing, JSON_E_REQUIRED,
					NULL, NULL);
				goto fail;
			}
		}
	}
	for (; iter < length; iter++) {
		if (!json_iswhitespace((unsigned char)json[iter])) {
			json_codec_error(
				context, path, JSON_E_SYNTAX, NULL,
				json + iter);
			goto fail;
		}
	}
	return true;
fail:
	json_free(schema, obj);
	if (schema->set_present == NULL) {
		memset(obj, 0, schema->obj_size);
	}
	return false;
}

/* Syntax diagnostics walk the raw input only after its non-destructive scan
 * failed. Decode path keys at delivery, so successful input is decoded once
 * by the actual codec and container fragments remain available to callers. */
struct json_syntax_path {
	struct json_path path;
	struct json_syntax_path *parent;
	size_t raw_len;
};

static const struct json_schema *json_syntax_decode(
	struct json_syntax_path *path, const struct json_schema *root)
{
	if (path == NULL) {
		return root;
	}
	const struct json_schema *schema =
		json_syntax_decode(path->parent, root);
	if (path->path.kind == JSON_PATH_INDEX) {
		return schema;
	}
	char *raw = path->path.key.str;
	if (!json_parse_string(
		    raw, path->raw_len, &path->path.key.str,
		    &path->path.key.len)) {
		return NULL;
	}
	if (schema == NULL) {
		return NULL;
	}
	if (schema->is_map) {
		path->path.kind = JSON_PATH_MAP;
		return NULL;
	}
	int index =
		schema->lookup == NULL ?
			-1 :
			schema->lookup(path->path.key.str, path->path.key.len);
	return index < 0 || (size_t)index >= schema->n_fields ?
		       NULL :
		       schema->fields[index].child;
}

static bool json_syntax_fail(
	struct json_context *context, struct json_syntax_path *path,
	const struct json_schema *root, size_t position)
{
	(void)json_syntax_decode(path, root);
	return json_codec_error(
		context, path == NULL ? NULL : &path->path, JSON_E_SYNTAX, NULL,
		context->root + position);
}

static void
json_syntax_whitespace(struct json_context *context, size_t *position)
{
	while (*position < context->length &&
	       json_iswhitespace((unsigned char)context->root[*position])) {
		(*position)++;
	}
}

static bool json_syntax_walk(
	struct json_context *context, const struct json_schema *root,
	struct json_syntax_path *path, size_t *position, unsigned depth)
{
	json_syntax_whitespace(context, position);
	if (*position == context->length || depth > 256) {
		return json_syntax_fail(context, path, root, *position);
	}
	char *json = context->root;
	char token = json[*position];
	if (token != '{' && token != '[') {
		ptrdiff_t count = scan_scalar(
			json + *position, context->length - *position);
		if (count < 0) {
			return json_syntax_fail(context, path, root, *position);
		}
		*position += (size_t)count;
		return true;
	}
	(*position)++;
	char close = token == '{' ? '}' : ']';
	json_syntax_whitespace(context, position);
	if (*position < context->length && json[*position] == close) {
		(*position)++;
		return true;
	}
	for (size_t index = 0;; index++) {
		struct json_syntax_path child = {
			.path = { .parent = path == NULL ? NULL : &path->path,
				  .kind = JSON_PATH_INDEX,
				  .index = index },
			.parent = path,
		};
		if (token == '{') {
			if (*position == context->length ||
			    json[*position] != '"') {
				return json_syntax_fail(
					context, path, root, *position);
			}
			ptrdiff_t length = scan_string_raw(
				json + *position, context->length - *position);
			if (length < 0) {
				return json_syntax_fail(
					context, path, root, *position);
			}
			child.path.kind = JSON_PATH_PROPERTY;
			child.path.key.str = json + *position;
			child.raw_len = (size_t)length;
			*position += (size_t)length;
			json_syntax_whitespace(context, position);
			if (*position == context->length ||
			    json[*position] != ':') {
				return json_syntax_fail(
					context, &child, root, *position);
			}
			(*position)++;
		}
		if (!json_syntax_walk(
			    context, root, &child, position, depth + 1)) {
			return false;
		}
		json_syntax_whitespace(context, position);
		if (*position == context->length) {
			return json_syntax_fail(context, path, root, *position);
		}
		if (json[*position] == close) {
			(*position)++;
			return true;
		}
		if (json[*position] != ',') {
			return json_syntax_fail(context, path, root, *position);
		}
		(*position)++;
		json_syntax_whitespace(context, position);
	}
}

bool json_unmarshal_ex(
	const struct json_schema *schema, void *obj, char *json, size_t length,
	const struct json_options *options)
{
	struct json_context context = { .root = json,
					.length = length,
					.options = options };
	size_t start = 0;
	json_syntax_whitespace(&context, &start);
	ptrdiff_t count = start == length ?
				  -1 :
				  skip_raw_value(json + start, length - start);
	size_t end = count < 0 ? start : start + (size_t)count;
	json_syntax_whitespace(&context, &end);
	if (count < 0 || end != length) {
		if (schema->set_present == NULL) {
			memset(obj, 0, schema->obj_size);
		} else {
			for (size_t i = 0; i < schema->n_fields; i++) {
				schema->set_present(obj, i, false);
			}
		}
		if (count < 0) {
			size_t position = 0;
			if (!json_syntax_walk(
				    &context, schema, NULL, &position, 0)) {
				return false;
			}
		}
		return json_codec_error(
			&context, NULL, JSON_E_SYNTAX, NULL, json + end);
	}
	return json_codec_read(
		schema, obj, json + start, length - start, &context, NULL,
		false);
}

bool json_unmarshal(
	const struct json_schema *restrict schema, void *obj, char *json,
	size_t length)
{
	return json_unmarshal_ex(schema, obj, json, length, NULL);
}

static size_t json_add(size_t n, size_t add)
{
	if (n > (size_t)INT_MAX || add > (size_t)INT_MAX - n) {
		return SIZE_MAX;
	}
	return n + add;
}

static size_t json_emit_ch(char *restrict buf, size_t bufsz, size_t n, char c)
{
	if (buf != NULL && n < bufsz) {
		buf[n] = c;
	}
	return json_add(n, 1);
}

static size_t json_emit_raw(
	char *restrict buf, size_t bufsz, size_t n, const char *restrict s,
	size_t len)
{
	if (buf != NULL && n < bufsz) {
		const size_t cap = bufsz - n;
		memcpy(buf + n, s, len < cap ? len : cap);
	}
	return json_add(n, len);
}

static size_t json_emit_str(
	char *restrict buf, size_t bufsz, size_t n, const char *restrict s,
	size_t len)
{
	char *const dst = (buf != NULL && n < bufsz) ? buf + n : NULL;
	const int r =
		json_marshal_string(dst, dst != NULL ? bufsz - n : 0, s, len);
	if (r < 0) {
		return SIZE_MAX;
	}
	return json_add(n, (size_t)r);
}

static size_t json_emit_indent(
	char *restrict buf, size_t bufsz, size_t n, const char *restrict indent,
	size_t ind_len, int d)
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

static void
json_output_raw(struct json_output *out, const char *text, size_t length)
{
	out->length =
		json_emit_raw(out->buf, out->size, out->length, text, length);
}

void json_codec_open(struct json_output *out, char bracket)
{
	out->length = json_emit_ch(out->buf, out->size, out->length, bracket);
}

static void json_output_indent(struct json_output *out, int depth)
{
	out->length = json_emit_indent(
		out->buf, out->size, out->length, out->indent,
		out->indent == NULL ? 0 : strlen(out->indent), depth);
}

void json_codec_key(
	struct json_output *out, const char *key, size_t length, int depth,
	bool *first)
{
	if (!*first) {
		json_codec_open(out, ',');
	}
	*first = false;
	json_output_indent(out, depth);
	out->length =
		json_emit_str(out->buf, out->size, out->length, key, length);
	json_codec_open(out, ':');
	if (out->indent != NULL) {
		json_codec_open(out, ' ');
	}
}

void json_codec_close(
	struct json_output *out, char bracket, int depth, bool first)
{
	if (!first) {
		json_output_indent(out, depth);
	}
	json_codec_open(out, bracket);
}

static void json_write_scalar(
	const struct json_field *field, const void *slot,
	struct json_output *out, const struct json_path *path, int depth)
{
	char number[JSON_NUM_BUFSIZE];
	int length = -1;
	switch (field->kind) {
	case JSON_K_STRING: {
		const struct json_string *text = slot;
		out->length = json_emit_str(
			out->buf, out->size, out->length,
			text->str == NULL ? "" : text->str,
			text->str == NULL ? 0 : text->len);
		return;
	}
	case JSON_K_DYNAMIC: {
		const struct json_string *text = slot;
		if (text->str != NULL) {
			json_output_raw(out, text->str, text->len);
		} else if (field->raw_type == JSON_OBJECT) {
			json_output_raw(out, "{}", 2);
		} else if (field->raw_type == JSON_ARRAY) {
			json_output_raw(out, "[]", 2);
		} else {
			json_output_raw(out, "null", 4);
		}
		return;
	}
	case JSON_K_INT:
		length = snprintf(
			number, sizeof(number), "%d", *(const int *)slot);
		break;
	case JSON_K_IMAX:
		length = snprintf(
			number, sizeof(number), "%jd", *(const intmax_t *)slot);
		break;
	case JSON_K_UINT:
		length = snprintf(
			number, sizeof(number), "%u", *(const unsigned *)slot);
		break;
	case JSON_K_UMAX:
		length = snprintf(
			number, sizeof(number), "%ju",
			*(const uintmax_t *)slot);
		break;
	case JSON_K_DOUBLE:
		if (!json_isfinite(*(const double *)slot)) {
			out->length = SIZE_MAX;
			return;
		}
		length = u8snprintf(
			number, sizeof(number), "%.17g", *(const double *)slot);
		break;
	case JSON_K_BOOL:
		json_output_raw(
			out, *(const bool *)slot ? "true" : "false",
			*(const bool *)slot ? 4 : 5);
		return;
	case JSON_K_NULL:
		json_output_raw(out, "null", 4);
		return;
	case JSON_K_OBJECT:
		json_codec_write(field->child, slot, out, path, depth);
		return;
	case JSON_K_VALUE: {
		const struct json_value *value = slot;
		if (value->type == JSON_BOOL) {
			json_output_raw(
				out, value->b ? "true" : "false",
				value->b ? 4 : 5);
		} else if (value->type == JSON_STRING) {
			out->length = json_emit_str(
				out->buf, out->size, out->length,
				value->text.str, value->text.len);
		} else if (value->type == JSON_NULL || value->type == JSON_ERROR) {
			json_output_raw(out, "null", 4);
		} else {
			json_output_raw(out, value->text.str, value->text.len);
		}
		return;
	}
	}
	if (length < 0 || (size_t)length >= sizeof(number)) {
		out->length = SIZE_MAX;
		return;
	}
	json_output_raw(out, number, (size_t)length);
}

void json_codec_write_field(
	const struct json_field *field, const void *obj,
	struct json_output *out, const struct json_path *path, int depth)
{
	if (out->length == SIZE_MAX) {
		return;
	}
	const char *base = obj;
	const void *slot = base + field->offset;
	if (!field->is_array) {
		json_write_scalar(field, slot, out, path, depth);
		return;
	}
	const char *items = json_array_load(field, slot);
	size_t count = *(const size_t *)(base + field->count_offset);
	size_t element_size = json_elem_size(field);
	json_codec_open(out, '[');
	for (size_t i = 0; i < count; i++) {
		if (i != 0) {
			json_codec_open(out, ',');
		}
		json_output_indent(out, depth + 1);
		struct json_path item_path = { .parent = path,
					       .kind = JSON_PATH_INDEX,
					       .index = i };
		json_write_scalar(
			field, items + i * element_size, out, &item_path,
			depth + 1);
	}
	json_codec_close(out, ']', depth, count == 0);
}

void json_codec_write(
	const struct json_schema *schema, const void *obj,
	struct json_output *out, const struct json_path *path, int depth)
{
	if (schema->write != NULL) {
		schema->write(schema, obj, out, path, depth);
		return;
	}
	json_codec_open(out, '{');
	bool first = true;
	if (schema->is_map) {
		struct json_field pointer_field = { .kind = JSON_K_OBJECT };
		const char *base = obj;
		const char *entries = json_array_load(
			&pointer_field, base + schema->entries_offset);
		size_t count = *(const size_t *)(base + schema->count_offset);
		for (size_t i = 0; i < count; i++) {
			const char *entry = entries + i * schema->entry_size;
			const struct json_string *key =
				(const struct json_string *)entry;
			if (out->options != NULL &&
			    out->options->filter != NULL &&
			    !out->options->filter(
				    out->options->context, path, key->str,
				    key->len)) {
				continue;
			}
			struct json_path entry_path = { .parent = path,
							.kind = JSON_PATH_MAP,
							.key = *key,
							.index = i };
			json_codec_key(
				out, key->str, key->len, depth + 1, &first);
			json_codec_write_field(
				schema->map_value, entry, out, &entry_path,
				depth + 1);
		}
	} else {
		for (size_t i = 0; i < schema->n_fields; i++) {
			if (schema->get_present != NULL &&
			    !schema->get_present(obj, i)) {
				continue;
			}
			const struct json_field *field = &schema->fields[i];
			struct json_path field_path = {
				.parent = path,
				.kind = JSON_PATH_PROPERTY,
				.key = { field->name_len, (char *)field->name }
			};
			json_codec_key(
				out, field->name, field->name_len, depth + 1,
				&first);
			json_codec_write_field(
				field, obj, out, &field_path, depth + 1);
		}
	}
	json_codec_close(out, '}', depth, first);
}

int json_marshal_ex(
	const struct json_schema *schema, char *buf, size_t bufsz,
	const void *obj, const char *indent, const struct json_options *options)
{
	struct json_output output = {
		.buf = buf, .size = bufsz, .indent = indent, .options = options
	};
	json_codec_write(schema, obj, &output, NULL, 0);
	if (buf != NULL && bufsz != 0) {
		buf[output.length < bufsz ? output.length : bufsz - 1] = '\0';
	}
	return marshal_checked_int(output.length);
}

int json_marshal(
	const struct json_schema *restrict schema, char *restrict buf,
	size_t bufsz, const void *restrict obj, const char *restrict indent)
{
	return json_marshal_ex(schema, buf, bufsz, obj, indent, NULL);
}

void json_free(const struct json_schema *restrict schema, void *restrict obj)
{
	if (schema->release != NULL) {
		schema->release(schema, obj);
		return;
	}
	if (schema->is_map) {
		struct json_field pointer_field = { .kind = JSON_K_OBJECT };
		char *base = obj;
		void *entries = json_array_load(
			&pointer_field, base + schema->entries_offset);
		free(entries);
		json_array_store(
			&pointer_field, base + schema->entries_offset, NULL);
		*(size_t *)(base + schema->count_offset) = 0;
	} else {
		for (size_t i = 0; i < schema->n_fields; i++) {
			if (schema->get_present != NULL &&
			    !schema->get_present(obj, i)) {
				continue;
			}
			json_codec_release(&schema->fields[i], obj);
			if (schema->set_present != NULL) {
				schema->set_present(obj, i, false);
			}
		}
	}
	json_codec_storage(schema, obj);
}

static void
json_path_output(struct json_output *out, const struct json_path *path)
{
	if (path == NULL) {
		json_codec_open(out, '$');
		return;
	}
	json_path_output(out, path->parent);
	if (path->kind != JSON_PATH_INDEX) {
		json_codec_open(out, '[');
		out->length = json_emit_str(
			out->buf, out->size, out->length, path->key.str,
			path->key.len);
		json_codec_open(out, ']');
	}
	if (path->kind != JSON_PATH_PROPERTY) {
		char index[3 * sizeof(size_t) + 1];
		int length = snprintf(index, sizeof(index), "%zu", path->index);
		json_codec_open(out, '[');
		json_output_raw(out, index, (size_t)length);
		json_codec_open(out, ']');
	}
}

int json_format_path(char *buf, size_t bufsz, const struct json_path *path)
{
	struct json_output output = { .buf = buf, .size = bufsz };
	json_path_output(&output, path);
	if (buf != NULL && bufsz != 0) {
		buf[output.length < bufsz ? output.length : bufsz - 1] = '\0';
	}
	return marshal_checked_int(output.length);
}
