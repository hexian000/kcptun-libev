/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "string.h"

#include "internal.h"
#include "math/float.h"
#include "utf8.h"

#if WITH_ICU
#include <unicode/uchar.h>
#include <unicode/udat.h>
#include <unicode/ustring.h>
#include <unicode/utypes.h>

#include <time.h>
#endif /* WITH_ICU */

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <uchar.h>

/* Is a unit utf8_next decoded as cp from n bytes an invalid byte? utf8_next
 * maps every ill-formed byte to U+FFFD while consuming just that byte, and a
 * genuine U+FFFD decodes from three, so a one-byte U+FFFD is exactly that. */
static inline bool is_bad_unit(const char32_t cp, const int n)
{
	return cp == 0xFFFDu && n == 1;
}

/* Sort key of a unit utf8_next decoded as cp (at most U+10FFFF) from the n
 * bytes at unit. Comparing the decoded values alone would make any two invalid
 * bytes equal each other and a genuine U+FFFD; the key keeps them all distinct.
 * An invalid byte sorts right after U+FFFD, and invalid bytes among themselves
 * by byte value. */
static inline uint_fast32_t
unit_key(const char32_t cp, const int n, const char *restrict unit)
{
	const uint_fast32_t key = (uint_fast32_t)cp << 9;
	if (is_bad_unit(cp, n)) {
		return key | 0x100u | (unsigned char)*unit;
	}
	return key;
}

size_t u8strlen(const char *restrict s)
{
	const char *p = s;
	size_t count = 0;
	char32_t cp;
	while (utf8_next(&cp, &p) > 0) {
		count++;
	}
	return count;
}

size_t u8strnlen(const char *restrict s, const size_t n)
{
	const char *p = s;
	size_t count = 0;
	for (;;) {
		char32_t cp;
		const char *next = p;
		if (utf8_next(&cp, &next) == 0) {
			return count; /* terminator */
		}
		if ((size_t)(next - s) > n) {
			return count; /* unit straddles the byte limit */
		}
		p = next;
		count++;
	}
}

/* Append whole units of src after dlen existing bytes of dst with snprintf(3)
 * semantics: units are stored atomically so truncation never splits a sequence,
 * and the full needed length is always returned. */
static int copy_units(
	char *restrict dst, const size_t dstsize, const size_t dlen,
	const char *restrict src)
{
	const size_t cap = dstsize > 0 ? dstsize - 1 : 0;
	/* dst already holds dlen bytes: seed the sink with them, and freeze it
	 * when they alone reached the cap */
	struct sink s = {
		.buf = dst,
		.cap = cap,
		.len = dlen,
		.fill = dlen < cap ? dlen : cap,
		.frozen = dlen >= cap,
	};
	for (const char *p = src; *p != '\0';) {
		char32_t cp;
		const char *next = p;
		const size_t ulen = (size_t)utf8_next(&cp, &next);
		sink_put(&s, p, ulen);
		p = next;
	}
	if (dlen < dstsize) {
		dst[s.fill] = '\0';
	}
	return s.len <= INT_MAX ? (int)s.len : -1;
}

int u8strlcpy(char *restrict dst, const size_t dstsize, const char *restrict src)
{
	return copy_units(dst, dstsize, 0, src);
}

int u8strlcat(char *restrict dst, const size_t dstsize, const char *restrict src)
{
	size_t dlen = 0;
	while (dlen < dstsize && dst[dlen] != '\0') {
		dlen++;
	}
	return copy_units(dst, dstsize, dlen, src);
}

char *u8strchr(char *restrict s, const char32_t cp)
{
	const char *p = s;
	for (;;) {
		const size_t off = (size_t)(p - s);
		char32_t c;
		const int n = utf8_next(&c, &p);
		if (c == cp && !is_bad_unit(c, n)) {
			return s + off;
		}
		if (n == 0) {
			return NULL;
		}
	}
}

char *u8strrchr(char *restrict s, const char32_t cp)
{
	const char *p = s;
	char *last = NULL;
	for (;;) {
		const size_t off = (size_t)(p - s);
		char32_t c;
		const int n = utf8_next(&c, &p);
		if (c == cp && !is_bad_unit(c, n)) {
			last = s + off;
		}
		if (n == 0) {
			return last;
		}
	}
}

bool u8strhasprefix(const char *restrict s, const char *restrict prefix)
{
	for (size_t i = 0; prefix[i] != '\0'; i++) {
		if (s[i] != prefix[i]) {
			return false;
		}
	}
	return true;
}

bool u8strhassuffix(const char *restrict s, const char *restrict suffix)
{
	const size_t sl = strlen(s);
	const size_t xl = strlen(suffix);
	return xl <= sl && memcmp(s + sl - xl, suffix, xl) == 0;
}

char *u8strtrimprefix(char *restrict s, const char *restrict prefix)
{
	for (size_t i = 0; prefix[i] != '\0'; i++) {
		if (s[i] != prefix[i]) {
			return s;
		}
	}
	return s + strlen(prefix);
}

char *u8strtrimsuffix(char *restrict s, const char *restrict suffix)
{
	const size_t sl = strlen(s);
	const size_t xl = strlen(suffix);
	if (xl <= sl && memcmp(s + sl - xl, suffix, xl) == 0) {
		s[sl - xl] = '\0';
	}
	return s;
}

/* Is the unit decoded as c from the n bytes at unit one of the units spelled in
 * the UTF-8 string set? */
static bool
in_set(const char32_t c, const int n, const char *restrict unit,
       const char *restrict set)
{
	const uint_fast32_t key = unit_key(c, n, unit);
	const char *p = set;
	for (;;) {
		const char *const su = p;
		char32_t sc;
		const int sn = utf8_next(&sc, &p);
		if (sn == 0) {
			return false;
		}
		if (unit_key(sc, sn, su) == key) {
			return true;
		}
	}
}

size_t u8strspn(const char *restrict s, const char *restrict set)
{
	const char *p = s;
	for (;;) {
		const size_t off = (size_t)(p - s);
		char32_t c;
		const int n = utf8_next(&c, &p);
		if (n == 0 || !in_set(c, n, s + off, set)) {
			return off;
		}
	}
}

size_t u8strcspn(const char *restrict s, const char *restrict set)
{
	const char *p = s;
	for (;;) {
		const size_t off = (size_t)(p - s);
		char32_t c;
		const int n = utf8_next(&c, &p);
		if (n == 0 || in_set(c, n, s + off, set)) {
			return off;
		}
	}
}

char *u8strpbrk(char *restrict s, const char *restrict set)
{
	const char *p = s;
	for (;;) {
		const size_t off = (size_t)(p - s);
		char32_t c;
		const int n = utf8_next(&c, &p);
		if (n == 0) {
			return NULL;
		}
		if (in_set(c, n, s + off, set)) {
			return s + off;
		}
	}
}

char *u8strsep(char **restrict s, const char *restrict set)
{
	char *const tok = *s;
	if (tok == NULL) {
		return NULL;
	}
	const char *p = tok;
	for (;;) {
		const size_t off = (size_t)(p - tok);
		char32_t c;
		const int n = utf8_next(&c, &p);
		if (n == 0) {
			*s = NULL;
			return tok;
		}
		if (in_set(c, n, tok + off, set)) {
			tok[off] = '\0';
			*s = tok + off + (size_t)n;
			return tok;
		}
	}
}

/* Unicode White_Space test. The property is a fixed 25-codepoint set, so it is
 * spelled out here rather than pulled from a table or libicu: this keeps the
 * whitespace-skipping number parsers and the trim helpers allocation-free,
 * async-signal-safe, and independent of the WITH_ICU build. */
static inline bool is_space32(const char32_t c)
{
	if (c == 0x20u) {
		return true;
	}
	if (0x09u <= c && c <= 0x0Du) {
		return true;
	}
	if (0x2000u <= c && c <= 0x200Au) {
		return true;
	}
	switch (c) {
	case 0x85u:
	case 0xA0u:
	case 0x1680u:
	case 0x2028u:
	case 0x2029u:
	case 0x202Fu:
	case 0x205Fu:
	case 0x3000u:
		return true;
	default:
		return false;
	}
}

/* Value of an ASCII hexadecimal digit (0-15), or -1 if c is not one. The number
 * parsers keep this char32_t-typed helper local rather than pulling in the
 * byte-typed unhex from utils/ctype_ascii.h. */
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

char *u8strtrimleftspace(char *restrict s)
{
	while (*s != '\0') {
		char32_t cp;
		const int n = utf8_decode(&cp, s, peek_avail(s));
		if (n <= 0 || !is_space32(cp)) {
			break;
		}
		s += n;
	}
	return s;
}

char *u8strtrimrightspace(char *restrict s)
{
	char *cut = s; /* the NUL goes here: end of the last non-space unit */
	for (char *p = s; *p != '\0';) {
		char32_t cp;
		const int n = utf8_decode(&cp, p, peek_avail(p));
		/* an invalid byte is a non-space unit of length 1 */
		const size_t unit = n > 0 ? (size_t)n : 1;
		p += unit;
		if (n <= 0 || !is_space32(cp)) {
			cut = p;
		}
	}
	*cut = '\0';
	return s;
}

char *u8strtrimspace(char *restrict s)
{
	return u8strtrimrightspace(u8strtrimleftspace(s));
}

#if WITH_ICU

/* Simple Unicode case mappings via libicu. u_tolower/u_toupper are defined only
 * on U+0000..U+10FFFF; a codepoint outside that range, or one with no mapping,
 * comes back unchanged. These back the u8strcase* family and case_convert. */
static inline char32_t tolower32(const char32_t c)
{
	return c <= 0x10FFFFu ? (char32_t)u_tolower((UChar32)c) : c;
}

static inline char32_t toupper32(const char32_t c)
{
	return c <= 0x10FFFFu ? (char32_t)u_toupper((UChar32)c) : c;
}

int u8strcasecmp(const char *restrict a, const char *restrict b)
{
	const char *pa = a, *pb = b;
	for (;;) {
		const char *const ua = pa, *const ub = pb;
		char32_t ca, cb;
		const int na = utf8_next(&ca, &pa);
		const int nb = utf8_next(&cb, &pb);
		const uint_fast32_t la = unit_key(tolower32(ca), na, ua);
		const uint_fast32_t lb = unit_key(tolower32(cb), nb, ub);
		if (la != lb) {
			return la < lb ? -1 : 1;
		}
		if (na == 0 || nb == 0) {
			return 0;
		}
	}
}

int u8strncasecmp(const char *restrict a, const char *restrict b, const size_t n)
{
	const char *pa = a, *pb = b;
	for (size_t i = 0; i < n; i++) {
		const char *const ua = pa, *const ub = pb;
		char32_t ca, cb;
		const int na = utf8_next(&ca, &pa);
		const int nb = utf8_next(&cb, &pb);
		const uint_fast32_t la = unit_key(tolower32(ca), na, ua);
		const uint_fast32_t lb = unit_key(tolower32(cb), nb, ub);
		if (la != lb) {
			return la < lb ? -1 : 1;
		}
		if (na == 0 || nb == 0) {
			break;
		}
	}
	return 0;
}

static char *
casestr_fallback(char *restrict haystack, const char *restrict needle)
{
	const char *h = haystack;
	for (;;) {
		const size_t off = (size_t)(h - haystack);
		char32_t hc;
		const int n = utf8_next(&hc, &h);
		const char *hp = haystack + off;
		const char *np = needle;
		for (;;) {
			char32_t nc;
			const char *const nu = np;
			const int nn = utf8_next(&nc, &np);
			if (nn == 0) {
				return haystack +
				       off; /* whole needle matched */
			}
			char32_t hcc;
			const char *const hu = hp;
			const int hn = utf8_next(&hcc, &hp);
			if (hn == 0 ||
			    unit_key(tolower32(hcc), hn, hu) !=
				    unit_key(tolower32(nc), nn, nu)) {
				break;
			}
		}
		if (n == 0) {
			return NULL;
		}
	}
}

/* Reuse matching prefixes of folded unit keys. The candidate start advances
 * only forward, so recovering its byte offset costs linear decoding too. */
char *u8strcasestr(char *restrict haystack, const char *restrict needle)
{
	struct match_unit {
		uint_fast32_t key;
		size_t prefix;
	};
	const size_t count = u8strlen(needle);
	if (count == 0) {
		return haystack;
	}
	if (count > SIZE_MAX / sizeof(struct match_unit)) {
		return casestr_fallback(haystack, needle);
	}
	struct match_unit *const units = malloc(count * sizeof(*units));
	if (units == NULL) {
		return casestr_fallback(haystack, needle);
	}
	const char *np = needle;
	for (size_t i = 0; i < count; i++) {
		const char *const nu = np;
		char32_t cp;
		const int n = utf8_next(&cp, &np);
		units[i].key = unit_key(tolower32(cp), n, nu);
		size_t j = i > 0 ? units[i - 1].prefix : 0;
		while (j > 0 && units[i].key != units[j].key) {
			j = units[j - 1].prefix;
		}
		units[i].prefix =
			i > 0 && units[i].key == units[j].key ? j + 1 : 0;
	}
	const char *hp = haystack;
	const char *start = hp;
	size_t matched = 0;
	char *result = NULL;
	for (;;) {
		const char *const hu = hp;
		char32_t cp;
		const int n = utf8_next(&cp, &hp);
		if (n == 0) {
			break;
		}
		const uint_fast32_t key = unit_key(tolower32(cp), n, hu);
		while (matched > 0 && key != units[matched].key) {
			const size_t next = units[matched - 1].prefix;
			for (size_t i = next; i < matched; i++) {
				char32_t skipped;
				utf8_next(&skipped, &start);
			}
			matched = next;
		}
		if (matched == 0) {
			start = hu;
		}
		if (key == units[matched].key) {
			matched++;
			if (matched == count) {
				result = haystack + (start - haystack);
				break;
			}
		}
	}
	free(units);
	return result;
}

/* Case-map every codepoint of src into buf with snprintf(3) semantics: whole
 * units are appended atomically so truncation never splits a sequence, and an
 * invalid byte passes through unchanged. */
static int case_convert(
	char *restrict buf, const size_t maxlen, const char *restrict src,
	const bool upper)
{
	struct sink s = {
		.buf = buf,
		.cap = maxlen > 0 ? maxlen - 1 : 0,
	};
	for (const char *p = src; *p != '\0';) {
		char unit[UTF8_MAX_LEN];
		char32_t cp;
		const int n = utf8_decode(&cp, p, peek_avail(p));
		size_t ulen;
		if (n > 0) {
			const char32_t mapped =
				upper ? toupper32(cp) : tolower32(cp);
			ulen = (size_t)utf8_encode(unit, mapped);
			p += n;
		} else {
			unit[0] = *p;
			ulen = 1;
			p++;
		}
		sink_put(&s, unit, ulen);
	}
	if (maxlen > 0) {
		buf[s.fill] = '\0';
	}
	return s.len <= INT_MAX ? (int)s.len : -1;
}

int u8strlower(char *restrict buf, const size_t maxlen, const char *restrict src)
{
	return case_convert(buf, maxlen, src, false);
}

int u8strupper(char *restrict buf, const size_t maxlen, const char *restrict src)
{
	return case_convert(buf, maxlen, src, true);
}

int ucwidth(const char32_t c)
{
	if (c == 0) {
		return 0; /* NUL, matching wcwidth(0) */
	}
	if (c > 0x10FFFFu) {
		return -1;
	}
	/* non-printable exactly where uctype_isprint() is, except that format
	 * characters are zero-width, as in wcwidth(3) */
	switch (u_charType((UChar32)c)) {
	case U_CONTROL_CHAR:
	case U_SURROGATE:
	case U_UNASSIGNED:
	case U_LINE_SEPARATOR:
	case U_PARAGRAPH_SEPARATOR:
		return -1;
	case U_NON_SPACING_MARK:
	case U_ENCLOSING_MARK:
	case U_FORMAT_CHAR:
		return 0;
	default:
		break;
	}
	/* a conjoining medial (V) or final (T) jamo composes into the preceding
	 * syllable and takes no column of its own; a leading (L) jamo stays wide
	 * by its East Asian width below */
	const int32_t hst =
		u_getIntPropertyValue((UChar32)c, UCHAR_HANGUL_SYLLABLE_TYPE);
	if (hst == U_HST_VOWEL_JAMO || hst == U_HST_TRAILING_JAMO) {
		return 0;
	}
	const int32_t eaw =
		u_getIntPropertyValue((UChar32)c, UCHAR_EAST_ASIAN_WIDTH);
	if (eaw == U_EA_WIDE || eaw == U_EA_FULLWIDTH) {
		return 2;
	}
	return 1;
}

int u8strwidth(const char *restrict s)
{
	int total = 0;
	const char *p = s;
	char32_t cp;
	while (utf8_next(&cp, &p) > 0) {
		const int w = ucwidth(cp);
		if (w < 0) {
			return -1;
		}
		total = total > INT_MAX - w ? INT_MAX : total + w;
	}
	return total;
}

int u8strftime(
	char *restrict buf, const size_t maxlen, const char *restrict pattern,
	const char *restrict locale, const char *restrict tz, const time_t t)
{
	/* keeps the UTF-16 scratch buffers on the stack: a pattern, time zone id,
	 * or formatted result reaching this many code units is rejected */
	enum { SCRATCH_CAP = 1024 };
	UDateFormat *fmt = NULL;
	int ret = -1;
	UErrorCode err;
	int32_t patlen = 0, tzlen = 0, reslen = 0;
	const char *const loc = (locale != NULL) ? locale : "";
	const char *const tzsrc = (tz != NULL) ? tz : "UTC";
	const UDate when = (UDate)t * 1000.0;

	if (pattern == NULL) {
		goto done;
	}

	/* pattern and time zone -> UTF-16 preflight (NULL tz selects UTC) */
	err = U_ZERO_ERROR;
	u_strFromUTF8(NULL, 0, &patlen, pattern, -1, &err);
	err = U_ZERO_ERROR;
	u_strFromUTF8(NULL, 0, &tzlen, tzsrc, -1, &err);
	if (patlen < 0 || patlen >= SCRATCH_CAP || tzlen < 0 ||
	    tzlen >= SCRATCH_CAP) {
		goto done;
	}
	{
		UChar pat[patlen + 1], tzid[tzlen + 1];
		err = U_ZERO_ERROR;
		u_strFromUTF8(pat, patlen + 1, NULL, pattern, -1, &err);
		if (U_FAILURE(err)) {
			goto done;
		}
		err = U_ZERO_ERROR;
		u_strFromUTF8(tzid, tzlen + 1, NULL, tzsrc, -1, &err);
		if (U_FAILURE(err)) {
			goto done;
		}
		/* NULL locale selects the root locale */
		err = U_ZERO_ERROR;
		fmt = udat_open(
			UDAT_PATTERN, UDAT_PATTERN, loc, tzid, tzlen, pat,
			patlen, &err);
	}
	if (U_FAILURE(err)) {
		goto done;
	}

	err = U_ZERO_ERROR;
	reslen = udat_format(fmt, when, NULL, 0, NULL, &err);
	if (reslen < 0 || reslen >= SCRATCH_CAP) {
		goto done;
	}
	{
		UChar res[reslen + 1];
		err = U_ZERO_ERROR;
		udat_format(fmt, when, res, reslen + 1, NULL, &err);
		if (U_FAILURE(err)) {
			goto done;
		}
		/* UTF-16 result -> UTF-8 (reuses the utf8.h bridge) */
		ret = utf8_encode16(buf, maxlen, (const char16_t *)res);
	}

done:
	if (fmt != NULL) {
		udat_close(fmt);
	}
	if (ret < 0 && buf != NULL && maxlen > 0) {
		buf[0] = '\0';
	}
	return ret;
}

#endif /* WITH_ICU */

/* --- locale-free, async-signal-safe printf -------------------------------- *
 * No libc function is called on any path: output is copied bytewise, and the
 * floating conversions build on math/float.h. Output goes through the same
 * bounded sink as the u8str* writers above, so truncation never splits a
 * UTF-8 sequence.
 */

static void sink_putc(struct sink *restrict s, const char c)
{
	sink_put(s, &c, 1);
}

/* n may be huge (width/precision): count the excess without looping */
static void sink_fill(struct sink *restrict s, const char c, const size_t n)
{
	if (!s->frozen) {
		const size_t avail = s->cap - s->fill;
		const size_t w = n < avail ? n : avail;
		for (size_t i = 0; i < w; i++) {
			s->buf[s->fill + i] = c;
		}
		s->fill += w;
		if (w < n) {
			s->frozen = true;
		}
	}
	sink_count(s, n);
}

static void sink_putu(struct sink *restrict s, uintmax_t v)
{
	char tmp[sizeof(uintmax_t) * 3];
	size_t n = 0;
	do {
		tmp[n++] = (char)('0' + (char)(v % 10));
		v /= 10;
	} while (v != 0);
	while (n > 0) {
		sink_putc(s, tmp[--n]);
	}
}

enum length_mod {
	LEN_NONE,
	LEN_CHAR, /* hh */
	LEN_SHORT, /* h */
	LEN_LONG, /* l */
	LEN_LLONG, /* ll */
	LEN_MAX, /* j */
	LEN_SIZE, /* z */
	LEN_PTRDIFF, /* t */
	LEN_LDOUBLE, /* L */
};

struct spec {
	bool minus, plus, space, zero, hash;
	int width; /* 0 = none */
	int prec; /* -1 = none */
	enum length_mod length;
	char conv;
};

static int parse_num(const char **restrict pf)
{
	int v = 0;
	for (; '0' <= **pf && **pf <= '9'; (*pf)++) {
		const int digit = **pf - '0';
		if (v <= (INT_MAX - digit) / 10) {
			v = v * 10 + digit;
		} else {
			v = INT_MAX;
		}
	}
	return v;
}

/* parse [flags][width][.precision][length] and stop at the conversion char;
 * ap is passed by pointer: a va_list consumed by value is not portably
 * reflected in the caller */
static void parse_spec(
	struct spec *restrict sp, const char **restrict pf,
	va_list *restrict ap)
{
	*sp = (struct spec){ .prec = -1 };
	for (;; (*pf)++) {
		const char c = **pf;
		if (c == '-') {
			sp->minus = true;
		} else if (c == '+') {
			sp->plus = true;
		} else if (c == ' ') {
			sp->space = true;
		} else if (c == '0') {
			sp->zero = true;
		} else if (c == '#') {
			sp->hash = true;
		} else {
			break;
		}
	}
	if (**pf == '*') {
		(*pf)++;
		const int w = va_arg(*ap, int);
		if (w < 0) {
			/* negative width: '-' flag plus its magnitude */
			sp->minus = true;
			sp->width = w == INT_MIN ? INT_MAX : -w;
		} else {
			sp->width = w;
		}
	} else {
		sp->width = parse_num(pf);
	}
	if (**pf == '.') {
		(*pf)++;
		if (**pf == '*') {
			(*pf)++;
			const int p = va_arg(*ap, int);
			/* a negative '*' precision means omitted */
			sp->prec = p < 0 ? -1 : p;
		} else {
			sp->prec = parse_num(pf);
		}
	}
	switch (**pf) {
	case 'h':
		(*pf)++;
		if (**pf == 'h') {
			(*pf)++;
			sp->length = LEN_CHAR;
		} else {
			sp->length = LEN_SHORT;
		}
		break;
	case 'l':
		(*pf)++;
		if (**pf == 'l') {
			(*pf)++;
			sp->length = LEN_LLONG;
		} else {
			sp->length = LEN_LONG;
		}
		break;
	case 'j':
		(*pf)++;
		sp->length = LEN_MAX;
		break;
	case 'z':
		(*pf)++;
		sp->length = LEN_SIZE;
		break;
	case 't':
		(*pf)++;
		sp->length = LEN_PTRDIFF;
		break;
	case 'L':
		(*pf)++;
		sp->length = LEN_LDOUBLE;
		break;
	default:
		break;
	}
	sp->conv = **pf;
}

/* each length modifier names the exact promoted type; a mismatch is UB */
static intmax_t fetch_signed(va_list *restrict ap, const enum length_mod len)
{
	if (len == LEN_CHAR) {
		return (signed char)va_arg(*ap, int);
	}
	if (len == LEN_SHORT) {
		return (short)va_arg(*ap, int);
	}
	if (len == LEN_LONG) {
		return (intmax_t)va_arg(*ap, long);
	}
	if (len == LEN_LLONG) {
		return (intmax_t)va_arg(*ap, long long);
	}
	if (len == LEN_MAX) {
		return va_arg(*ap, intmax_t);
	}
	if (len == LEN_SIZE || len == LEN_PTRDIFF) {
		/* the signed counterpart of size_t shares the width */
		return (intmax_t)va_arg(*ap, ptrdiff_t);
	}
	return va_arg(*ap, int);
}

static uintmax_t fetch_unsigned(va_list *restrict ap, const enum length_mod len)
{
	if (len == LEN_CHAR) {
		return (unsigned char)va_arg(*ap, unsigned int);
	}
	if (len == LEN_SHORT) {
		return (unsigned short)va_arg(*ap, unsigned int);
	}
	if (len == LEN_LONG) {
		return (uintmax_t)va_arg(*ap, unsigned long);
	}
	if (len == LEN_LLONG) {
		return (uintmax_t)va_arg(*ap, unsigned long long);
	}
	if (len == LEN_MAX) {
		return va_arg(*ap, uintmax_t);
	}
	if (len == LEN_SIZE || len == LEN_PTRDIFF) {
		/* z is size_t; t's unsigned counterpart shares its width */
		return (uintmax_t)va_arg(*ap, size_t);
	}
	return (uintmax_t)va_arg(*ap, unsigned int);
}

/* open a right-aligned or zero-filled field: emit the leading padding, the
 * sign and the prefix; the caller emits bodylen bytes and then the returned
 * count of trailing spaces */
static size_t pad_begin(
	struct sink *restrict s, const struct spec *restrict sp,
	const char sign, const char *restrict prefix, const size_t prefixlen,
	const size_t bodylen, const bool zero_ok)
{
	const size_t content = (sign != '\0' ? 1 : 0) + prefixlen + bodylen;
	size_t padn = 0;
	if (sp->width > 0 && (size_t)sp->width > content) {
		padn = (size_t)sp->width - content;
	}
	const bool zerofill = zero_ok && sp->zero && !sp->minus;
	if (!sp->minus && !zerofill) {
		sink_fill(s, ' ', padn);
	}
	if (sign != '\0') {
		sink_putc(s, sign);
	}
	for (size_t i = 0; i < prefixlen; i++) {
		sink_putc(s, prefix[i]);
	}
	if (zerofill) {
		sink_fill(s, '0', padn);
	}
	return sp->minus ? padn : 0;
}

static void emit_int(
	struct sink *restrict s, const struct spec *restrict sp,
	va_list *restrict ap)
{
	const char conv = sp->conv;
	const char *digitchars = "0123456789abcdef";
	const char *prefix = "";
	size_t prefixlen = 0;
	unsigned int base = 10;
	uintmax_t mag;
	char sign = '\0';
	if (conv == 'd' || conv == 'i') {
		const intmax_t v = fetch_signed(ap, sp->length);
		if (v < 0) {
			sign = '-';
			/* negate through uintmax_t: INTMAX_MIN is safe */
			mag = -(uintmax_t)v;
		} else {
			mag = (uintmax_t)v;
			if (sp->plus) {
				sign = '+';
			} else if (sp->space) {
				sign = ' ';
			}
		}
	} else {
		mag = fetch_unsigned(ap, sp->length);
		if (conv == 'o') {
			base = 8;
		} else if (conv == 'x' || conv == 'X') {
			base = 16;
			if (conv == 'X') {
				digitchars = "0123456789ABCDEF";
			}
			if (sp->hash && mag != 0) {
				prefix = conv == 'X' ? "0X" : "0x";
				prefixlen = 2;
			}
		}
	}
	char tmp[(sizeof(uintmax_t) * CHAR_BIT + 2) / 3];
	size_t ndig = 0;
	for (uintmax_t v = mag; v != 0; v /= base) {
		tmp[ndig++] = digitchars[v % base];
	}
	/* precision is the minimum digit count; 0 with value 0 prints none */
	size_t mindig = sp->prec >= 0 ? (size_t)sp->prec : 1;
	if (sp->hash && conv == 'o' && mindig <= ndig) {
		/* alternative form: force one leading zero */
		mindig = ndig + 1;
	}
	const size_t bodylen = mindig > ndig ? mindig : ndig;
	/* an explicit precision disables the '0' flag */
	const size_t trailing = pad_begin(
		s, sp, sign, prefix, prefixlen, bodylen, sp->prec < 0);
	sink_fill(s, '0', bodylen - ndig);
	while (ndig > 0) {
		sink_putc(s, tmp[--ndig]);
	}
	sink_fill(s, ' ', trailing);
}

static void emit_ptr(
	struct sink *restrict s, const struct spec *restrict sp,
	va_list *restrict ap)
{
	uintptr_t v = (uintptr_t)va_arg(*ap, void *);
	char tmp[sizeof(uintptr_t) * 2];
	size_t ndig = 0;
	do {
		tmp[ndig++] = "0123456789abcdef"[v % 16];
		v /= 16;
	} while (v != 0);
	const size_t trailing = pad_begin(s, sp, '\0', "0x", 2, ndig, false);
	while (ndig > 0) {
		sink_putc(s, tmp[--ndig]);
	}
	sink_fill(s, ' ', trailing);
}

static void emit_char(
	struct sink *restrict s, const struct spec *restrict sp,
	va_list *restrict ap)
{
	/* one byte, not a codepoint */
	const char c = (char)va_arg(*ap, int);
	size_t padn = 0;
	if (sp->width > 1) {
		padn = (size_t)sp->width - 1;
	}
	if (!sp->minus) {
		sink_fill(s, ' ', padn);
	}
	sink_putc(s, c);
	if (sp->minus) {
		sink_fill(s, ' ', padn);
	}
}

/* one unit: a valid codepoint (1-4 bytes) or a single stray byte;
 * the peek never runs past the terminator */
static size_t unit_len(const char *restrict p)
{
	const int n = utf8_decode(NULL, p, peek_avail(p));
	return n > 0 ? (size_t)n : 1;
}

static void emit_str(
	struct sink *restrict s, const struct spec *restrict sp,
	va_list *restrict ap)
{
	const char *str = va_arg(*ap, const char *);
	if (str == NULL) {
		str = "(null)";
	}
	/* precision and width count codepoints, not bytes */
	size_t units = 0, bytes = 0;
	for (const char *p = str;;) {
		/* the precision is spent first: with one specified vsnprintf(3)
		 * lets the argument stop right here without a terminator, so
		 * *p must not be read once the allowance is used up */
		if (sp->prec >= 0 && units == (size_t)sp->prec) {
			break;
		}
		if (*p == '\0') {
			break;
		}
		const size_t n = unit_len(p);
		units++;
		bytes += n;
		p += n;
	}
	size_t padn = 0;
	if (sp->width > 0 && (size_t)sp->width > units) {
		padn = (size_t)sp->width - units;
	}
	if (!sp->minus) {
		sink_fill(s, ' ', padn);
	}
	for (const char *p = str; bytes > 0;) {
		const size_t n = unit_len(p);
		sink_put(s, p, n);
		p += n;
		bytes -= n;
	}
	if (sp->minus) {
		sink_fill(s, ' ', padn);
	}
}

static size_t dec_digits(uintmax_t v)
{
	size_t n = 1;
	while (v >= 10) {
		v /= 10;
		n++;
	}
	return n;
}

static void emit_hexfloat(
	struct sink *restrict s, const struct spec *restrict sp, const double x,
	const char sign, const bool upper)
{
	const char *const xdigits =
		upper ? "0123456789ABCDEF" : "0123456789abcdef";
	const uint64_t u = float_tobits(x);
	const int be = (int)((u >> 52) & 0x7FF);
	const uint64_t frac = u & ((UINT64_C(1) << 52) - 1);
	int lead = be != 0 ? 1 : 0;
	const int sub_e2 = frac != 0 ? -1022 : 0;
	const int e2 = be != 0 ? be - 1023 : sub_e2;
	int shown; /* fraction nibbles taken from hfrac */
	size_t zext = 0; /* zero nibbles appended beyond the mantissa */
	uint64_t hfrac;
	if (sp->prec < 0) {
		/* omitted precision: minimal digits */
		shown = 13;
		for (uint64_t f = frac; shown > 0 && (f & 0xF) == 0; f >>= 4) {
			shown--;
		}
		hfrac = frac >> (4 * (13 - shown));
	} else if (sp->prec >= 13) {
		shown = 13;
		hfrac = frac;
		zext = (size_t)sp->prec - 13;
	} else {
		shown = sp->prec;
		const int dropbits = 4 * (13 - shown);
		const uint64_t half = UINT64_C(1) << (dropbits - 1);
		const uint64_t tail = frac & ((half << 1) - 1);
		hfrac = frac >> dropbits;
		/* round-half-even; at precision 0 the leading digit decides */
		const int lastkept = shown > 0 ? (int)(hfrac & 1) : (lead & 1);
		if (tail > half || (tail == half && lastkept != 0)) {
			hfrac++;
			if ((hfrac >> (4 * shown)) != 0) {
				/* carry into the leading digit; the exponent
				 * is not renormalized */
				hfrac = 0;
				lead++;
			}
		}
	}
	const bool dot = shown > 0 || zext > 0 || sp->hash;
	const size_t explen = dec_digits((uintmax_t)(e2 < 0 ? -e2 : e2));
	const size_t bodylen =
		1 + (dot ? 1 + (size_t)shown + zext : 0) + 2 + explen;
	const size_t trailing =
		pad_begin(s, sp, sign, upper ? "0X" : "0x", 2, bodylen, true);
	sink_putc(s, xdigits[lead]);
	if (dot) {
		sink_putc(s, '.');
		for (int i = shown - 1; i >= 0; i--) {
			sink_putc(s, xdigits[(hfrac >> (4 * i)) & 0xF]);
		}
		sink_fill(s, '0', zext);
	}
	sink_putc(s, upper ? 'P' : 'p');
	sink_putc(s, e2 < 0 ? '-' : '+');
	sink_putu(s, (uintmax_t)(e2 < 0 ? -e2 : e2));
	sink_fill(s, ' ', trailing);
}

/* d1.d2..e±XX; digits beyond n are zeros, frac is the fraction length */
static void emit_estyle(
	struct sink *restrict s, const struct spec *restrict sp,
	const char sign, const char *restrict dig, const int n, const int x10,
	const size_t frac, const bool upper)
{
	const bool dot = frac > 0 || sp->hash;
	const int xa = x10 < 0 ? -x10 : x10;
	size_t explen = dec_digits((uintmax_t)xa);
	if (explen < 2) {
		explen = 2;
	}
	const size_t bodylen = 1 + (dot ? 1 + frac : 0) + 2 + explen;
	const size_t trailing = pad_begin(s, sp, sign, "", 0, bodylen, true);
	if (n > 0) {
		sink_putc(s, dig[0]);
	} else {
		sink_putc(s, '0');
	}
	if (dot) {
		sink_putc(s, '.');
		const size_t have = n > 1 ? (size_t)(n - 1) : 0;
		for (size_t i = 0; i < have; i++) {
			sink_putc(s, dig[i + 1]);
		}
		sink_fill(s, '0', frac - have);
	}
	sink_putc(s, upper ? 'E' : 'e');
	sink_putc(s, x10 < 0 ? '-' : '+');
	if (xa < 10) {
		sink_putc(s, '0');
	}
	sink_putu(s, (uintmax_t)xa);
	sink_fill(s, ' ', trailing);
}

/* ddd.ddd; the significant digit at position k+m fills fraction place m */
static void emit_fstyle(
	struct sink *restrict s, const struct spec *restrict sp,
	const char sign, const char *restrict dig, const int n, const int k,
	const size_t frac)
{
	const size_t intlen = k > 0 ? (size_t)k : 1;
	const bool dot = frac > 0 || sp->hash;
	const size_t bodylen = intlen + (dot ? 1 + frac : 0);
	const size_t trailing = pad_begin(s, sp, sign, "", 0, bodylen, true);
	if (k > 0) {
		const int m = n < k ? n : k;
		for (int i = 0; i < m; i++) {
			sink_putc(s, dig[i]);
		}
		sink_fill(s, '0', (size_t)(k - m));
	} else {
		sink_putc(s, '0');
	}
	if (dot) {
		sink_putc(s, '.');
		size_t zlead = k < 0 ? (size_t)-k : 0;
		if (zlead > frac) {
			zlead = frac;
		}
		sink_fill(s, '0', zlead);
		const int j0 = k > 0 ? k : 0;
		size_t c = n > j0 ? (size_t)(n - j0) : 0;
		if (c > frac - zlead) {
			c = frac - zlead;
		}
		for (size_t i = 0; i < c; i++) {
			sink_putc(s, dig[(size_t)j0 + i]);
		}
		sink_fill(s, '0', frac - zlead - c);
	}
	sink_fill(s, ' ', trailing);
}

static void emit_float(
	struct sink *restrict s, const struct spec *restrict sp,
	va_list *restrict ap)
{
	/* the L modifier still names the argument type; extra precision is
	 * deliberately dropped */
	const double x = sp->length == LEN_LDOUBLE ?
				 (double)va_arg(*ap, long double) :
				 va_arg(*ap, double);
	const bool upper = sp->conv >= 'A' && sp->conv <= 'Z';
	const char conv = (char)(sp->conv | 0x20);
	char sign = '\0';
	if (float_signbit(x)) {
		sign = '-';
	} else if (sp->plus) {
		sign = '+';
	} else if (sp->space) {
		sign = ' ';
	}
	switch (float_classify(x)) {
	case FLOAT_INF:
	case FLOAT_NAN: {
		const char *body;
		if (float_classify(x) == FLOAT_INF) {
			body = upper ? "INF" : "inf";
		} else {
			body = upper ? "NAN" : "nan";
		}
		const size_t trailing = pad_begin(s, sp, sign, "", 0, 3, false);
		for (int i = 0; i < 3; i++) {
			sink_putc(s, body[i]);
		}
		sink_fill(s, ' ', trailing);
		return;
	}
	default:
		break;
	}
	if (conv == 'a') {
		emit_hexfloat(s, sp, x, sign, upper);
		return;
	}
	const int prec = sp->prec >= 0 ? sp->prec : 6;
	char dig[FLOAT_DECIMAL_DIGITS];
	int k = 0;
	if (conv == 'e') {
		const int n = float_todecimal(
			x, prec < INT_MAX ? prec + 1 : INT_MAX, dig, &k);
		emit_estyle(
			s, sp, sign, dig, n, n > 0 ? k - 1 : 0, (size_t)prec,
			upper);
		return;
	}
	if (conv == 'f') {
		int n = float_todecimal(x, FLOAT_DECIMAL_DIGITS, dig, &k);
		/* the cut at 10^-prec keeps k+prec significant digits */
		const long long nd = (long long)k + prec;
		if (nd < n) {
			n = float_todecimal(x, (int)nd, dig, &k);
		}
		emit_fstyle(s, sp, sign, dig, n, n > 0 ? k : 0, (size_t)prec);
		return;
	}
	/* 'g': round first, then choose the style on the rounded exponent */
	const int p = prec == 0 ? 1 : prec;
	const int n = float_todecimal(x, p, dig, &k);
	const int x10 = n > 0 ? k - 1 : 0;
	if (x10 < -4 || x10 >= p) {
		size_t frac = n > 1 ? (size_t)(n - 1) : 0;
		if (sp->hash) {
			frac = (size_t)(p - 1);
		}
		emit_estyle(s, sp, sign, dig, n, x10, frac, upper);
		return;
	}
	size_t frac = n - k > 0 ? (size_t)(n - k) : 0;
	if (sp->hash) {
		/* x10 may be negative: p - 1 - x10 exceeds INT_MAX when p is
		 * near it */
		frac = (size_t)((long long)p - 1 - x10);
	}
	emit_fstyle(s, sp, sign, dig, n, n > 0 ? k : 0, frac);
}

int u8vsnprintf(
	char *restrict buf, const size_t maxlen, const char *restrict format,
	va_list args)
{
	struct sink s = {
		.buf = buf,
		.cap = (buf != NULL && maxlen > 0) ? maxlen - 1 : 0,
	};
	/* a local copy makes &ap portable even when va_list is an array */
	va_list ap;
	va_copy(ap, args);
	for (const char *f = format; *f != '\0'; f++) {
		if (*f != '%') {
			/* copy a literal run as whole UTF-8 units, so a
			 * multibyte codepoint in the format string is never
			 * split on truncation (as the %s path already does) */
			const size_t n = unit_len(f);
			sink_put(&s, f, n);
			f += n - 1; /* the loop's f++ advances the last byte */
			continue;
		}
		const char *const start = f;
		f++;
		if (*f == '%') {
			sink_putc(&s, '%');
			continue;
		}
		struct spec sp;
		parse_spec(&sp, &f, &ap);
		switch (sp.conv) {
		case 'd':
		case 'i':
		case 'u':
		case 'o':
		case 'x':
		case 'X':
			emit_int(&s, &sp, &ap);
			continue;
		case 'c':
			if (sp.length == LEN_NONE) {
				emit_char(&s, &sp, &ap);
				continue;
			}
			break;
		case 's':
			if (sp.length == LEN_NONE) {
				emit_str(&s, &sp, &ap);
				continue;
			}
			break;
		case 'p':
			emit_ptr(&s, &sp, &ap);
			continue;
		case 'f':
		case 'F':
		case 'e':
		case 'E':
		case 'g':
		case 'G':
		case 'a':
		case 'A':
			emit_float(&s, &sp, &ap);
			continue;
		default:
			break;
		}
		/* unknown or unsupported (%n, %lc, ...): echo the raw spec
		 * and consume no conversion argument; a '*' width or
		 * precision was already consumed by parse_spec. The spec prefix
		 * [start, f) is ASCII; the conversion char at f may be a
		 * multibyte lead byte, so echo it as a whole UTF-8 unit. */
		sink_put(&s, start, (size_t)(f - start));
		if (sp.conv == '\0') {
			/* malformed spec hit the terminator */
			break;
		}
		const size_t cn = unit_len(f);
		sink_put(&s, f, cn);
		f += cn - 1; /* the loop's f++ advances the last byte */
	}
	va_end(ap);
	if (buf != NULL && maxlen > 0) {
		buf[s.fill] = '\0';
	}
	return s.len > INT_MAX ? -1 : (int)s.len;
}

int u8snprintf(
	char *restrict buf, const size_t maxlen, const char *restrict format,
	...)
{
	va_list args;
	va_start(args, format);
	const int ret = u8vsnprintf(buf, maxlen, format, args);
	va_end(args);
	return ret;
}

/* --- locale-free, async-signal-safe scanf --------------------------------- *
 * The mirror of the printf above: input is walked one codepoint at a time and
 * the decimal float parse is handed to math/float.h's float_fromdecimal, so no
 * libc function is called on any path. Whitespace and literal matching are
 * codepoint-aware; numeric syntax is ASCII.
 */

enum scan_status { SCAN_OK, SCAN_NOMATCH, SCAN_INPUT_END };

/* Keep scanner output independent of libc. The volatile destination prevents
 * an optimizing compiler from recognizing this loop as a memcpy call. */
static void
copy_scan_bytes(char *restrict out, const char *restrict in, const size_t len)
{
	volatile char *const dst = out;
	for (size_t i = 0; i < len; i++) {
		dst[i] = in[i];
	}
}

/* Round mant * 2^e2 (plus a positive tail below 2^e2 iff sticky) to the nearest
 * binary64 magnitude, round-half-even. The uint64 analog of float.c's assemble,
 * used only for the exact hexfloat path. */
static double scale2(uint64_t mant, const int e2, bool sticky)
{
	if (mant == 0) {
		return 0.0;
	}
	int bl = 0;
	for (uint64_t v = mant; v != 0; v >>= 1) {
		bl++;
	}
	int expb = bl + e2 + 1022;
	int drop = bl - 53;
	if (expb < 1) {
		drop = -1074 - e2;
		expb = 0;
	}
	uint64_t m;
	int roundbit = 0;
	if (drop <= 0) {
		m = mant << -drop;
	} else if (drop < 64) {
		m = mant >> drop;
		roundbit = (int)((mant >> (drop - 1)) & 1);
		if ((mant & ((UINT64_C(1) << (drop - 1)) - 1)) != 0) {
			sticky = true;
		}
	} else {
		m = 0;
		if (drop == 64) {
			roundbit = (int)(mant >> 63);
			sticky = sticky ||
				 (mant & ((UINT64_C(1) << 63) - 1)) != 0;
		} else {
			sticky = true;
		}
	}
	if (roundbit != 0 && (sticky || (m & 1) != 0)) {
		m++;
	}
	if (expb == 0) {
		return float_frombits(m);
	}
	if (m == (UINT64_C(1) << 53)) {
		m >>= 1;
		expb++;
	}
	if (expb >= 2047) {
		return float_frombits(UINT64_C(0x7FF) << 52);
	}
	return float_frombits(
		(uint64_t)expb << 52 | (m & ((UINT64_C(1) << 52) - 1)));
}

/* Exponent magnitude that saturates both conversions below to +inf or +0
 * whatever the significand: far outside the finite binary64 range. */
enum { EXP_LIMIT = 100000000 };

/* Clamp an exponent counted over a digit run of arbitrary length: past
 * EXP_LIMIT the conversion saturates to the same value either way. */
static int clamp_exp(const int_fast64_t e)
{
	if (e > EXP_LIMIT) {
		return EXP_LIMIT;
	}
	if (e < -EXP_LIMIT) {
		return -EXP_LIMIT;
	}
	return (int)e;
}

/* Value of an ASCII base-36 digit (0-9, A-Z, a-z -> 0..35), or -1. */
static int digit_value(const char c)
{
	if ('0' <= c && c <= '9') {
		return c - '0';
	}
	if ('A' <= c && c <= 'Z') {
		return (c - 'A') + 10;
	}
	if ('a' <= c && c <= 'z') {
		return (c - 'a') + 10;
	}
	return -1;
}

/* length of tok if the ASCII-case-insensitive prefix matches at p, else 0 */
static int match_ci(const char *restrict p, const char *restrict tok)
{
	int i = 0;
	for (; tok[i] != '\0'; i++) {
		char c = p[i];
		if ('A' <= c && c <= 'Z') {
			c = (char)(c + ('a' - 'A'));
		}
		if (c != tok[i]) {
			return 0;
		}
	}
	return i;
}

static const char *skip_ws(const char *restrict p)
{
	for (;;) {
		char32_t cp;
		const char *q = p;
		if (utf8_next(&cp, &q) == 0 || !is_space32(cp)) {
			return p;
		}
		p = q;
	}
}

/* Is the unit decoded as c from the n bytes at unit a member of the [set]
 * spelled by format bytes [begin, end)? A 'lo-hi' triple is a range in unit_key
 * order; a '-' with no bound is literal. */
static bool scanset_match(
	const char32_t c, const int n, const char *restrict unit,
	const char *restrict begin, const char *restrict end, const bool negate)
{
	const uint_fast32_t key = unit_key(c, n, unit);
	bool found = false;
	const char *s = begin;
	while (s < end) {
		char32_t lo;
		const char *q = s;
		const int lon = utf8_next(&lo, &q);
		const uint_fast32_t lokey = unit_key(lo, lon, s);
		if (q < end && *q == '-' && q + 1 < end) {
			char32_t hi;
			const char *r = q + 1;
			const int hin = utf8_next(&hi, &r);
			if (lokey <= key && key <= unit_key(hi, hin, q + 1)) {
				found = true;
			}
			s = r;
			continue;
		}
		if (lokey == key) {
			found = true;
		}
		s = q;
	}
	return found != negate;
}

static void
store_signed(va_list *restrict ap, const enum length_mod len, const intmax_t v)
{
	switch (len) {
	case LEN_CHAR:
		*va_arg(*ap, signed char *) = (signed char)v;
		break;
	case LEN_SHORT:
		*va_arg(*ap, short *) = (short)v;
		break;
	case LEN_LONG:
		*va_arg(*ap, long *) = (long)v;
		break;
	case LEN_LLONG:
		*va_arg(*ap, long long *) = (long long)v;
		break;
	case LEN_MAX:
		*va_arg(*ap, intmax_t *) = v;
		break;
	case LEN_SIZE:
	case LEN_PTRDIFF:
		/* z's signed counterpart shares ptrdiff_t's width */
		*va_arg(*ap, ptrdiff_t *) = (ptrdiff_t)v;
		break;
	default:
		*va_arg(*ap, int *) = (int)v;
		break;
	}
}

static void store_unsigned(
	va_list *restrict ap, const enum length_mod len, const uintmax_t v)
{
	switch (len) {
	case LEN_CHAR:
		*va_arg(*ap, unsigned char *) = (unsigned char)v;
		break;
	case LEN_SHORT:
		*va_arg(*ap, unsigned short *) = (unsigned short)v;
		break;
	case LEN_LONG:
		*va_arg(*ap, unsigned long *) = (unsigned long)v;
		break;
	case LEN_LLONG:
		*va_arg(*ap, unsigned long long *) = (unsigned long long)v;
		break;
	case LEN_MAX:
		*va_arg(*ap, uintmax_t *) = v;
		break;
	case LEN_SIZE:
	case LEN_PTRDIFF:
		/* t's unsigned counterpart shares size_t's width */
		*va_arg(*ap, size_t *) = (size_t)v;
		break;
	default:
		*va_arg(*ap, unsigned int *) = (unsigned int)v;
		break;
	}
}

static void store_float(
	va_list *restrict ap, const enum length_mod len, const bool neg,
	const double mag)
{
	const double v = neg ? -mag : mag;
	switch (len) {
	case LEN_LONG:
		*va_arg(*ap, double *) = v;
		break;
	case LEN_LDOUBLE:
		*va_arg(*ap, long double *) = (long double)v;
		break;
	default:
		*va_arg(*ap, float *) = (float)v;
		break;
	}
}

struct scanspec {
	bool suppress; /* '*' */
	int width; /* 0 = unbounded */
	enum length_mod length;
	char conv;
};

static void
parse_scanspec(struct scanspec *restrict sp, const char **restrict pf)
{
	*sp = (struct scanspec){ 0 };
	if (**pf == '*') {
		sp->suppress = true;
		(*pf)++;
	}
	sp->width = parse_num(pf);

	switch (**pf) {
	case 'h':
		(*pf)++;
		if (**pf == 'h') {
			(*pf)++;
			sp->length = LEN_CHAR;
		} else {
			sp->length = LEN_SHORT;
		}
		break;
	case 'l':
		(*pf)++;
		if (**pf == 'l') {
			(*pf)++;
			sp->length = LEN_LLONG;
		} else {
			sp->length = LEN_LONG;
		}
		break;
	case 'j':
		(*pf)++;
		sp->length = LEN_MAX;
		break;
	case 'z':
		(*pf)++;
		sp->length = LEN_SIZE;
		break;
	case 't':
		(*pf)++;
		sp->length = LEN_PTRDIFF;
		break;
	case 'L':
		(*pf)++;
		sp->length = LEN_LDOUBLE;
		break;
	default:
		break;
	}
	sp->conv = **pf;
}

/* consume up to maxw base digits; returns the count and the value */
static int read_uint(
	const char **restrict pp, const unsigned int base, const int maxw,
	uintmax_t *restrict out)
{
	const char *p = *pp;
	uintmax_t v = 0;
	int n = 0;
	for (; n < maxw; n++) {
		const int d = unhex((char32_t)(unsigned char)*p);
		if (d < 0 || (unsigned int)d >= base) {
			break;
		}
		v = v * base + (unsigned int)d;
		p++;
	}
	*out = v;
	*pp = p;
	return n;
}

static enum scan_status read_int(
	const char **restrict in, const struct scanspec *restrict sp,
	va_list *restrict ap)
{
	const char *p = skip_ws(*in);
	if (*p == '\0') {
		return SCAN_INPUT_END;
	}
	const int maxw = sp->width > 0 ? sp->width : INT_MAX;
	int used = 0;
	bool neg = false;
	if ((*p == '+' || *p == '-') && used < maxw) {
		neg = (*p == '-');
		p++;
		used++;
	}
	const char conv = sp->conv;
	unsigned int base;
	bool is_signed;
	switch (conv) {
	case 'd':
		base = 10, is_signed = true;
		break;
	case 'i':
		base = 0, is_signed = true;
		break;
	case 'u':
		base = 10, is_signed = false;
		break;
	case 'o':
		base = 8, is_signed = false;
		break;
	default: /* x X p */
		base = 16, is_signed = false;
		break;
	}
	bool prefixed = false;
	/* accept a 0x prefix for hex and auto base, or a leading 0 as octal */
	if ((base == 0 || base == 16) && *p == '0') {
		if ((p[1] == 'x' || p[1] == 'X') && used + 2 <= maxw) {
			base = 16;
			p += 2;
			used += 2;
			prefixed = true;
		} else if (base == 0) {
			base = 8;
		}
	}
	if (base == 0) {
		base = 10;
	}
	/* This scanner accepts a consumed "0x" without digits as zero. C11
	 * 7.21.6.2 instead treats that incomplete matching prefix as failure. */
	uintmax_t val;
	if (read_uint(&p, base, maxw - used, &val) == 0 && !prefixed) {
		return SCAN_NOMATCH;
	}
	if (!sp->suppress) {
		if (conv == 'p') {
			*va_arg(*ap, void **) = (void *)(uintptr_t)val;
		} else if (is_signed) {
			/* form the result in uintmax_t: negating (intmax_t)val
			 * would overflow at the INTMAX_MIN magnitude */
			const uintmax_t u = neg ? (uintmax_t)0 - val : val;
			store_signed(ap, sp->length, (intmax_t)u);
		} else {
			store_unsigned(
				ap, sp->length, neg ? (uintmax_t)0 - val : val);
		}
	}
	*in = p;
	return SCAN_OK;
}

/* Fold a float item's optional exponent part at *pp -- the marker (either
 * case), an optional sign and a digit run -- into e, the exponent its digit run
 * already carries, and return the sum clamped. The part shares the item's field
 * width, maxw characters of which used are spent: one that does not fit whole
 * is left unconsumed by this parser. Scanf's C11 7.21.6.2 input item instead
 * includes an incomplete exponent prefix and fails its conversion. */
static int read_exponent(
	const char **restrict pp, const int maxw, const int used,
	const char *restrict marker, const int_fast64_t e)
{
	const char *p = *pp;
	if (used >= maxw || match_ci(p, marker) == 0) {
		return clamp_exp(e);
	}
	p++;
	int eused = used + 1;
	bool neg = false;
	if (eused < maxw && (*p == '+' || *p == '-')) {
		neg = (*p == '-');
		p++;
		eused++;
	}
	if (eused >= maxw || *p < '0' || *p > '9') {
		return clamp_exp(e);
	}
	/* Past EXP_LIMIT + |e| the sum lies beyond EXP_LIMIT on the explicit
	 * exponent's side whatever e is, so it clamps to the same bound as any
	 * larger explicit exponent would: saturating there loses nothing, and
	 * bounds the sum by 2|e| + EXP_LIMIT however many digits it has. */
	const int_fast64_t cap = EXP_LIMIT + (e < 0 ? -e : e);
	int_fast64_t ev = 0;
	for (; eused < maxw && '0' <= *p && *p <= '9'; p++, eused++) {
		ev = ev * 10 + (*p - '0');
		if (ev > cap) {
			ev = cap;
		}
	}
	*pp = p;
	return clamp_exp(neg ? e - ev : e + ev);
}

/* value = mant * 2^binexp; after "0x", up to maxw-used more chars */
static double read_hexfloat(
	const char **restrict pp, const int maxw, int used, bool *restrict ok)
{
	const char *p = *pp;
	uint64_t mant = 0;
	/* every digit the mantissa cannot hold shifts the exponent by 4, for as
	 * many digits as the field width allows */
	int_fast64_t binexp = 0;
	bool dot = false, sticky = false;
	int ndig = 0;
	for (; used < maxw; used++) {
		if (*p == '.' && !dot) {
			dot = true;
			p++;
			continue;
		}
		const int h = unhex((char32_t)(unsigned char)*p);
		if (h < 0) {
			break;
		}
		p++;
		ndig++;
		if (mant < (UINT64_C(1) << 59)) {
			mant = mant * 16 + (unsigned int)h;
			if (dot) {
				binexp -= 4;
			}
		} else {
			if (!dot) {
				binexp += 4;
			}
			sticky = sticky || h != 0;
		}
	}
	if (ndig == 0) {
		*ok = false;
		return 0.0;
	}
	const int e2 = read_exponent(&p, maxw, used, "p", binexp);
	*pp = p;
	*ok = true;
	return scale2(mant, e2, sticky);
}

/* A decimal float at *pp -- a digit run with an optional '.', then an optional
 * exponent part -- within maxw characters, used of which are spent. Stores the
 * magnitude in *mag and sets *nonzero if a nonzero digit was read; returns
 * false, *pp untouched, when there is no digit. */
static bool read_decfloat(
	const char **restrict pp, const int maxw, int used,
	bool *restrict nonzero, double *restrict mag)
{
	const char *p = *pp;
	char digits[FLOAT_ROUND_DIGITS + 1];
	int nd = 0;
	/* the digit run is bounded only by the input */
	int_fast64_t intdigits = 0, lead = 0;
	bool dot = false, any = false, tail = false;
	*nonzero = false;
	for (; used < maxw; used++) {
		if (*p == '.' && !dot) {
			dot = true;
			p++;
			continue;
		}
		if (*p < '0' || *p > '9') {
			break;
		}
		any = true;
		if (*p != '0') {
			*nonzero = true;
		}
		if (!dot) {
			intdigits++;
		}
		if (nd == 0 && *p == '0') {
			/* leading zeros only shift the exponent */
			lead++;
		} else if (nd < FLOAT_ROUND_DIGITS) {
			digits[nd++] = *p;
		} else if (*p != '0') {
			tail = true;
		}
		p++;
	}
	if (!any) {
		return false;
	}
	if (tail) {
		/* one nonzero digit past the last that rounding can use stands
		 * for the dropped tail: it moves the value off an exact tie
		 * without crossing a rounding boundary */
		digits[nd++] = '1';
	}
	const int k = read_exponent(&p, maxw, used, "e", intdigits - lead);
	*mag = float_fromdecimal(digits, nd, k);
	*pp = p;
	return true;
}

/* The float subject sequence of strtod(3) at *pp, leading whitespace already
 * skipped: an optional sign, then "inf" or "infinity", "nan" with an optional
 * "(n-char-sequence)", or a hexadecimal or decimal float (C11 7.22.1.3), all
 * within a field width of maxw characters. On a match, advances *pp past it,
 * stores its sign in *neg and its magnitude in *mag, and sets *range if a
 * numeric value overflowed to infinity or a nonzero decimal one underflowed to
 * zero; returns false, *pp untouched, when no float matches. */
static bool parse_float(
	const char **restrict pp, const int maxw, bool *restrict neg,
	double *restrict mag, bool *restrict range)
{
	const char *p = *pp;
	int used = 0;
	*neg = false;
	*range = false;
	if ((*p == '+' || *p == '-') && used < maxw) {
		*neg = (*p == '-');
		p++;
		used++;
	}
	/* The infinity and NaN spellings are input items like any other, so
	 * they match only when they fit whole within the field width; a
	 * shorter width falls through to the numeric branches, which then find
	 * no digits and report a matching failure. */
	if (used + 3 <= maxw && match_ci(p, "inf") != 0) {
		/* The item runs as far along the spelling as the width allows
		 * (C11 7.21.6.2), and only "inf" and "infinity" are matching
		 * sequences -- a width stopping anywhere between them yields a
		 * mere prefix, which is a matching failure rather than a
		 * shorter match. */
		int n = 3;
		if (match_ci(p + 3, "inity") != 0) {
			while (n < 8 && used + n + 1 <= maxw) {
				n++;
			}
			if (n != 3 && n != 8) {
				return false;
			}
		}
		p += n;
		*mag = float_frombits(UINT64_C(0x7FF) << 52);
	} else if (used + 3 <= maxw && match_ci(p, "nan") != 0) {
		/* This parser backs off to "nan" if a payload is malformed,
		 * unterminated or cut by the width. Scanf's C11 7.21.6.2 rule
		 * instead fails an incomplete matching prefix such as "nan(abc". */
		int n = 3;
		if (p[3] == '(' && used + 4 <= maxw) {
			const char *q = p + 4;
			while (digit_value(*q) >= 0 || *q == '_') {
				q++;
			}
			/* compared as a distance so a sequence longer than int
			 * cannot wrap into a negative width */
			const ptrdiff_t full = q + 1 - p;
			if (*q == ')' && full <= (ptrdiff_t)(maxw - used)) {
				n = (int)full;
			}
		}
		p += n;
		*mag = float_frombits(UINT64_C(0x7FF8) << 48);
	} else if (
		used + 2 < maxw && *p == '0' && (p[1] == 'x' || p[1] == 'X') &&
		(unhex((char32_t)(unsigned char)p[2]) >= 0 ||
		 (p[2] == '.' && unhex((char32_t)(unsigned char)p[3]) >= 0))) {
		p += 2;
		bool ok;
		*mag = read_hexfloat(&p, maxw, used + 2, &ok);
		if (!ok) {
			return false;
		}
		*range = float_classify(*mag) == FLOAT_INF;
	} else {
		bool nonzero;
		if (!read_decfloat(&p, maxw, used, &nonzero, mag)) {
			return false;
		}
		*range = float_classify(*mag) == FLOAT_INF ||
			 (*mag == 0.0 && nonzero);
	}
	*pp = p;
	return true;
}

static enum scan_status read_float(
	const char **restrict in, const struct scanspec *restrict sp,
	va_list *restrict ap)
{
	const char *p = skip_ws(*in);
	if (*p == '\0') {
		return SCAN_INPUT_END;
	}
	const int maxw = sp->width > 0 ? sp->width : INT_MAX;
	bool neg, range;
	double mag;
	if (!parse_float(&p, maxw, &neg, &mag, &range)) {
		return SCAN_NOMATCH;
	}
	if (range) {
		errno = ERANGE;
	}
	if (!sp->suppress) {
		store_float(ap, sp->length, neg, mag);
	}
	*in = p;
	return SCAN_OK;
}

static enum scan_status read_str(
	const char **restrict in, const struct scanspec *restrict sp,
	va_list *restrict ap)
{
	const char *p = skip_ws(*in);
	if (*p == '\0') {
		return SCAN_INPUT_END;
	}
	const int maxw = sp->width > 0 ? sp->width : INT_MAX;
	char *out = sp->suppress ? NULL : va_arg(*ap, char *);
	for (int n = 0; n < maxw;) {
		char32_t cp;
		const char *q = p;
		const int len = utf8_next(&cp, &q);
		if (len == 0 || is_space32(cp)) {
			break;
		}
		if (out != NULL) {
			copy_scan_bytes(out, p, (size_t)len);
			out += len;
		}
		p = q;
		n++;
	}
	if (out != NULL) {
		*out = '\0';
	}
	*in = p;
	return SCAN_OK;
}

static enum scan_status read_char(
	const char **restrict in, const struct scanspec *restrict sp,
	va_list *restrict ap)
{
	const char *p = *in; /* no leading-whitespace skip */
	const int want = sp->width > 0 ? sp->width : 1;
	char *out = sp->suppress ? NULL : va_arg(*ap, char *);
	int got = 0;
	for (; got < want; got++) {
		char32_t cp;
		const char *q = p;
		const int len = utf8_next(&cp, &q);
		if (len == 0) {
			break;
		}
		if (out != NULL) {
			copy_scan_bytes(out, p, (size_t)len);
			out += len;
		}
		p = q;
	}
	if (got == 0) {
		return SCAN_INPUT_END;
	}
	*in = p;
	return SCAN_OK;
}

static enum scan_status read_scanset(
	const char **restrict in, const struct scanspec *restrict sp,
	const char *restrict setb, const char *restrict sete, const bool neg,
	va_list *restrict ap)
{
	const char *p = *in; /* no leading-whitespace skip */
	if (*p == '\0') {
		return SCAN_INPUT_END;
	}
	const int maxw = sp->width > 0 ? sp->width : INT_MAX;
	char *out = sp->suppress ? NULL : va_arg(*ap, char *);
	int n = 0;
	for (; n < maxw; n++) {
		char32_t cp;
		const char *q = p;
		const int len = utf8_next(&cp, &q);
		if (len == 0 || !scanset_match(cp, len, p, setb, sete, neg)) {
			break;
		}
		if (out != NULL) {
			copy_scan_bytes(out, p, (size_t)len);
			out += len;
		}
		p = q;
	}
	if (n == 0) {
		return SCAN_NOMATCH;
	}
	if (out != NULL) {
		*out = '\0';
	}
	*in = p;
	return SCAN_OK;
}

int u8vsscanf(
	const char *restrict str, const char *restrict format, va_list args)
{
	va_list ap;
	va_copy(ap, args);
	const char *in = str;
	int count = 0;
	bool input_end = false;
	const char *f = format;
	while (*f != '\0') {
		if (*f != '%') {
			char32_t fcp;
			const char *fq = f;
			const int fn = utf8_next(&fcp, &fq);
			if (is_space32(fcp)) {
				in = skip_ws(in);
				f = fq;
				continue;
			}
			char32_t icp;
			const char *iq = in;
			const int in_len = utf8_next(&icp, &iq);
			if (in_len == 0) {
				input_end = true;
				break;
			}
			if (unit_key(icp, in_len, in) != unit_key(fcp, fn, f)) {
				break;
			}
			in = iq;
			f = fq;
			continue;
		}
		f++;
		if (*f == '%') {
			/* Match a literal '%'. This is a conversion
			 * specification like any other, so it skips leading
			 * input whitespace first -- only [, c and n do not. */
			in = skip_ws(in);
			if (*in != '%') {
				input_end = (*in == '\0');
				break;
			}
			in++;
			f++;
			continue;
		}
		struct scanspec sp;
		parse_scanspec(&sp, &f); /* f now at the conversion char */
		const char conv = sp.conv;
		const char *setb = NULL, *sete = NULL;
		bool neg = false;
		if (conv == '[') {
			const char *s = f + 1;
			if (*s == '^') {
				neg = true;
				s++;
			}
			setb = s;
			if (*s == ']') {
				s++;
			}
			while (*s != '\0' && *s != ']') {
				s++;
			}
			sete = s;
			if (*s == ']') {
				s++;
			}
			f = s;
		} else if (conv != '\0') {
			f++;
		}
		enum scan_status st;
		switch (conv) {
		case 'd':
		case 'i':
		case 'u':
		case 'o':
		case 'x':
		case 'X':
		case 'p':
			st = read_int(&in, &sp, &ap);
			break;
		case 'f':
		case 'F':
		case 'e':
		case 'E':
		case 'g':
		case 'G':
		case 'a':
		case 'A':
			st = read_float(&in, &sp, &ap);
			break;
		case 's':
			st = sp.length != LEN_NONE ? SCAN_NOMATCH :
						     read_str(&in, &sp, &ap);
			break;
		case 'c':
			st = sp.length != LEN_NONE ? SCAN_NOMATCH :
						     read_char(&in, &sp, &ap);
			break;
		case '[':
			st = sp.length != LEN_NONE ?
				     SCAN_NOMATCH :
				     read_scanset(
					     &in, &sp, setb, sete, neg, &ap);
			break;
		default:
			/* '\0' (malformed) or unsupported (%n, %ls, ...): stop */
			st = SCAN_NOMATCH;
			break;
		}
		if (st == SCAN_INPUT_END) {
			input_end = true;
			break;
		}
		if (st == SCAN_NOMATCH) {
			break;
		}
		if (!sp.suppress) {
			count++;
		}
	}
	va_end(ap);
	return count == 0 && input_end ? -1 : count;
}

int u8sscanf(const char *restrict str, const char *restrict format, ...)
{
	va_list args;
	va_start(args, format);
	const int ret = u8vsscanf(str, format, args);
	va_end(args);
	return ret;
}

/* --- locale-free strtol/strtoul/strtod ------------------------------------ *
 * The <stdlib.h> numeric parsers, locale-independent and matching the C
 * library's endptr + errno=ERANGE contract. They share the number parsing
 * above: skip_ws for leading whitespace, and parse_float, the subject-sequence
 * parser behind u8sscanf's float conversions, for u8strtod. Only errno may be
 * touched here; the parse itself calls no libc.
 */

/* Parse the integer subject sequence of s: leading whitespace, an optional sign,
 * a base prefix, then the digit run. Returns the magnitude (wrapping past
 * ULONG_MAX), sets *neg for a minus sign and *overflow when the magnitude
 * exceeds ULONG_MAX. *endptr is left past the last digit, or at s when no digit
 * is present (no conversion). */
static unsigned long strtoint(
	const char *restrict s, char **restrict endptr, int base,
	bool *restrict neg, bool *restrict overflow)
{
	*neg = false;
	*overflow = false;
	if (base != 0 && (base < 2 || base > 36)) {
		if (endptr != NULL) {
			*endptr = (char *)s;
		}
		return 0;
	}
	const char *p = skip_ws(s);
	bool negative = false;
	if (*p == '+' || *p == '-') {
		negative = (*p == '-');
		p++;
	}
	if ((base == 0 || base == 16) && p[0] == '0' &&
	    (p[1] == 'x' || p[1] == 'X') && digit_value(p[2]) >= 0 &&
	    digit_value(p[2]) < 16) {
		p += 2;
		base = 16;
	} else if (base == 0) {
		base = p[0] == '0' ? 8 : 10;
	}
	unsigned long val = 0;
	bool any = false, ovf = false;
	for (;;) {
		const int d = digit_value(*p);
		if (d < 0 || d >= base) {
			break;
		}
		any = true;
		if (val >
		    (ULONG_MAX - (unsigned long)d) / (unsigned long)base) {
			ovf = true;
		}
		val = val * (unsigned long)base + (unsigned long)d;
		p++;
	}
	if (!any) {
		if (endptr != NULL) {
			*endptr = (char *)s;
		}
		return 0;
	}
	if (endptr != NULL) {
		*endptr = (char *)p;
	}
	*neg = negative;
	*overflow = ovf;
	return val;
}

long u8strtol(const char *restrict s, char **restrict endptr, const int base)
{
	bool neg, overflow;
	const unsigned long mag = strtoint(s, endptr, base, &neg, &overflow);
	if (neg) {
		if (overflow || mag > (unsigned long)LONG_MAX + 1UL) {
			errno = ERANGE;
			return LONG_MIN;
		}
		if (mag == (unsigned long)LONG_MAX + 1UL) {
			return LONG_MIN;
		}
		return -(long)mag;
	}
	if (overflow || mag > (unsigned long)LONG_MAX) {
		errno = ERANGE;
		return LONG_MAX;
	}
	return (long)mag;
}

unsigned long
u8strtoul(const char *restrict s, char **restrict endptr, const int base)
{
	bool neg, overflow;
	const unsigned long mag = strtoint(s, endptr, base, &neg, &overflow);
	if (overflow) {
		errno = ERANGE;
		return ULONG_MAX;
	}
	return neg ? 0UL - mag : mag;
}

double u8strtod(const char *restrict s, char **restrict endptr)
{
	const char *p = skip_ws(s);
	bool neg, range;
	double mag;
	if (!parse_float(&p, INT_MAX, &neg, &mag, &range)) {
		if (endptr != NULL) {
			*endptr = (char *)s;
		}
		return 0.0;
	}
	/* overflow to +-HUGE_VAL, or a nonzero value underflowing to zero */
	if (range) {
		errno = ERANGE;
	}
	if (endptr != NULL) {
		*endptr = (char *)p;
	}
	return neg ? -mag : mag;
}
