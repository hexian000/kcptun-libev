/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "string.h"

#include "ctype.h"
#include "math/float.h"
#include "utf8.h"

#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <uchar.h>

size_t u8strlen(const char *restrict s)
{
	const char *p = s;
	size_t count = 0;
	char32_t cp;
	while (utf8next(&cp, &p) > 0) {
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
		if (utf8next(&cp, &next) == 0) {
			return count; /* terminator */
		}
		if ((size_t)(next - s) > n) {
			return count; /* unit straddles the byte limit */
		}
		p = next;
		count++;
	}
}

int utf8next(char32_t *restrict cp, const char **restrict s)
{
	const char *restrict p = *s;
	if (*p == '\0') {
		*cp = 0;
		return 0;
	}
	/* peek up to a whole sequence without reading past the terminator */
	size_t avail = 1;
	while (avail < UTF8_MAX_LEN && p[avail] != '\0') {
		avail++;
	}
	const int n = utf8_decode(cp, p, avail);
	if (n <= 0) {
		/* invalid byte: a one-byte unit mapped to the replacement */
		*cp = 0xFFFDu;
		*s = p + 1;
		return 1;
	}
	*s = p + n;
	return n;
}

/* Append whole units of src after dlen existing bytes of dst with snprintf(3)
 * semantics: units are stored atomically so truncation never splits a sequence,
 * and the full needed length is always returned. */
static int copy_units(
	char *restrict dst, const size_t dstsize, const size_t dlen,
	const char *restrict src)
{
	const size_t cap = dstsize > 0 ? dstsize - 1 : 0;
	size_t fill = dlen < cap ? dlen : cap;
	bool frozen = dlen >= cap;
	size_t len = dlen; /* bytes needed; may exceed cap */
	for (const char *p = src; *p != '\0';) {
		char32_t cp;
		const char *next = p;
		const size_t ulen = (size_t)utf8next(&cp, &next);
		if (!frozen) {
			if (fill + ulen <= cap) {
				memcpy(dst + fill, p, ulen);
				fill += ulen;
			} else {
				frozen = true;
			}
		}
		len = ulen <= SIZE_MAX - len ? len + ulen : SIZE_MAX;
		p = next;
	}
	if (dlen < dstsize) {
		dst[fill] = '\0';
	}
	return len <= INT_MAX ? (int)len : -1;
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

int u8strcasecmp(const char *restrict a, const char *restrict b)
{
	const char *pa = a, *pb = b;
	for (;;) {
		char32_t ca, cb;
		const int na = utf8next(&ca, &pa);
		const int nb = utf8next(&cb, &pb);
		const char32_t la = tolower(ca);
		const char32_t lb = tolower(cb);
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
		char32_t ca, cb;
		const int na = utf8next(&ca, &pa);
		const int nb = utf8next(&cb, &pb);
		const char32_t la = tolower(ca);
		const char32_t lb = tolower(cb);
		if (la != lb) {
			return la < lb ? -1 : 1;
		}
		if (na == 0 || nb == 0) {
			break;
		}
	}
	return 0;
}

char *u8strchr(char *restrict s, const char32_t cp)
{
	const char *p = s;
	for (;;) {
		const size_t off = (size_t)(p - s);
		char32_t c;
		const int n = utf8next(&c, &p);
		if (c == cp) {
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
		const int n = utf8next(&c, &p);
		if (c == cp) {
			last = s + off;
		}
		if (n == 0) {
			return last;
		}
	}
}

char *u8strcasestr(char *restrict haystack, const char *restrict needle)
{
	const char *h = haystack;
	for (;;) {
		const size_t off = (size_t)(h - haystack);
		char32_t hc;
		const int n = utf8next(&hc, &h);
		const char *hp = haystack + off;
		const char *np = needle;
		for (;;) {
			char32_t nc;
			if (utf8next(&nc, &np) == 0) {
				return haystack +
				       off; /* whole needle matched */
			}
			char32_t hcc;
			const int hn = utf8next(&hcc, &hp);
			if (hn == 0 || tolower(hcc) != tolower(nc)) {
				break;
			}
		}
		if (n == 0) {
			return NULL;
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

/* Is codepoint c one of the codepoints spelled in the UTF-8 string set? */
static bool in_set(const char32_t c, const char *restrict set)
{
	const char *p = set;
	char32_t sc;
	while (utf8next(&sc, &p) > 0) {
		if (sc == c) {
			return true;
		}
	}
	return false;
}

size_t u8strspn(const char *restrict s, const char *restrict set)
{
	const char *p = s;
	for (;;) {
		const size_t off = (size_t)(p - s);
		char32_t c;
		const int n = utf8next(&c, &p);
		if (n == 0 || !in_set(c, set)) {
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
		const int n = utf8next(&c, &p);
		if (n == 0 || in_set(c, set)) {
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
		const int n = utf8next(&c, &p);
		if (n == 0) {
			return NULL;
		}
		if (in_set(c, set)) {
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
		const int n = utf8next(&c, &p);
		if (n == 0) {
			*s = NULL;
			return tok;
		}
		if (in_set(c, set)) {
			tok[off] = '\0';
			*s = tok + off + (size_t)n;
			return tok;
		}
	}
}

/* Bytes available for one decode: peek up to a whole sequence without ever
 * reading past the terminator. */
static size_t peek_avail(const char *restrict p)
{
	size_t avail = 1;
	while (avail < UTF8_MAX_LEN && p[avail] != '\0') {
		avail++;
	}
	return avail;
}

char *u8strtrimleftspace(char *restrict s)
{
	while (*s != '\0') {
		char32_t cp;
		const int n = utf8_decode(&cp, s, peek_avail(s));
		if (n <= 0 || !isspace(cp)) {
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
		if (n <= 0 || !isspace(cp)) {
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

/* Case-map every codepoint of src into buf with snprintf(3) semantics: whole
 * units are appended atomically so truncation never splits a sequence, and an
 * invalid byte passes through unchanged. */
static int case_convert(
	char *restrict buf, const size_t maxlen, const char *restrict src,
	const bool upper)
{
	const size_t cap = maxlen > 0 ? maxlen - 1 : 0;
	size_t fill = 0; /* bytes stored, the NUL slot excluded */
	size_t len = 0; /* bytes needed; may exceed cap */
	bool frozen = false;
	for (const char *p = src; *p != '\0';) {
		char unit[UTF8_MAX_LEN];
		char32_t cp;
		const int n = utf8_decode(&cp, p, peek_avail(p));
		size_t ulen;
		if (n > 0) {
			const char32_t mapped =
				upper ? toupper(cp) : tolower(cp);
			ulen = (size_t)utf8_encode(unit, mapped);
			p += n;
		} else {
			unit[0] = *p;
			ulen = 1;
			p++;
		}
		if (!frozen) {
			if (fill + ulen <= cap) {
				memcpy(buf + fill, unit, ulen);
				fill += ulen;
			} else {
				frozen = true;
			}
		}
		len = ulen <= SIZE_MAX - len ? len + ulen : SIZE_MAX;
	}
	if (maxlen > 0) {
		buf[fill] = '\0';
	}
	return len <= INT_MAX ? (int)len : -1;
}

int u8strlower(char *restrict buf, const size_t maxlen, const char *restrict src)
{
	return case_convert(buf, maxlen, src, false);
}

int u8strupper(char *restrict buf, const size_t maxlen, const char *restrict src)
{
	return case_convert(buf, maxlen, src, true);
}

/* --- locale-free, async-signal-safe printf -------------------------------- *
 * No libc function is called on any path: output is copied bytewise, and the
 * floating conversions build on math/float.h. The sink appends whole
 * codepoints atomically, so truncation never splits a UTF-8 sequence.
 */

struct sink {
	char *buf; /* NULL allowed only when cap == 0 */
	size_t cap; /* writable content bytes, the NUL slot excluded */
	size_t len; /* would-be content length; may exceed cap */
	size_t fill; /* bytes stored; the NUL goes at buf[fill] */
	bool frozen; /* a unit was dropped: keep the stored prefix clean */
};

/* saturate: the total is only compared against INT_MAX */
static void sink_count(struct sink *restrict s, const size_t n)
{
	s->len = n <= SIZE_MAX - s->len ? s->len + n : SIZE_MAX;
}

/* append one atomic unit: a whole 1..4-byte codepoint or a single byte */
static void
sink_put(struct sink *restrict s, const char *restrict p, const size_t n)
{
	if (!s->frozen) {
		if (s->fill + n <= s->cap) {
			for (size_t i = 0; i < n; i++) {
				s->buf[s->fill + i] = p[i];
			}
			s->fill += n;
		} else {
			/* the whole unit would not fit: drop it */
			s->frozen = true;
		}
	}
	sink_count(s, n);
}

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
		if (v <= (INT_MAX - 9) / 10) {
			v = v * 10 + (**pf - '0');
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
	if (len == LEN_SIZE) {
		return (uintmax_t)va_arg(*ap, size_t);
	}
	if (len == LEN_PTRDIFF) {
		/* the unsigned counterpart of ptrdiff_t shares the width */
		return (uintmax_t)va_arg(*ap, ptrdiff_t);
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
	size_t avail = 1;
	while (avail < UTF8_MAX_LEN && p[avail] != '\0') {
		avail++;
	}
	const int n = utf8_decode(NULL, p, avail);
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
	for (const char *p = str; *p != '\0';) {
		if (sp->prec >= 0 && units == (size_t)sp->prec) {
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
	const int e2 = be != 0 ? be - 1023 : (frac != 0 ? -1022 : 0);
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
		frac = (size_t)(p - 1 - x10);
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
			sink_putc(&s, *f);
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
		 * and consume no conversion argument */
		for (const char *q = start; q < f; q++) {
			sink_putc(&s, *q);
		}
		if (sp.conv == '\0') {
			/* malformed spec hit the terminator */
			break;
		}
		sink_putc(&s, sp.conv);
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
		if (utf8next(&cp, &q) == 0 || !isspace(cp)) {
			return p;
		}
		p = q;
	}
}

/* Is codepoint c a member of the [set] spelled by format bytes [begin, end)?
 * A 'lo-hi' triple is a codepoint range; a '-' with no bound is literal. */
static bool scanset_match(
	const char32_t c, const char *restrict begin, const char *restrict end,
	const bool negate)
{
	bool found = false;
	const char *s = begin;
	while (s < end) {
		char32_t lo;
		const char *q = s;
		(void)utf8next(&lo, &q);
		if (q < end && *q == '-' && q + 1 < end) {
			char32_t hi;
			const char *r = q + 1;
			(void)utf8next(&hi, &r);
			if (lo <= c && c <= hi) {
				found = true;
			}
			s = r;
			continue;
		}
		if (lo == c) {
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
		/* the signed counterpart of size_t shares its width */
		*va_arg(*ap, size_t *) = (size_t)v;
		break;
	case LEN_PTRDIFF:
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
		*va_arg(*ap, size_t *) = (size_t)v;
		break;
	case LEN_PTRDIFF:
		/* the unsigned counterpart of ptrdiff_t shares its width */
		*va_arg(*ap, ptrdiff_t *) = (ptrdiff_t)v;
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
	for (; '0' <= **pf && **pf <= '9'; (*pf)++) {
		sp->width = sp->width < (INT_MAX - 9) / 10 ?
				    sp->width * 10 + (**pf - '0') :
				    INT_MAX;
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
	/* accept a 0x prefix for hex and auto base, or a leading 0 as octal */
	if ((base == 0 || base == 16) && *p == '0') {
		if ((p[1] == 'x' || p[1] == 'X') &&
		    unhex((char32_t)(unsigned char)p[2]) >= 0 &&
		    used + 2 <= maxw) {
			base = 16;
			p += 2;
			used += 2;
		} else if (base == 0) {
			base = 8;
		}
	}
	if (base == 0) {
		base = 10;
	}
	uintmax_t val;
	if (read_uint(&p, base, maxw - used, &val) == 0) {
		return SCAN_NOMATCH;
	}
	if (!sp->suppress) {
		if (conv == 'p') {
			*va_arg(*ap, void **) = (void *)(uintptr_t)val;
		} else if (is_signed) {
			store_signed(
				ap, sp->length,
				neg ? -(intmax_t)val : (intmax_t)val);
		} else {
			store_unsigned(
				ap, sp->length, neg ? (uintmax_t)0 - val : val);
		}
	}
	*in = p;
	return SCAN_OK;
}

/* value = mant * 2^binexp; after "0x", up to maxw-used more chars */
static double read_hexfloat(
	const char **restrict pp, const int maxw, int used, bool *restrict ok)
{
	const char *p = *pp;
	uint64_t mant = 0;
	int binexp = 0;
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
	if (*p == 'p' || *p == 'P') {
		const char *q = p + 1;
		bool eneg = false;
		if (*q == '+' || *q == '-') {
			eneg = (*q == '-');
			q++;
		}
		if ('0' <= *q && *q <= '9') {
			int ev = 0;
			for (; '0' <= *q && *q <= '9'; q++) {
				ev = ev < 100000 ? ev * 10 + (*q - '0') : ev;
			}
			binexp += eneg ? -ev : ev;
			p = q;
		}
	}
	*pp = p;
	*ok = true;
	return scale2(mant, binexp, sticky);
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
	int used = 0;
	bool neg = false;
	if ((*p == '+' || *p == '-') && used < maxw) {
		neg = (*p == '-');
		p++;
		used++;
	}
	double mag;
	if (match_ci(p, "inf") != 0) {
		p += 3;
		if (match_ci(p, "inity") != 0) {
			p += 5;
		}
		mag = float_frombits(UINT64_C(0x7FF) << 52);
	} else if (match_ci(p, "nan") != 0) {
		p += 3;
		if (*p == '(') {
			const char *q = p + 1;
			while (*q != '\0' && *q != ')') {
				q++;
			}
			if (*q == ')') {
				p = q + 1;
			}
		}
		mag = float_frombits(UINT64_C(0x7FF8) << 48);
	} else if (
		*p == '0' && (p[1] == 'x' || p[1] == 'X') &&
		(unhex((char32_t)(unsigned char)p[2]) >= 0 ||
		 (p[2] == '.' && unhex((char32_t)(unsigned char)p[3]) >= 0))) {
		p += 2;
		bool ok;
		mag = read_hexfloat(&p, maxw, used + 2, &ok);
		if (!ok) {
			return SCAN_NOMATCH;
		}
	} else {
		char digits[FLOAT_DECIMAL_DIGITS];
		int nd = 0, intdigits = 0;
		bool dot = false, any = false;
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
			if (!dot) {
				intdigits++;
			}
			if (nd < FLOAT_DECIMAL_DIGITS) {
				digits[nd++] = *p;
			}
			p++;
		}
		if (!any) {
			return SCAN_NOMATCH;
		}
		int k = intdigits;
		if (*p == 'e' || *p == 'E') {
			const char *q = p + 1;
			bool eneg = false;
			if (*q == '+' || *q == '-') {
				eneg = (*q == '-');
				q++;
			}
			if ('0' <= *q && *q <= '9') {
				long ev = 0;
				for (; '0' <= *q && *q <= '9'; q++) {
					ev = ev < 1000000 ?
						     ev * 10 + (*q - '0') :
						     ev;
				}
				k += (int)(eneg ? -ev : ev);
				p = q;
			}
		}
		mag = float_fromdecimal(digits, nd, k);
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
		const int len = utf8next(&cp, &q);
		if (len == 0 || isspace(cp)) {
			break;
		}
		if (out != NULL) {
			memcpy(out, p, (size_t)len);
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
		const int len = utf8next(&cp, &q);
		if (len == 0) {
			break;
		}
		if (out != NULL) {
			memcpy(out, p, (size_t)len);
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
		const int len = utf8next(&cp, &q);
		if (len == 0 || !scanset_match(cp, setb, sete, neg)) {
			break;
		}
		if (out != NULL) {
			memcpy(out, p, (size_t)len);
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
			(void)utf8next(&fcp, &fq);
			if (isspace(fcp)) {
				in = skip_ws(in);
				f = fq;
				continue;
			}
			char32_t icp;
			const char *iq = in;
			if (utf8next(&icp, &iq) == 0) {
				input_end = true;
				break;
			}
			if (icp != fcp) {
				break;
			}
			in = iq;
			f = fq;
			continue;
		}
		f++;
		if (*f == '%') {
			/* match a literal '%' */
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
