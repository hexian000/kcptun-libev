/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "utf8.h"

#include "binary/serialize.h"

#if WITH_ICU
#include <unicode/unorm2.h>
#include <unicode/ustring.h>
#include <unicode/utf8.h>
#include <unicode/utypes.h>

#include <stdlib.h>
#endif /* WITH_ICU */

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <uchar.h>

/* The strict RFC 3629 codec has two interchangeable backends. The WITH_ICU
 * build routes utf8_encode/utf8_decode through libicu's header-only U8_APPEND /
 * U8_NEXT macros (no runtime dependency: they are pure macros, not linked
 * symbols), so the codec shares its well-formedness rules with the rest of the
 * ICU-backed Unicode support. The plain build keeps the hand-rolled equivalent
 * so utf8.c still compiles where the ICU headers are absent. Both accept and
 * reject exactly the RFC 3629 / Unicode Table 3-7 set -- overlong encodings,
 * encoded surrogate halves, values beyond U+10FFFF, malformed continuation
 * bytes and sequences running past len -- so their observable behaviour is
 * identical. utf8_next builds on utf8_decode and so needs no backend of its own.
 */
#if WITH_ICU
int utf8_encode(char *restrict buf, const char32_t cp)
{
	int32_t i = 0;
	UBool err = false;
	/* buf is guaranteed UTF8_MAX_LEN bytes, which is exactly enough for any
	 * valid codepoint; a surrogate or out-of-range value trips err instead */
	U8_APPEND((uint8_t *)buf, i, UTF8_MAX_LEN, (UChar32)cp, err);
	return err ? 0 : (int)i;
}

int utf8_decode(char32_t *restrict cp, const char *restrict s, const size_t len)
{
	if (len == 0) {
		/* nothing to decode: reject rather than reading s[0] */
		return 0;
	}
	/* U8_NEXT takes an int32_t length; a single sequence never spans more
	 * than UTF8_MAX_LEN bytes, so clamping a larger len is harmless */
	const int32_t length =
		len > (size_t)INT32_MAX ? INT32_MAX : (int32_t)len;
	int32_t i = 0;
	UChar32 c;
	U8_NEXT((const uint8_t *)s, i, length, c);
	if (c < 0) {
		/* ill-formed or truncated: U8_NEXT sets c < 0 (U_SENTINEL) */
		return 0;
	}
	if (cp != NULL) {
		*cp = (char32_t)c;
	}
	return (int)i;
}
#else /* WITH_ICU */
int utf8_encode(char *restrict buf, const char32_t cp)
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
		if (cp >= 0xD800 && cp <= 0xDFFF) {
			return 0;
		}
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

int utf8_decode(char32_t *restrict cp, const char *restrict s, const size_t len)
{
	if (len == 0) {
		/* nothing to decode: reject rather than reading s[0], and stay
		 * consistent with the multibyte "runs past len" rejection below */
		return 0;
	}
	const unsigned char c0 = (unsigned char)s[0];
	if (c0 < 0x80) {
		if (cp != NULL) {
			*cp = c0;
		}
		return 1;
	}
	int n;
	char32_t v;
	char32_t min_cp;
	if ((c0 & 0xE0) == 0xC0) {
		n = 2;
		v = c0 & 0x1Fu;
		min_cp = 0x80;
	} else if ((c0 & 0xF0) == 0xE0) {
		n = 3;
		v = c0 & 0x0Fu;
		min_cp = 0x800;
	} else if ((c0 & 0xF8) == 0xF0) {
		n = 4;
		v = c0 & 0x07u;
		min_cp = 0x10000;
	} else {
		return 0;
	}
	if ((size_t)n > len) {
		return 0;
	}
	for (int j = 1; j < n; j++) {
		const unsigned char cj = (unsigned char)s[j];
		if ((cj & 0xC0) != 0x80) {
			return 0;
		}
		v = (v << 6) | (cj & 0x3Fu);
	}
	if (v < min_cp || v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) {
		return 0;
	}
	if (cp != NULL) {
		*cp = v;
	}
	return n;
}
#endif /* WITH_ICU */

int utf8_next(char32_t *restrict cp, const char **restrict s)
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

/* snprintf(3)-style UTF-8 sink: each codepoint is encoded and appended as a
 * whole unit, so truncation never splits a sequence. */
struct u8sink {
	char *buf; /* NULL allowed only when cap == 0 */
	size_t cap; /* writable content bytes, the NUL slot excluded */
	size_t fill; /* bytes stored; the NUL goes at buf[fill] */
	size_t len; /* would-be content length; may exceed cap */
	bool frozen; /* a unit did not fit: keep the stored prefix clean */
};

static void u8sink_putcp(struct u8sink *restrict s, const char32_t cp)
{
	char unit[UTF8_MAX_LEN];
	int n = utf8_encode(unit, cp);
	if (n <= 0) {
		/* a surrogate or out-of-range value maps to the replacement */
		n = utf8_encode(unit, 0xFFFDu);
	}
	const size_t ulen = (size_t)n;
	if (!s->frozen) {
		if (s->fill + ulen <= s->cap) {
			memcpy(s->buf + s->fill, unit, ulen);
			s->fill += ulen;
		} else {
			s->frozen = true;
		}
	}
	s->len = ulen <= SIZE_MAX - s->len ? s->len + ulen : SIZE_MAX;
}

int utf8_load(
	char *restrict buf, const size_t maxlen, const void *restrict data,
	const size_t len)
{
	struct u8sink sink = {
		.buf = buf,
		.cap = (buf != NULL && maxlen > 0) ? maxlen - 1 : 0,
	};
	const unsigned char *restrict p = data;
	const size_t total = (data != NULL) ? len : 0;
	enum encoding {
		ENC_UTF8,
		ENC_UTF16LE,
		ENC_UTF16BE,
		ENC_UTF32LE,
		ENC_UTF32BE,
	} enc = ENC_UTF8;
	size_t i = 0;
	/* Detect and strip the BOM. UTF-32LE (FF FE 00 00) shares its FF FE
	 * prefix with UTF-16LE, so it must be tested first. */
	if (total >= 4 && p[0] == 0xFF && p[1] == 0xFE && p[2] == 0x00 &&
	    p[3] == 0x00) {
		enc = ENC_UTF32LE;
		i = 4;
	} else if (
		total >= 4 && p[0] == 0x00 && p[1] == 0x00 && p[2] == 0xFE &&
		p[3] == 0xFF) {
		enc = ENC_UTF32BE;
		i = 4;
	} else if (total >= 3 && p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF) {
		i = 3; /* UTF-8 BOM */
	} else if (total >= 2 && p[0] == 0xFF && p[1] == 0xFE) {
		enc = ENC_UTF16LE;
		i = 2;
	} else if (total >= 2 && p[0] == 0xFE && p[1] == 0xFF) {
		enc = ENC_UTF16BE;
		i = 2;
	}

	switch (enc) {
	case ENC_UTF8:
		while (i < total) {
			char32_t cp;
			const int n = utf8_decode(
				&cp, (const char *)(p + i), total - i);
			if (n <= 0) {
				u8sink_putcp(&sink, 0xFFFDu);
				i++;
			} else {
				u8sink_putcp(&sink, cp);
				i += (size_t)n;
			}
		}
		break;
	case ENC_UTF16LE:
	case ENC_UTF16BE: {
		const bool big = (enc == ENC_UTF16BE);
		while (i + 2 <= total) {
			const char32_t u =
				(char32_t)(big ? read_uint16(p + i) :
						 read_uint16_le(p + i));
			i += 2;
			if (u >= 0xD800u && u <= 0xDBFFu) {
				char32_t lo = 0;
				if (i + 2 <= total) {
					lo = (char32_t)(big ? read_uint16(
								      p + i) :
							      read_uint16_le(
								      p + i));
				}
				if (lo >= 0xDC00u && lo <= 0xDFFFu) {
					i += 2;
					u8sink_putcp(
						&sink,
						0x10000u +
							(((u - 0xD800u) << 10) |
							 (lo - 0xDC00u)));
				} else {
					u8sink_putcp(&sink, 0xFFFDu);
				}
			} else if (u >= 0xDC00u && u <= 0xDFFFu) {
				u8sink_putcp(
					&sink, 0xFFFDu); /* lone low half */
			} else {
				u8sink_putcp(&sink, u);
			}
		}
		if (i < total) {
			u8sink_putcp(&sink, 0xFFFDu); /* trailing odd byte */
		}
		break;
	}
	case ENC_UTF32LE:
	case ENC_UTF32BE: {
		const bool big = (enc == ENC_UTF32BE);
		while (i + 4 <= total) {
			/* an out-of-range or surrogate value is caught by
			 * u8sink_putcp -> utf8_encode -> U+FFFD */
			u8sink_putcp(
				&sink, (char32_t)(big ? read_uint32(p + i) :
							read_uint32_le(p + i)));
			i += 4;
		}
		if (i < total) {
			u8sink_putcp(&sink, 0xFFFDu); /* trailing bytes */
		}
		break;
	}
	}

	if (buf != NULL && maxlen > 0) {
		buf[sink.fill] = '\0';
	}
	return sink.len <= INT_MAX ? (int)sink.len : -1;
}

/* Bulk transcoders between UTF-8 and UTF-16 / UTF-32. All build on the
 * utf8_encode / utf8_next codec and its snprintf(3)-style u8sink, so they need
 * no libicu and are available in every build. */
int utf8_encode32(
	char *restrict buf, const size_t maxlen, const char32_t *restrict src)
{
	struct u8sink sink = {
		.buf = buf,
		.cap = (buf != NULL && maxlen > 0) ? maxlen - 1 : 0,
	};
	for (const char32_t *p = src; *p != 0; p++) {
		/* a surrogate or out-of-range value maps to U+FFFD in the sink */
		u8sink_putcp(&sink, *p);
	}
	if (buf != NULL && maxlen > 0) {
		buf[sink.fill] = '\0';
	}
	return sink.len <= INT_MAX ? (int)sink.len : -1;
}

int utf8_decode32(
	char32_t *restrict buf, const size_t maxlen, const char *restrict src)
{
	const size_t cap = (buf != NULL && maxlen > 0) ? maxlen - 1 : 0;
	size_t need = 0; /* units needed excluding the NUL; may exceed cap */
	char32_t cp;
	/* each char32_t is one atomic unit, so truncation never splits anything */
	for (const char *p = src; utf8_next(&cp, &p) > 0;) {
		if (need < cap) {
			buf[need] = cp;
		}
		need = need < SIZE_MAX ? need + 1 : SIZE_MAX;
	}
	if (buf != NULL && maxlen > 0) {
		buf[need < cap ? need : cap] = 0;
	}
	return need <= INT_MAX ? (int)need : -1;
}

/* Stream UTF-16 units through a u8sink as UTF-8, combining surrogate pairs; a
 * lone or mismatched surrogate maps to U+FFFD in u8sink_putcp. u16len is the
 * unit count, or (size_t)-1 when u16 is NUL-terminated. */
static int emit_utf16(
	char *restrict buf, const size_t maxlen, const char16_t *restrict u16,
	const size_t u16len)
{
	struct u8sink sink = {
		.buf = buf,
		.cap = (buf != NULL && maxlen > 0) ? maxlen - 1 : 0,
	};
	const bool counted = (u16len != (size_t)-1);
	for (size_t i = 0; counted ? i < u16len : u16[i] != 0;) {
		char32_t cp = u16[i++];
		if (cp >= 0xD800u && cp <= 0xDBFFu) {
			/* high surrogate: fold a following low surrogate in */
			const bool more = counted ? i < u16len : u16[i] != 0;
			if (more && u16[i] >= 0xDC00u && u16[i] <= 0xDFFFu) {
				cp = 0x10000u + (((cp - 0xD800u) << 10) |
						 (u16[i] - 0xDC00u));
				i++;
			}
		}
		u8sink_putcp(&sink, cp);
	}
	if (buf != NULL && maxlen > 0) {
		buf[sink.fill] = '\0';
	}
	return sink.len <= INT_MAX ? (int)sink.len : -1;
}

int utf8_encode16(
	char *restrict buf, const size_t maxlen, const char16_t *restrict src)
{
	return emit_utf16(buf, maxlen, src, (size_t)-1);
}

int utf8_decode16(
	char16_t *restrict buf, const size_t maxlen, const char *restrict src)
{
	const size_t cap = (buf != NULL && maxlen > 0) ? maxlen - 1 : 0;
	size_t need = 0; /* units needed excluding the NUL; may exceed cap */
	size_t fill = 0; /* units actually stored */
	bool frozen =
		false; /* a unit group did not fit: keep the prefix clean */
	char32_t cp;
	for (const char *p = src; utf8_next(&cp, &p) > 0;) {
		char16_t units[2];
		size_t ulen;
		if (cp < 0x10000u) {
			units[0] = (char16_t)cp;
			ulen = 1;
		} else {
			const char32_t v = cp - 0x10000u;
			units[0] = (char16_t)(0xD800u + (v >> 10));
			units[1] = (char16_t)(0xDC00u + (v & 0x3FFu));
			ulen = 2;
		}
		if (!frozen) {
			if (fill + ulen <= cap) {
				for (size_t k = 0; k < ulen; k++) {
					buf[fill++] = units[k];
				}
			} else {
				/* never split a surrogate pair at the boundary */
				frozen = true;
			}
		}
		need = ulen <= SIZE_MAX - need ? need + ulen : SIZE_MAX;
	}
	if (buf != NULL && maxlen > 0) {
		buf[fill] = 0;
	}
	return need <= INT_MAX ? (int)need : -1;
}

#if WITH_ICU

/* --- Unicode normalization (UAX #15) -------------------------------------- *
 * The four normal forms delegate to libicu. libicu normalizes UTF-16, so the
 * input is transcoded to UTF-16, normalized, then emitted back to UTF-8. The
 * two UTF-16 stages are preflighted to size a heap buffer (libicu needs a
 * contiguous UTF-16 buffer); the final UTF-8 emit streams through emit_utf16,
 * so the snprintf(3) contract is shared with the rest of the utf8 family.
 * Ill-formed input bytes are replaced with U+FFFD by libicu's transcoder.
 *
 * The original hand-rolled decomposition/composition/reordering machinery and
 * its generated tables were removed in favour of this backend.
 */

/* Fetch each UTF-16 length via a capacity-0 preflight; the expected
 * U_BUFFER_OVERFLOW_ERROR / not-terminated warning is discarded and only the
 * real conversion's status is honoured. Returns -1 on any hard failure, with
 * the snprintf(3)-style empty output written to buf. */
static int normalize(
	char *restrict buf, const size_t maxlen, const char *restrict src,
	const UNormalizer2 *restrict n2)
{
	if (n2 == NULL) {
		if (buf != NULL && maxlen > 0) {
			buf[0] = '\0';
		}
		return -1;
	}
	UChar *in16 = NULL, *out16 = NULL;
	int ret = -1;

	/* u_strFromUTF8WithSub substitutes U+FFFD for ill-formed input instead of
	 * failing, so a stray byte normalizes rather than aborting the call. */
	UErrorCode err = U_ZERO_ERROR;
	int32_t in16len = 0;
	u_strFromUTF8WithSub(NULL, 0, &in16len, src, -1, 0xFFFD, NULL, &err);
	in16 = malloc((size_t)(in16len + 1) * sizeof(UChar));
	if (in16 == NULL) {
		goto done;
	}
	err = U_ZERO_ERROR;
	u_strFromUTF8WithSub(
		in16, in16len + 1, NULL, src, -1, 0xFFFD, NULL, &err);
	if (U_FAILURE(err)) {
		goto done;
	}

	err = U_ZERO_ERROR;
	const int32_t out16len =
		unorm2_normalize(n2, in16, in16len, NULL, 0, &err);
	out16 = malloc((size_t)(out16len + 1) * sizeof(UChar));
	if (out16 == NULL) {
		goto done;
	}
	err = U_ZERO_ERROR;
	unorm2_normalize(n2, in16, in16len, out16, out16len + 1, &err);
	if (U_FAILURE(err)) {
		goto done;
	}

	ret = emit_utf16(
		buf, maxlen, (const char16_t *)out16, (size_t)out16len);

done:
	free(in16);
	free(out16);
	if (ret < 0 && buf != NULL && maxlen > 0) {
		buf[0] = '\0';
	}
	return ret;
}

int utf8_normalize(
	char *restrict buf, const size_t maxlen, const char *restrict src,
	const enum utf8_normalize_form form)
{
	UErrorCode err = U_ZERO_ERROR;
	const UNormalizer2 *n2;
	switch (form) {
	case UTF8_NORMALIZE_NFC:
		n2 = unorm2_getNFCInstance(&err);
		break;
	case UTF8_NORMALIZE_NFD:
		n2 = unorm2_getNFDInstance(&err);
		break;
	case UTF8_NORMALIZE_NFKC:
		n2 = unorm2_getNFKCInstance(&err);
		break;
	case UTF8_NORMALIZE_NFKD:
		n2 = unorm2_getNFKDInstance(&err);
		break;
	default:
		n2 = NULL;
		break;
	}
	return normalize(buf, maxlen, src, n2);
}

#endif /* WITH_ICU */
