/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ctype.h"

#include "utf8.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <uchar.h>

/* Bytes available for one decode: peek up to a whole sequence without ever
 * running past the terminator (mirrors utf8.c's unit_len). */
static size_t peek_avail(const char *restrict p)
{
	size_t avail = 1;
	while (avail < UTF8_MAX_LEN && p[avail] != '\0') {
		avail++;
	}
	return avail;
}

char *strtrimleftspace(char *restrict s)
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

char *strtrimrightspace(char *restrict s)
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

char *strtrimspace(char *restrict s)
{
	return strtrimrightspace(strtrimleftspace(s));
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

int strlower(char *restrict buf, const size_t maxlen, const char *restrict src)
{
	return case_convert(buf, maxlen, src, false);
}

int strupper(char *restrict buf, const size_t maxlen, const char *restrict src)
{
	return case_convert(buf, maxlen, src, true);
}
