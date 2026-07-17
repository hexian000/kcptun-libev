/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "utf8.h"

#include <stddef.h>
#include <stdint.h>

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
