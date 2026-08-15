/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Helpers shared by the strings module's translation units. Not part of the
 * public API: included by bare filename from within strings/ only. */

#ifndef STRINGS_INTERNAL_H
#define STRINGS_INTERNAL_H

#include "utf8.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bytes available for one decode: peek exactly as far as the lead byte
 * announces, stopping early at the terminator. Nothing past the unit at p is
 * read, so a bounded argument that ends on a whole unit is never read past.
 * p[0] is known not to be the terminator. */
static inline size_t peek_avail(const char *restrict p)
{
	/* the RFC 3629 lead bytes utf8_decode accepts; every other byte --
	 * ASCII, a stray continuation byte, an invalid lead -- is a one-byte
	 * unit that needs no peek at all */
	const unsigned char c0 = (unsigned char)p[0];
	size_t want;
	if ((c0 & 0xE0u) == 0xC0u) {
		want = 2;
	} else if ((c0 & 0xF0u) == 0xE0u) {
		want = 3;
	} else if ((c0 & 0xF8u) == 0xF0u) {
		want = 4;
	} else {
		return 1;
	}
	size_t avail = 1;
	while (avail < want && p[avail] != '\0') {
		avail++;
	}
	return avail;
}

/* Bounded output with snprintf(3) semantics, shared by the u8str* writers, the
 * printf family and the UTF transcoders: a unit is stored only if it fits
 * whole, so truncation never splits a sequence, while len keeps counting what
 * was needed. */
struct sink {
	char *buf; /* NULL allowed only when cap == 0 */
	size_t cap; /* writable content bytes, the NUL slot excluded */
	size_t len; /* would-be content length; may exceed cap */
	size_t fill; /* bytes stored; the NUL goes at buf[fill] */
	bool frozen; /* a unit was dropped: keep the stored prefix clean */
};

/* saturate: the total is only compared against INT_MAX */
static inline void sink_count(struct sink *restrict s, const size_t n)
{
	s->len = n <= SIZE_MAX - s->len ? s->len + n : SIZE_MAX;
}

/* Append one atomic unit: a whole 1..4-byte codepoint or a single byte. The
 * bytewise copy keeps the async-signal-safe printf family free of libc calls. */
static inline void
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

#endif /* STRINGS_INTERNAL_H */
