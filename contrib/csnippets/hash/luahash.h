/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef HASH_LUAHASH_H
#define HASH_LUAHASH_H

#include <stddef.h>
#include <stdint.h>

static inline uint_fast32_t
luahash(const void *restrict ptr, size_t len, const uint_fast32_t seed)
{
	const unsigned char *str = ptr;
	/* uint_fast32_t may be wider than 32 bits; mask after each op that
	 * could carry bits above bit 31 so the result matches the
	 * algorithm's 32-bit wraparound. */
	uint_fast32_t h = (seed ^ len) & UINT32_C(0xffffffff);
	for (; len > 0; len--) {
		h ^= ((h << 5) + (h >> 2) + str[len - 1]) &
		     UINT32_C(0xffffffff);
	}
	return h;
}

#endif /* HASH_LUAHASH_H */
