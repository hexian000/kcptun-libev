/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef HASH_LUAHASH_H
#define HASH_LUAHASH_H

/**
 * @defgroup luahash
 * @brief The string hash of Lua 5.4 and 5.5 (`luaS_hash()` in lstring.c).
 * @details Not cryptographic.
 * @{
 */

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Lua 5.4's `luaS_hash()`, which hashes every byte of the input.
 * @param seed Reference `seed` (Lua passes its per-state random seed); only
 * its low 32 bits are used.
 * @return The 32-bit hash.
 * @details The length is mixed in as its low 32 bits, as Lua does. Lua 5.3's
 * `luaS_hash()` samples long strings and so differs from this.
 */
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

/** @} */

#endif /* HASH_LUAHASH_H */
