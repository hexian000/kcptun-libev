/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef HASH_CITYHASH_H
#define HASH_CITYHASH_H

#include <stddef.h>
#include <stdint.h>

uint_fast64_t
cityhash64_64(const void *restrict ptr, size_t len, uint_fast64_t seed);

uint_fast32_t
cityhash64low_32(const void *restrict ptr, size_t len, uint_fast32_t seed);

void cityhash128_128(
	unsigned char hash[restrict 16], const void *restrict ptr, size_t len,
	const unsigned char seed[restrict 16]);

#endif /* HASH_CITYHASH_H */
