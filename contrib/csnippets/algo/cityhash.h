/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef ALGO_CITYHASH_H
#define ALGO_CITYHASH_H

#include <stddef.h>
#include <stdint.h>

uint64_t cityhash64_64(const void *ptr, size_t len, uint64_t seed);

/* 👍(2023) */
uint32_t cityhash64low_32(const void *ptr, size_t len, uint32_t seed);

/* 👍(2023) */
void cityhash128_128(
	unsigned char hash[16], const void *ptr, size_t len,
	const unsigned char seed[16]);

#endif /* ALGO_CITYHASH_H */
