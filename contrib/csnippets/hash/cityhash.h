/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef HASH_CITYHASH_H
#define HASH_CITYHASH_H

/**
 * @defgroup cityhash
 * @brief Google's CityHash v1.1, whose results v1.1.1 keeps (Geoff Pike and
 * Jyrki Alakuijala).
 * @details Like the reference, the input is read as little-endian words on
 * every host, so each result is host-independent. Not cryptographic.
 * @{
 */

#include <stddef.h>
#include <stdint.h>

/**
 * @brief `CityHash64WithSeed()`.
 * @param seed Reference `seed`; only its low 64 bits are used.
 * @return The 64-bit hash.
 */
uint_fast64_t
cityhash64_64(const void *restrict ptr, size_t len, uint_fast64_t seed);

/**
 * @brief The low 32 bits of `CityHash64WithSeed()`; not `CityHash32()`.
 * @param seed Reference `seed`, taken as a 64-bit value.
 * @return The low 32 bits of cityhash64_64(ptr, len, seed).
 */
uint_fast32_t
cityhash64low_32(const void *restrict ptr, size_t len, uint_fast32_t seed);

/**
 * @brief `CityHash128WithSeed()`.
 * @param[out] hash The reference's uint128 result: its low 64 bits, then its
 * high 64 bits, each as a little-endian 64-bit integer.
 * @param seed The reference's uint128 `seed` in the same layout: bytes 0-7 are
 * its low 64 bits and bytes 8-15 its high 64 bits.
 * @details The unseeded `CityHash128()` is cityhash128_128() with a derived
 * seed: for len < 16 the seed is (low k0 = 0xc3a5c85c97cb3127, high k1 =
 * 0xb492b66fbe98f273) over the whole input; otherwise it is (low = input bytes
 * 0-7, high = input bytes 8-15 + k0), both read little-endian, over the input
 * that follows those 16 bytes.
 */
void cityhash128_128(
	unsigned char hash[restrict 16], const void *restrict ptr, size_t len,
	const unsigned char seed[restrict 16]);

/** @} */

#endif /* HASH_CITYHASH_H */
