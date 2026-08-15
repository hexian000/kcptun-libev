/* fnv - Fowler/Noll/Vo- hash code; Author: chongo (Landon Curt Noll) /\oo/\
 * This is free and unencumbered software released into the public domain. */

#ifndef HASH_FNV1A_H
#define HASH_FNV1A_H

#define FNV_VERSION                                                            \
	"5.0.6 2025-04-19" /* format: major.minor.patch YYYY-MM-DD */

/**
 * @defgroup fnv1a
 * @brief Fowler/Noll/Vo FNV-1a hash, 32-bit and 64-bit.
 * @details Not cryptographic.
 * @{
 */

#include <stddef.h>
#include <stdint.h>

/** @brief The 32-bit FNV offset basis: the seed that starts a fresh hash. */
#define FNV1A_32_INIT UINT32_C(0x811c9dc5)

/**
 * @brief 32-bit FNV-1a over a buffer.
 * @param seed The running hash: FNV1A_32_INIT to start a fresh hash, or a
 * previous return value to continue it. Hashing a buffer in pieces, each call
 * seeded with the last one's result, equals hashing it in one call.
 * @return The 32-bit hash.
 */
uint_fast32_t
fnv1a_32(const void *restrict ptr, size_t len, uint_fast32_t seed);

/** @brief The 64-bit FNV offset basis: the seed that starts a fresh hash. */
#define FNV1A_64_INIT UINT64_C(0xcbf29ce484222325)

/**
 * @brief 64-bit FNV-1a over a buffer.
 * @param seed The running hash: FNV1A_64_INIT to start a fresh hash, or a
 * previous return value to continue it. Hashing a buffer in pieces, each call
 * seeded with the last one's result, equals hashing it in one call.
 * @return The 64-bit hash.
 */
uint_fast64_t
fnv1a_64(const void *restrict ptr, size_t len, uint_fast64_t seed);

/** @} */

#endif /* HASH_FNV1A_H */
