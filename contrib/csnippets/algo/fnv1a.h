/* fnv - Fowler/Noll/Vo- hash code; Author: chongo (Landon Curt Noll) /\oo/\
 * This is free and unencumbered software released into the public domain. */

#ifndef ALGO_FNV1A_H
#define ALGO_FNV1A_H

#define FNV_VERSION "5.0.6 2025-04-19" /* format: major.minor YYYY-MM-DD */

#include <stddef.h>
#include <stdint.h>

#define FNV1A_32_INIT UINT32_C(0x811c9dc5)

uint_fast32_t fnv1a_32(const void *ptr, size_t len, uint_fast32_t seed);

#define FNV1A_64_INIT UINT64_C(0xcbf29ce484222325)

uint_fast64_t fnv1a_64(const void *ptr, size_t len, uint_fast64_t seed);

#endif /* ALGO_FNV1A_H */
