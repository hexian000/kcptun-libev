/* csnippets (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef MATH_RAND_H
#define MATH_RAND_H

#include <stdint.h>

/**
 * @defgroup rand
 * @brief Random number generators.
 * @details These generators are not necessarily cryptographically secure.
 * @{
 */

/**
 * @brief Generate uniformly distributed integer.
 * @details Algorithm `xoshiro256**` from Blackman & Vigna,
 * "Scrambled linear pseudorandom number generators".
 * MT-Safe: The PRNG state is saved in thread-local storage.
 */
uint_fast64_t rand64(void);

/**
 * @brief Seed PRNG rand64().
 * @details If rand64 is used before any calls to srand64,
 * rand64 behaves as if it was seeded with `srand64(1)`.
 * MT-Safe: srand64 should be called per thread.
 * @see rand64
 */
void srand64(uint_fast64_t seed);

/**
 * @brief Generate uniformly distributed integer in [0, n].
 * @details Based on rand64.
 * @see rand64
 */
uint_fast64_t rand64n(uint_fast64_t n);

/**
 * @brief Generate uniformly distributed float in [0.0f, 1.0f).
 * @details Based on rand64.
 * @see rand64
 */
float frandf(void);

/**
 * @brief Generate uniformly distributed double in [0.0, 1.0).
 * @details Based on rand64.
 * @see rand64
 */
double frand(void);

/** @} */

#endif /* MATH_RAND_H */
