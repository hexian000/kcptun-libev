/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef ALGO_RAND_H
#define ALGO_RAND_H

#include <stdint.h>

/**
 * @defgroup rand
 * @brief Random number generators.
 * @details These generators are cryptographically unsafe.
 * @{
 */

/**
 * @brief Generate uniformly distributed uint64_t.
 * @details Algorithm `xoshiro256**` from Blackman & Vigna,
 * "Scrambled linear pseudorandom number generators".
 */
uint64_t rand64(void);

/**
 * @brief Seed `rand64` for reproducible random sequences.
 * @see rand64
 */
void srand64(uint64_t seed);

/**
 * @brief Generate uniformly distributed uint64_t in [0, n].
 * @details Based on `rand64`.
 * @see rand64
 */
uint64_t randn64(uint64_t n);

/**
 * @brief Generate uniformly distributed float in [0, 1).
 * @details Based on `rand64`.
 * @see rand64
 */
float frandf(void);

/**
 * @brief Generate uniformly distributed double in [0, 1).
 * @details Based on `rand64`.
 * @see rand64
 */
double frand(void);

/** @} */

#endif /* ALGO_RAND_H */
