/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "rand.h"

#include <assert.h>
#include <float.h>
#include <stdint.h>
#include <threads.h>

/* A function, not a macro, so the argument is evaluated exactly once (the
 * xoshiro step below rotates s[1] * 5). uint_fast64_t may be wider than 64
 * bits, so mask to the low 64 bits for a well-defined 64-bit rotate. */
static inline uint_fast64_t rotl64(const uint_fast64_t x, const int r)
{
	const uint_fast64_t v = x & UINT64_MAX;
	/* A shift by the operand width is undefined, so r == 0 must not reach
	 * `v >> 64`. Every call here passes a non-zero literal, for which the
	 * ternary folds away. */
	return r == 0 ? v : (((v << r) | (v >> (64 - r))) & UINT64_MAX);
}

/* xoshiro256** and splitmix64 (used only to expand a seed into this state)
 * are bit-exact algorithms defined for 64-bit words; uint_fast64_t is only
 * guaranteed to be *at least* 64 bits, so the state and arithmetic use the
 * exact-width type and convert to uint_fast64_t only at the public API. */
static thread_local uint64_t xoshiro256ss[4] = {
	UINT64_C(0x910A2DEC89025CC1),
	UINT64_C(0xBEEB8DA1658EEC67),
	UINT64_C(0xF893A2EEFB32555E),
	UINT64_C(0x71C18690EE42C90B),
};

uint_fast64_t rand64(void)
{
	uint64_t *restrict s = xoshiro256ss;

	const uint64_t result =
		(rotl64(s[1] * UINT64_C(5), 7) * UINT64_C(9)) & UINT64_MAX;
	const uint64_t t = s[1] << 17u;

	s[2] ^= s[0];
	s[3] ^= s[1];
	s[1] ^= s[2];
	s[0] ^= s[3];

	s[2] ^= t;
	s[3] = rotl64(s[3], 45);
	return result;
}

static inline uint64_t splitmix64(uint64_t *restrict state)
{
	uint64_t result = (*state += UINT64_C(0x9E3779B97f4A7C15));
	result = (result ^ (result >> 30u)) * UINT64_C(0xBF58476D1CE4E5B9);
	result = (result ^ (result >> 27u)) * UINT64_C(0x94D049BB133111EB);
	return result ^ (result >> 31u);
}

void srand64(const uint_fast64_t seed)
{
	uint64_t state = (uint64_t)seed;
	uint64_t *restrict s = xoshiro256ss;
	s[0] = splitmix64(&state);
	s[1] = splitmix64(&state);
	s[2] = splitmix64(&state);
	s[3] = splitmix64(&state);
}

uint_fast64_t rand64n(const uint_fast64_t n)
{
	if ((n & (n + UINT64_C(1))) == UINT64_C(0)) {
		return rand64() & n;
	}

	uint_fast64_t mask = n;
	mask |= (mask >> 1u);
	mask |= (mask >> 2u);
	mask |= (mask >> 4u);
	mask |= (mask >> 8u);
	mask |= (mask >> 16u);
	mask |= (mask >> 32u);

	/* rejection sampling */
	uint_fast64_t x;
	for (x = rand64() & mask; x > n; x &= mask) {
		x = rand64();
	}
	return x;
}

/* Both routines draw the mantissa from a fixed-width random source: 32 bits for
 * float, 64 for double. On a wider floating-point format the `N - MANT_DIG`
 * shift below would go negative (undefined) and the `1 << (MANT_DIG - 1)` scale
 * would overflow its type; mainstream IEEE-754 (FLT_MANT_DIG 24, DBL_MANT_DIG
 * 53) is well within budget. Assert the assumption so an exotic target fails to
 * compile here instead of silently invoking UB and under-filling the mantissa. */
static_assert(
	FLT_MANT_DIG <= 32, "frandf: float mantissa exceeds its 32-bit source");
static_assert(
	DBL_MANT_DIG <= 64, "frand: double mantissa exceeds its 64-bit source");

float frandf(void)
{
	return (float)(((uint_fast32_t)rand64n(UINT32_C(0xFFFFFFFF))) >>
		       (32 - FLT_MANT_DIG)) *
	       (0.5f / ((uint_fast32_t)1 << (FLT_MANT_DIG - 1)));
}

double frand(void)
{
	return (double)(rand64() >> (64 - DBL_MANT_DIG)) *
	       (0.5 / ((uint_fast64_t)1 << (DBL_MANT_DIG - 1)));
}
