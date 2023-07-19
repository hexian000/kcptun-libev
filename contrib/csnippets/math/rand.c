/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "rand.h"

#include <float.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define ROTL(x, r) (((x) << (r)) | ((x) >> ((sizeof(x) * 8) - (r))))

static inline uint64_t splitmix64(uint64_t *restrict state)
{
	uint64_t result = (*state += UINT64_C(0x9E3779B97f4A7C15));
	result = (result ^ (result >> 30u)) * UINT64_C(0xBF58476D1CE4E5B9);
	result = (result ^ (result >> 27u)) * UINT64_C(0x94D049BB133111EB);
	return result ^ (result >> 31u);
}

static _Thread_local uint64_t xoshiro256ss[4] = {
	UINT64_C(0x910A2DEC89025CC1),
	UINT64_C(0xBEEB8DA1658EEC67),
	UINT64_C(0xF893A2EEFB32555E),
	UINT64_C(0x71C18690EE42C90B),
};

void srand64(uint64_t seed)
{
	uint64_t *restrict s = xoshiro256ss;
	s[0] = splitmix64(&seed);
	s[1] = splitmix64(&seed);
	s[2] = splitmix64(&seed);
	s[3] = splitmix64(&seed);
}

uint64_t rand64(void)
{
	uint64_t *restrict s = xoshiro256ss;

	const uint64_t result =
		ROTL(s[1] * UINT64_C(5), UINT64_C(7)) * UINT64_C(9);
	const uint64_t t = s[1] << 17u;

	s[2] ^= s[0];
	s[3] ^= s[1];
	s[1] ^= s[2];
	s[0] ^= s[3];

	s[2] ^= t;
	s[3] = ROTL(s[3], 45);
	return result;
}

uint64_t randn64(const uint64_t n)
{
	if ((n & (n + UINT64_C(1))) == UINT64_C(0)) {
		return rand64() & n;
	}

	uint64_t mask = n;
	mask |= (mask >> 1u);
	mask |= (mask >> 2u);
	mask |= (mask >> 4u);
	mask |= (mask >> 8u);
	mask |= (mask >> 16u);
	mask |= (mask >> 32u);

	/* rejection sampling */
	uint64_t x;
	for (x = rand64() & mask; x > n; x &= mask) {
		x = rand64();
	}
	return x;
}

float frandf(void)
{
	return (float)(((uint32_t)rand64()) >> (32 - FLT_MANT_DIG)) *
	       (0.5f / ((uint32_t)1 << (FLT_MANT_DIG - 1)));
}

double frand(void)
{
	return (double)(rand64() >> (64 - DBL_MANT_DIG)) *
	       (0.5 / ((uint64_t)1 << (DBL_MANT_DIG - 1)));
}
