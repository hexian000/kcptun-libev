/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "rand.h"

#include <float.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

uint32_t rand32(void)
{
	static _Thread_local struct {
		uint32_t x;
	} state = { .x = UINT32_C(0) };
	if (state.x == UINT32_C(0)) {
		state.x = xorshift32(time(NULL)) ^
			  xorshift32((uintptr_t)(&state));
	}
	state.x = xorshift32(state.x);
	return state.x;
}

#define ROTL(x, r) (((x) << (r)) | ((x) >> ((sizeof(x) * 8) - (r))))

static inline uint64_t splitmix64(uint64_t *restrict state)
{
	uint64_t result = (*state += UINT64_C(0x9E3779B97f4A7C15));
	result = (result ^ (result >> 30u)) * UINT64_C(0xBF58476D1CE4E5B9);
	result = (result ^ (result >> 27u)) * UINT64_C(0x94D049BB133111EB);
	return result ^ (result >> 31u);
}

/* Algorithm "xoshiro256**" from Blackman & Vigna, "Scrambled linear pseudorandom number generators" */
uint64_t rand64(void)
{
	static _Thread_local struct {
		bool init;
		uint64_t s[4];
	} state = { .init = false };
	uint64_t *restrict s = state.s;
	if (!state.init) {
		uint64_t seed = xorshift64(time(NULL)) ^
				xorshift64((uintptr_t)(&state));
		s[0] = splitmix64(&seed);
		s[1] = splitmix64(&seed);
		s[2] = splitmix64(&seed);
		s[3] = splitmix64(&seed);
		state.init = true;
	}

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

float frandf(void)
{
	return (float)(rand32() >> (32 - FLT_MANT_DIG)) *
	       (0.5f / ((uint32_t)1 << (FLT_MANT_DIG - 1)));
}

double frand(void)
{
	return (double)(rand64() >> (64 - DBL_MANT_DIG)) *
	       (0.5 / ((uint64_t)1 << (DBL_MANT_DIG - 1)));
}
