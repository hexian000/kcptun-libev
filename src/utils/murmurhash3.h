/*-----------------------------------------------------------------------------
 * MurmurHash3 was written by Austin Appleby, and is placed in the public
 * domain. The author hereby disclaims copyright to this source code.
 */

#ifndef MURMURHASH3_H
#define MURMURHASH3_H

#include <stddef.h>
#include <stdint.h>

#include "serialize.h"

static inline uint32_t rotl32(uint32_t x, int8_t r)
{
	return (x << r) | (x >> (32 - r));
}

static inline uint32_t
murmurhash3(const void *key, const size_t len, const uint32_t seed)
{
	const uint8_t *data = (const uint8_t *)key;
	const size_t nblocks = len / sizeof(uint32_t);

	uint32_t h1 = seed;

	const uint32_t c1 = UINT32_C(0xcc9e2d51);
	const uint32_t c2 = UINT32_C(0x1b873593);

	/* body */
	const uint8_t *blocks = data + nblocks * sizeof(uint32_t);
	for (size_t i = -nblocks; i; i++) {
		uint32_t k1 = read_uint32(blocks + (i * sizeof(uint32_t)));

		k1 *= c1;
		k1 = rotl32(k1, 15);
		k1 *= c2;

		h1 ^= k1;
		h1 = rotl32(h1, 13);
		h1 = h1 * UINT32_C(5) + UINT32_C(0xe6546b64);
	}

	/* tail */
	const uint8_t *tail = blocks;
	uint32_t k1 = 0;
	switch (len & 3) {
	case 3:
		k1 ^= tail[2] << 16;
		/* fallthrough */
	case 2:
		k1 ^= tail[1] << 8;
		/* fallthrough */
	case 1:
		k1 ^= tail[0];
		k1 *= c1;
		k1 = rotl32(k1, 15);
		k1 *= c2;
		h1 ^= k1;
		/* fallthrough */
	}

	/* finalization */
	h1 ^= (uint32_t)len;

	/* force all bits of a hash block to avalanche */
	h1 ^= h1 >> 16u;
	h1 *= UINT32_C(0x85ebca6b);
	h1 ^= h1 >> 13u;
	h1 *= UINT32_C(0xc2b2ae35);
	h1 ^= h1 >> 16u;

	return h1;
}

#endif /* MURMURHASH3_H */
