/*-----------------------------------------------------------------------------
 * MurmurHash3 was written by Austin Appleby, and is placed in the public
 * domain. The author hereby disclaims copyright to this source code.
 */

#ifndef MURMURHASH3_H
#define MURMURHASH3_H

#include <stddef.h>
#include <stdint.h>

#include "serialize.h"

#define ROTL32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))
#define ROTL64(x, r) (((x) << (r)) | ((x) >> (64 - (r))))

static inline uint32_t
murmurhash3(const void *key, const size_t len, const uint32_t seed)
{
	const uint8_t *data = (const uint8_t *)key;
	const size_t n = len / sizeof(uint32_t);

	uint32_t h1 = seed;

	const uint32_t c1 = UINT32_C(0xcc9e2d51);
	const uint32_t c2 = UINT32_C(0x1b873593);

	/* - body - */
	const uint8_t *blocks = data + n * sizeof(uint32_t);
	for (size_t i = -n; i; i++) {
		uint32_t k1 = read_uint32(blocks + (i * sizeof(uint32_t)));

		k1 *= c1;
		k1 = ROTL32(k1, 15);
		k1 *= c2;

		h1 ^= k1;
		h1 = ROTL32(h1, 13);
		h1 = h1 * UINT32_C(5) + UINT32_C(0xe6546b64);
	}

	/* - tail - */
	const uint8_t *tail = blocks;
	uint32_t k1 = 0;
	switch (len & 3) {
	case 3:
		k1 ^= ((uint32_t)tail[2]) << 16;
		/* fallthrough */
	case 2:
		k1 ^= ((uint32_t)tail[1]) << 8;
		/* fallthrough */
	case 1:
		k1 ^= ((uint32_t)tail[0]);
		k1 *= c1;
		k1 = ROTL32(k1, 15);
		k1 *= c2;
		h1 ^= k1;
	}

	/* - finalization - */
	h1 ^= (uint32_t)len;

	/* force all bits of a hash block to avalanche */
	h1 ^= h1 >> 16u;
	h1 *= UINT32_C(0x85ebca6b);
	h1 ^= h1 >> 13u;
	h1 *= UINT32_C(0xc2b2ae35);
	h1 ^= h1 >> 16u;

	return h1;
}

static inline void murmurhash3_128(
	const void *key, const size_t len, const uint32_t seed, uint64_t *out)
{
	const uint8_t *data = (const uint8_t *)key;
	const size_t n = len / (sizeof(uint64_t) * 2);

	uint64_t h1 = seed;
	uint64_t h2 = seed;

	const uint64_t c1 = UINT64_C(0x87c37b91114253d5);
	const uint64_t c2 = UINT64_C(0x4cf5ad432745937f);

	/* - body - */
	const uint64_t *blocks = (const uint64_t *)(data);

	for (size_t i = 0; i < n; i++) {
		uint64_t k1 = read_uint64(
			(const unsigned char *)(blocks + i * 2 + 0));
		uint64_t k2 = read_uint64(
			(const unsigned char *)(blocks + i * 2 + 1));

		k1 *= c1;
		k1 = ROTL64(k1, 31);
		k1 *= c2;
		h1 ^= k1;

		h1 = ROTL64(h1, 27);
		h1 += h2;
		h1 = h1 * UINT64_C(5) + UINT64_C(0x52dce729);

		k2 *= c2;
		k2 = ROTL64(k2, 33);
		k2 *= c1;
		h2 ^= k2;

		h2 = ROTL64(h2, 31);
		h2 += h1;
		h2 = h2 * UINT64_C(5) + UINT64_C(0x38495ab5);
	}

	/* - tail - */
	const uint8_t *tail = (const uint8_t *)(data + n * 16);

	uint64_t k1 = 0;
	uint64_t k2 = 0;

	switch (len & 15) {
	case 15:
		k2 ^= ((uint64_t)tail[14]) << 48;
		/* fallthrough */
	case 14:
		k2 ^= ((uint64_t)tail[13]) << 40;
		/* fallthrough */
	case 13:
		k2 ^= ((uint64_t)tail[12]) << 32;
		/* fallthrough */
	case 12:
		k2 ^= ((uint64_t)tail[11]) << 24;
		/* fallthrough */
	case 11:
		k2 ^= ((uint64_t)tail[10]) << 16;
		/* fallthrough */
	case 10:
		k2 ^= ((uint64_t)tail[9]) << 8;
		/* fallthrough */
	case 9:
		k2 ^= ((uint64_t)tail[8]) << 0;
		k2 *= c2;
		k2 = ROTL64(k2, 33);
		k2 *= c1;
		h2 ^= k2;
		/* fallthrough */
	case 8:
		k1 ^= ((uint64_t)tail[7]) << 56;
		/* fallthrough */
	case 7:
		k1 ^= ((uint64_t)tail[6]) << 48;
		/* fallthrough */
	case 6:
		k1 ^= ((uint64_t)tail[5]) << 40;
		/* fallthrough */
	case 5:
		k1 ^= ((uint64_t)tail[4]) << 32;
		/* fallthrough */
	case 4:
		k1 ^= ((uint64_t)tail[3]) << 24;
		/* fallthrough */
	case 3:
		k1 ^= ((uint64_t)tail[2]) << 16;
		/* fallthrough */
	case 2:
		k1 ^= ((uint64_t)tail[1]) << 8;
		/* fallthrough */
	case 1:
		k1 ^= ((uint64_t)tail[0]) << 0;
		k1 *= c1;
		k1 = ROTL64(k1, 31);
		k1 *= c2;
		h1 ^= k1;
	};

	/* - finalization - */
	h1 ^= len;
	h2 ^= len;

	h1 += h2;
	h2 += h1;

	/* h1 = fmix64(h1) */
	h1 ^= h1 >> 33;
	h1 *= UINT64_C(0xff51afd7ed558ccd);
	h1 ^= h1 >> 33;
	h1 *= UINT64_C(0xc4ceb9fe1a85ec53);
	h1 ^= h1 >> 33;

	/* h2 = fmix64(h2) */
	h2 ^= h2 >> 33;
	h2 *= UINT64_C(0xff51afd7ed558ccd);
	h2 ^= h2 >> 33;
	h2 *= UINT64_C(0xc4ceb9fe1a85ec53);
	h2 ^= h2 >> 33;

	h1 += h2;
	h2 += h1;

	out[0] = h1;
	out[1] = h2;
}

#endif /* MURMURHASH3_H */
