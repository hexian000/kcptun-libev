/*-----------------------------------------------------------------------------
 * MurmurHash3 was written by Austin Appleby, and is placed in the public
 * domain. The author hereby disclaims copyright to this source code.
 */

/* csnippets: The following implements are modified to be portable. */

#include "murmurhash.h"
#include "utils/serialize.h"
#include <stdint.h>

#define ROTL(x, r) (((x) << (r)) | ((x) >> ((sizeof(x) * 8) - (r))))

#define LOAD_TAIL(k, tail, len)                                                \
	do {                                                                   \
		(k) = 0;                                                       \
		for (size_t i = 0; i < (len); i++) {                           \
			(k) |= (uint8_t)(tail)[i];                             \
			(k) <<= 8u;                                            \
		}                                                              \
	} while (0)

static inline uint64_t shift_mix(uint64_t v)
{
	return v ^ (v >> 47);
}

uint32_t murmurhash2_32(const void *ptr, size_t len, uint32_t seed)
{
	const uint32_t m = UINT32_C(0x5bd1e995);
	uint32_t hash = seed ^ len;
	const unsigned char *buf = (const unsigned char *)(ptr);

	// Mix 4 bytes at a time into the hash.
	while (len >= 4) {
		uint32_t k = read_uint32(buf);
		k *= m;
		k ^= k >> 24;
		k *= m;
		hash *= m;
		hash ^= k;
		buf += 4;
		len -= 4;
	}

	// Handle the last few bytes of the input array.
	switch (len) {
	case 3:
		hash ^= (uint8_t)(buf[2]) << 16;
		/* fallthrough */
	case 2:
		hash ^= (uint8_t)(buf[1]) << 8;
		/* fallthrough */
	case 1:
		hash ^= (uint8_t)(buf[0]);
		hash *= m;
	};

	// Do a few final mixes of the hash.
	hash ^= hash >> 13;
	hash *= m;
	hash ^= hash >> 15;
	return hash;
}

uint64_t murmurhash2_64(const void *ptr, size_t len, uint64_t seed)
{
	static const uint64_t mul = UINT64_C(0xc6a4a7935bd1e995);
	const unsigned char *const buf = (const unsigned char *)(ptr);

	// Remove the bytes not divisible by the sizeof(uint64_t).  This
	// allows the main loop to process the data as 64-bit integers.
	const size_t len_aligned = len & ~(size_t)0x7;
	const unsigned char *const end = buf + len_aligned;
	size_t hash = seed ^ (len * mul);
	for (const unsigned char *p = buf; p != end; p += 8) {
		const uint64_t data = shift_mix(read_uint64(p) * mul) * mul;
		hash ^= data;
		hash *= mul;
	}
	if ((len & 0x7) != 0) {
		uint64_t data;
		LOAD_TAIL(data, end, len & 0x7);
		hash ^= data;
		hash *= mul;
	}
	hash = shift_mix(hash) * mul;
	hash = shift_mix(hash);
	return hash;
}

/* Finalization mix - force all bits of a hash block to avalanche */
static inline uint32_t fmix32(uint32_t h)
{
	h ^= h >> 16u;
	h *= UINT32_C(0x85ebca6b);
	h ^= h >> 13u;
	h *= UINT32_C(0xc2b2ae35);
	h ^= h >> 16u;
	return h;
}

static inline uint64_t fmix64(uint64_t k)
{
	k ^= k >> 33u;
	k *= UINT64_C(0xff51afd7ed558ccd);
	k ^= k >> 33u;
	k *= UINT64_C(0xc4ceb9fe1a85ec53);
	k ^= k >> 33u;
	return k;
}

uint32_t murmurhash3_32(const void *key, const size_t len, const uint32_t seed)
{
	const unsigned char *restrict data = (const unsigned char *)key;
	const size_t n = len / sizeof(uint32_t);

	uint32_t h1 = seed;

	const uint32_t c1 = UINT32_C(0xcc9e2d51);
	const uint32_t c2 = UINT32_C(0x1b873593);

	/* - body - */
	for (size_t i = 0; i < n; i++) {
		uint32_t k1 = read_uint32(data + (i * sizeof(uint32_t)));

		k1 *= c1;
		k1 = ROTL(k1, 15);
		k1 *= c2;

		h1 ^= k1;
		h1 = ROTL(h1, 13);
		h1 = h1 * UINT32_C(5) + UINT32_C(0xe6546b64);
	}

	/* - tail - */
	if (len & 3u) {
		data += n * sizeof(uint32_t);
		uint32_t k1;
		LOAD_TAIL(k1, data, len & 3u);
		k1 *= c1;
		k1 = ROTL(k1, 15);
		k1 *= c2;
		h1 ^= k1;
	}

	/* - finalization - */
	h1 ^= (uint32_t)len;

	h1 = fmix32(h1);

	return h1;
}

void murmurhash3_128(
	const void *key, const size_t len, const uint64_t seed[2],
	uint64_t out[2])
{
	const unsigned char *restrict data = (const unsigned char *)key;
	const size_t n = len / (sizeof(uint64_t) * 2);

	uint64_t h1 = seed[0];
	uint64_t h2 = seed[1];

	const uint64_t c1 = UINT64_C(0x87c37b91114253d5);
	const uint64_t c2 = UINT64_C(0x4cf5ad432745937f);

	/* - body - */
	for (size_t i = 0; i < n; i++) {
		uint64_t k1 =
			read_uint64(data + (i * 2 + 0) * sizeof(uint64_t));
		uint64_t k2 =
			read_uint64(data + (i * 2 + 1) * sizeof(uint64_t));

		k1 *= c1;
		k1 = ROTL(k1, 31);
		k1 *= c2;
		h1 ^= k1;

		h1 = ROTL(h1, 27);
		h1 += h2;
		h1 = h1 * UINT64_C(5) + UINT64_C(0x52dce729);

		k2 *= c2;
		k2 = ROTL(k2, 33);
		k2 *= c1;
		h2 ^= k2;

		h2 = ROTL(h2, 31);
		h2 += h1;
		h2 = h2 * UINT64_C(5) + UINT64_C(0x38495ab5);
	}

	/* - tail - */
	if (len & 15u) {
		data += n * sizeof(uint64_t) * 2;
		if (len & 8u) {
			uint64_t k1 = read_uint64(data);
			k1 *= c1;
			k1 = ROTL(k1, 31);
			k1 *= c2;
			h1 ^= k1;

			data += sizeof(uint64_t);
			uint64_t k2;
			LOAD_TAIL(k2, data, len & 7u);
			k2 *= c2;
			k2 = ROTL(k2, 33);
			k2 *= c1;
			h2 ^= k2;
		} else {
			uint64_t k1;
			LOAD_TAIL(k1, data, len & 7u);
			k1 *= c1;
			k1 = ROTL(k1, 31);
			k1 *= c2;
			h1 ^= k1;
		}
	}
	/* - finalization - */
	h1 ^= len;
	h2 ^= len;

	h1 += h2;
	h2 += h1;

	h1 = fmix64(h1);
	h2 = fmix64(h2);

	h1 += h2;
	h2 += h1;

	out[0] = h1;
	out[1] = h2;
}
