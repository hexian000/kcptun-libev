// Copyright (c) 2011 Google, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// CityHash, by Geoff Pike and Jyrki Alakuijala
//
// This file provides CityHash64() and related functions.
//
// It's probably possible to create even faster hash functions by
// writing a program that systematically explores some of the space of
// possible hash functions, by using SIMD instructions, or by
// compromising on hash quality.

/* csnippets: The following implementations are modified to conform to the ISO C standard. */

#include "cityhash.h"
#include "utils/serialize.h"
#include "utils/likely.h"

#include <stdint.h>

// Some primes between 2^63 and 2^64 for various uses.
static const uint64_t k0 = UINT64_C(0xc3a5c85c97cb3127);
static const uint64_t k1 = UINT64_C(0xb492b66fbe98f273);
static const uint64_t k2 = UINT64_C(0x9ae16a3b2f90404f);

#define SWAP(a, b)                                                             \
	do {                                                                   \
		(a) ^= (b), (b) ^= (a), (a) ^= (b);                            \
	} while (0)

#ifdef __has_builtin
#if __has_builtin(__builtin_bswap64)
#define bswap_64 __builtin_bswap64
#endif
#endif

#ifndef bswap_64
static inline uint64_t bswap_64(uint64_t v)
{
	uint8_t *restrict b = (uint8_t *)&v;
	SWAP(b[0], b[7]);
	SWAP(b[1], b[6]);
	SWAP(b[2], b[5]);
	SWAP(b[3], b[4]);
	return v;
}
#endif

#define PERMUTE3(a, b, c)                                                      \
	do {                                                                   \
		SWAP(a, c);                                                    \
		SWAP(b, c);                                                    \
	} while (0)

// Bitwise right rotate.  Normally this will compile to a single
// instruction, especially if the shift is a manifest constant.
#define ROTR(x, r) (((x) >> (r)) | ((x) << ((sizeof(x) * 8) - (r))))

static inline uint64_t shift_mix(const uint64_t v)
{
	return v ^ (v >> 47);
}

// Hash 128 input bits down to 64 bits of output.
// This is intended to be a reasonably good hash function.
static inline uint64_t Hash128to64(const uint64_t x[2])
{
	// Murmur-inspired hashing.
	const uint64_t kMul = 0x9ddfea08eb382d69ULL;
	uint64_t a = (x[0] ^ x[1]) * kMul;
	a ^= (a >> 47);
	uint64_t b = (x[1] ^ a) * kMul;
	b ^= (b >> 47);
	b *= kMul;
	return b;
}

static inline uint64_t HashLen16(uint64_t u, uint64_t v)
{
	return Hash128to64((uint64_t[]){ u, v });
}

static inline uint64_t HashLen16mul(uint64_t u, uint64_t v, uint64_t mul)
{
	// Murmur-inspired hashing.
	uint64_t a = (u ^ v) * mul;
	a ^= (a >> 47);
	uint64_t b = (v ^ a) * mul;
	b ^= (b >> 47);
	b *= mul;
	return b;
}

static uint64_t HashLen0to16(const unsigned char *s, size_t len)
{
	if (len >= 8) {
		uint64_t mul = k2 + len * 2;
		uint64_t a = read_uint64(s) + k2;
		uint64_t b = read_uint64(s + len - 8);
		uint64_t c = ROTR(b, 37) * mul + a;
		uint64_t d = (ROTR(a, 25) + b) * mul;
		return HashLen16mul(c, d, mul);
	}
	if (len >= 4) {
		uint64_t mul = k2 + len * 2;
		uint64_t a = read_uint32(s);
		return HashLen16mul(
			len + (a << 3), read_uint32(s + len - 4), mul);
	}
	if (len > 0) {
		uint8_t a = (uint8_t)(s[0]);
		uint8_t b = (uint8_t)(s[len >> 1]);
		uint8_t c = (uint8_t)(s[len - 1]);
		uint32_t y = (uint32_t)(a) + ((uint32_t)(b) << 8);
		uint32_t z = (uint32_t)(len) + ((uint32_t)(c) << 2);
		return shift_mix(y * k2 ^ z * k0) * k2;
	}
	return k2;
}

// This probably works well for 16-byte strings as well, but it may be overkill
// in that case.
static inline uint64_t HashLen17to32(const unsigned char *s, size_t len)
{
	uint64_t mul = k2 + len * 2;
	uint64_t a = read_uint64(s) * k1;
	uint64_t b = read_uint64(s + 8);
	uint64_t c = read_uint64(s + len - 8) * mul;
	uint64_t d = read_uint64(s + len - 16) * k2;
	return HashLen16mul(
		ROTR(a + b, 43) + ROTR(c, 30) + d, a + ROTR(b + k2, 18) + c,
		mul);
}

// Return a 16-byte hash for 48 bytes.  Quick and dirty.
// Callers do best to use "random-looking" values for a and b.
static inline void WeakHashLen32WithSeeds(
	uint64_t *restrict hash, uint64_t w, uint64_t x, uint64_t y, uint64_t z,
	uint64_t a, uint64_t b)
{
	a += w;
	b = ROTR(b + a + z, 21);
	const uint64_t c = a;
	a += x;
	a += y;
	b += ROTR(a, 44);

	hash[0] = a + z;
	hash[1] = b + c;
}

// Return a 16-byte hash for s[0] ... s[31], a, and b.  Quick and dirty.
static inline void WeakHashLen32WithSeedsStr(
	uint64_t *restrict hash, const unsigned char *s, uint64_t a, uint64_t b)
{
	WeakHashLen32WithSeeds(
		hash, read_uint64(s), read_uint64(s + 8), read_uint64(s + 16),
		read_uint64(s + 24), a, b);
}

// Return an 8-byte hash for 33 to 64 bytes.
static inline uint64_t HashLen33to64(const unsigned char *s, size_t len)
{
	uint64_t mul = k2 + len * 2;
	uint64_t a = read_uint64(s) * k2;
	uint64_t b = read_uint64(s + 8);
	uint64_t c = read_uint64(s + len - 24);
	uint64_t d = read_uint64(s + len - 32);
	uint64_t e = read_uint64(s + 16) * k2;
	uint64_t f = read_uint64(s + 24) * 9;
	uint64_t g = read_uint64(s + len - 8);
	uint64_t h = read_uint64(s + len - 16) * mul;
	uint64_t u = ROTR(a + g, 43) + (ROTR(b, 30) + c) * 9;
	uint64_t v = ((a + g) ^ d) + f + 1;
	uint64_t w = bswap_64((u + v) * mul) + h;
	uint64_t x = ROTR(e + f, 42) + c;
	uint64_t y = (bswap_64((v + w) * mul) + g) * mul;
	uint64_t z = e + f + c;
	a = bswap_64((x + z) * mul + y) + b;
	b = shift_mix((z + a) * mul + d + h) * mul;
	return b + x;
}

static uint64_t CityHash64(const void *ptr, size_t len)
{
	const unsigned char *s = ptr;
	if (len <= 32) {
		if (len <= 16) {
			return HashLen0to16(s, len);
		} else {
			return HashLen17to32(s, len);
		}
	} else if (len <= 64) {
		return HashLen33to64(s, len);
	}

	// For strings over 64 bytes we hash the end first, and then as we
	// loop we keep 56 bytes of state: v, w, x, y, and z.
	uint64_t x = read_uint64(s + len - 40);
	uint64_t y = read_uint64(s + len - 16) + read_uint64(s + len - 56);
	uint64_t z = HashLen16(
		read_uint64(s + len - 48) + len, read_uint64(s + len - 24));
	uint64_t v[2];
	WeakHashLen32WithSeedsStr(v, s + len - 64, len, z);
	uint64_t w[2];
	WeakHashLen32WithSeedsStr(w, s + len - 32, y + k1, x);
	x = x * k1 + read_uint64(s);

	// Decrease len to the nearest multiple of 64, and operate on 64-byte chunks.
	len = (len - 1) & ~(size_t)(63);
	do {
		x = ROTR(x + y + v[0] + read_uint64(s + 8), 37) * k1;
		y = ROTR(y + v[1] + read_uint64(s + 48), 42) * k1;
		x ^= w[1];
		y += v[0] + read_uint64(s + 40);
		z = ROTR(z + w[0], 33) * k1;
		WeakHashLen32WithSeedsStr(v, s, v[1] * k1, x + w[0]);
		WeakHashLen32WithSeedsStr(
			w, s + 32, z + w[1], y + read_uint64(s + 16));
		SWAP(z, x);
		s += 64;
		len -= 64;
	} while (len != 0);
	return HashLen16(
		HashLen16(v[0], w[0]) + shift_mix(y) * k1 + z,
		HashLen16(v[1], w[1]) + x);
}

static uint64_t
CityHash64WithSeeds(const void *ptr, size_t len, uint64_t seed0, uint64_t seed1)
{
	return HashLen16(CityHash64(ptr, len) - seed0, seed1);
}

static uint64_t CityHash64WithSeed(const void *ptr, size_t len, uint64_t seed)
{
	return CityHash64WithSeeds(ptr, len, k2, seed);
}

// A subroutine for CityHash128().  Returns a decent 128-bit hash for strings
// of any length representable in signed long.  Based on City and Murmur.
static void CityMurmur(
	unsigned char hash[16], const unsigned char *s, size_t len,
	const unsigned char seed[16])
{
	uint64_t a = read_uint64(seed);
	uint64_t b = read_uint64(seed + sizeof(uint64_t));
	uint64_t c = 0;
	uint64_t d = 0;
	if (len <= 16) {
		a = shift_mix(a * k1) * k1;
		c = b * k1 + HashLen0to16(s, len);
		d = shift_mix(a + (len >= 8 ? read_uint64(s) : c));
	} else {
		c = HashLen16(read_uint64(s + len - 8) + k1, a);
		d = HashLen16(b + len, c + read_uint64(s + len - 16));
		a += d;
		// len > 16 here, so do...while is safe
		do {
			a ^= shift_mix(read_uint64(s) * k1) * k1;
			a *= k1;
			b ^= a;
			c ^= shift_mix(read_uint64(s + 8) * k1) * k1;
			c *= k1;
			d ^= c;
			s += 16;
			len -= 16;
		} while (len > 16);
	}
	a = HashLen16(a, c);
	b = HashLen16(d, b);

	write_uint64(hash, a ^ b);
	write_uint64(hash + sizeof(uint64_t), HashLen16(b, a));
}

static void CityHash128WithSeed(
	unsigned char hash[16], const void *ptr, size_t len,
	const unsigned char seed[16])
{
	const unsigned char *s = ptr;
	if (len < 128) {
		CityMurmur(hash, s, len, seed);
		return;
	}

	// We expect len >= 128 to be the common case.  Keep 56 bytes of state:
	// v, w, x, y, and z.
	uint64_t v[2], w[2];
	uint64_t x = read_uint64(seed);
	uint64_t y = read_uint64(seed + sizeof(uint64_t));
	uint64_t z = len * k1;
	v[0] = ROTR(y ^ k1, 49) * k1 + read_uint64(s);
	v[1] = ROTR(v[0], 42) * k1 + read_uint64(s + 8);
	w[0] = ROTR(y + z, 35) * k1 + x;
	w[1] = ROTR(x + read_uint64(s + 88), 53) * k1;

	// This is the same inner loop as CityHash64(), manually unrolled.
	do {
		x = ROTR(x + y + v[0] + read_uint64(s + 8), 37) * k1;
		y = ROTR(y + v[1] + read_uint64(s + 48), 42) * k1;
		x ^= w[1];
		y += v[0] + read_uint64(s + 40);
		z = ROTR(z + w[0], 33) * k1;
		WeakHashLen32WithSeedsStr(v, s, v[1] * k1, x + w[0]);
		WeakHashLen32WithSeedsStr(
			w, s + 32, z + w[1], y + read_uint64(s + 16));
		SWAP(z, x);
		s += 64;
		x = ROTR(x + y + v[0] + read_uint64(s + 8), 37) * k1;
		y = ROTR(y + v[1] + read_uint64(s + 48), 42) * k1;
		x ^= w[1];
		y += v[0] + read_uint64(s + 40);
		z = ROTR(z + w[0], 33) * k1;
		WeakHashLen32WithSeedsStr(v, s, v[1] * k1, x + w[0]);
		WeakHashLen32WithSeedsStr(
			w, s + 32, z + w[1], y + read_uint64(s + 16));
		SWAP(z, x);
		s += 64;
		len -= 128;
	} while (LIKELY(len >= 128));
	x += ROTR(v[0] + z, 49) * k0;
	y = y * k0 + ROTR(w[1], 37);
	z = z * k0 + ROTR(w[0], 27);
	w[0] *= 9;
	v[0] *= k0;
	// If 0 < len < 128, hash up to 4 chunks of 32 bytes each from the end of s.
	for (size_t tail_done = 0; tail_done < len;) {
		tail_done += 32;
		y = ROTR(x + y, 42) * k0 + v[1];
		w[0] += read_uint64(s + len - tail_done + 16);
		x = x * k0 + w[0];
		z += w[1] + read_uint64(s + len - tail_done);
		w[1] += v[0];
		WeakHashLen32WithSeedsStr(
			v, s + len - tail_done, v[0] + z, v[1]);
		v[0] *= k0;
	}
	// At this point our 56 bytes of state should contain more than
	// enough information for a strong 128-bit hash.  We use two
	// different 56-byte-to-8-byte hashes to get a 16-byte final result.
	x = HashLen16(x, v[0]);
	y = HashLen16(y + z, w[0]);

	write_uint64(hash, HashLen16(x + v[1], w[1]) + y);
	write_uint64(hash + sizeof(uint64_t), HashLen16(x + w[1], y + v[1]));
}

/*
static void CityHash128(unsigned char hash[16], const void *ptr, size_t len)
{
	unsigned char seed[16];
	if (len < 16) {
		write_uint64(seed, k0);
		write_uint64(seed + sizeof(uint64_t), k1);
		CityHash128WithSeed(hash, ptr, len, seed);
		return;
	}
	const unsigned char *s = ptr;
	write_uint64(seed, read_uint64(s));
	write_uint64(seed + sizeof(uint64_t), read_uint64(s + 8) + k0);
	CityHash128WithSeed(hash, s + 16, len - 16, seed);
}
*/

uint64_t cityhash64_64(const void *ptr, const size_t len, const uint64_t seed)
{
	return CityHash64WithSeed(ptr, len, seed);
}

uint32_t
cityhash64low_32(const void *ptr, const size_t len, const uint32_t seed)
{
	return (uint32_t)CityHash64WithSeed(ptr, len, seed);
}

void cityhash128_128(
	unsigned char hash[16], const void *ptr, const size_t len,
	const unsigned char seed[16])
{
	CityHash128WithSeed(hash, ptr, len, seed);
}
