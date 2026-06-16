/* Copyright (c) 2011 Google, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * CityHash, by Geoff Pike and Jyrki Alakuijala
 *
 * This file provides CityHash64() and related functions.
 *
 * It's probably possible to create even faster hash functions by
 * writing a program that systematically explores some of the space of
 * possible hash functions, by using SIMD instructions, or by
 * compromising on hash quality.
 */

/* csnippets: The following implementations are modified to conform to the ISO C standard. */

#include "cityhash.h"

#include "utils/bswap.h"
#include "utils/likely.h"
#include "utils/serialize.h"

#include <stddef.h>
#include <stdint.h>

/* Some primes between 2^63 and 2^64 for various uses. */
static const uint_least64_t k0 = UINT64_C(0xc3a5c85c97cb3127);
static const uint_least64_t k1 = UINT64_C(0xb492b66fbe98f273);
static const uint_least64_t k2 = UINT64_C(0x9ae16a3b2f90404f);

/* Confine values to 64 bits using only the C11-mandated UINT64_C macro, so
 * the code never depends on the optional uint64_t type while still doing
 * exact mod-2^64 arithmetic where it matters: the rotate and the
 * murmur-style mixes below (the only places a value is shifted right), plus
 * BSWAP64() which masks its own input. Plain +, *, ^ and << preserve the
 * low 64 bits, and write_uint64_le() emits exactly those, so nothing else
 * needs a mask. */
#define M64(x) ((x) & UINT64_C(0xffffffffffffffff))

/* Bitwise right rotate within 64 bits. */
static inline uint_fast64_t rotr64(const uint_fast64_t x, const unsigned int r)
{
	const uint_fast64_t v = M64(x);
	return M64((v >> r) | (v << (64u - r)));
}

static inline uint_fast64_t shift_mix(uint_fast64_t v)
{
	v = M64(v);
	return v ^ (v >> 47u);
}

/* Murmur-inspired 128->64 bit mix. */
static inline uint_fast64_t
hash16mul(const uint_fast64_t u, const uint_fast64_t v, const uint_fast64_t mul)
{
	uint_fast64_t a = M64((u ^ v) * mul);
	a ^= a >> 47u;
	uint_fast64_t b = M64((v ^ a) * mul);
	b ^= b >> 47u;
	b = M64(b * mul);
	return b;
}

static inline uint_fast64_t
HashLen16(const uint_fast64_t u, const uint_fast64_t v)
{
	return hash16mul(u, v, UINT64_C(0x9ddfea08eb382d69));
}

static inline uint_fast64_t HashLen16mul(
	const uint_fast64_t u, const uint_fast64_t v, const uint_fast64_t mul)
{
	return hash16mul(u, v, mul);
}

static uint_fast64_t HashLen0to16(const unsigned char *restrict s, size_t len)
{
	if (len >= 8) {
		uint_fast64_t mul = k2 + len * 2;
		uint_fast64_t a = read_uint64_le(s) + k2;
		uint_fast64_t b = read_uint64_le(s + len - 8);
		uint_fast64_t c = rotr64(b, 37) * mul + a;
		uint_fast64_t d = (rotr64(a, 25) + b) * mul;
		return HashLen16mul(c, d, mul);
	}
	if (len >= 4) {
		uint_fast64_t mul = k2 + len * 2;
		uint_fast64_t a = read_uint32_le(s);
		return HashLen16mul(
			len + (a << 3), read_uint32_le(s + len - 4), mul);
	}
	if (len > 0) {
		uint_fast8_t a = (uint_fast8_t)(s[0]);
		uint_fast8_t b = (uint_fast8_t)(s[len >> 1]);
		uint_fast8_t c = (uint_fast8_t)(s[len - 1]);
		uint_fast32_t y =
			(uint_fast32_t)(a) + ((uint_fast32_t)(b) << 8);
		uint_fast32_t z =
			(uint_fast32_t)(len) + ((uint_fast32_t)(c) << 2);
		return shift_mix(y * k2 ^ z * k0) * k2;
	}
	return k2;
}

/* This probably works well for 16-byte strings as well, but it may be overkill
 * in that case. */
static inline uint_fast64_t
HashLen17to32(const unsigned char *restrict s, size_t len)
{
	uint_fast64_t mul = k2 + len * 2;
	uint_fast64_t a = read_uint64_le(s) * k1;
	uint_fast64_t b = read_uint64_le(s + 8);
	uint_fast64_t c = read_uint64_le(s + len - 8) * mul;
	uint_fast64_t d = read_uint64_le(s + len - 16) * k2;
	return HashLen16mul(
		rotr64(a + b, 43) + rotr64(c, 30) + d,
		a + rotr64(b + k2, 18) + c, mul);
}

/* Return a 16-byte hash for 48 bytes. Quick and dirty.
 * Callers do best to use "random-looking" values for a and b. */
static inline void WeakHashLen32WithSeeds(
	uint_fast64_t *restrict hash, uint_fast64_t w, uint_fast64_t x,
	uint_fast64_t y, uint_fast64_t z, uint_fast64_t a, uint_fast64_t b)
{
	a += w;
	b = rotr64(b + a + z, 21);
	const uint_fast64_t c = a;
	a += x;
	a += y;
	b += rotr64(a, 44);

	hash[0] = a + z;
	hash[1] = b + c;
}

/* Return a 16-byte hash for s[0] ... s[31], a, and b. Quick and dirty. */
static inline void WeakHashLen32WithSeedsStr(
	uint_fast64_t *restrict hash, const unsigned char *s, uint_fast64_t a,
	uint_fast64_t b)
{
	WeakHashLen32WithSeeds(
		hash, read_uint64_le(s), read_uint64_le(s + 8),
		read_uint64_le(s + 16), read_uint64_le(s + 24), a, b);
}

/* Return an 8-byte hash for 33 to 64 bytes. */
static inline uint_fast64_t
HashLen33to64(const unsigned char *restrict s, size_t len)
{
	uint_fast64_t mul = k2 + len * 2;
	uint_fast64_t a = read_uint64_le(s) * k2;
	uint_fast64_t b = read_uint64_le(s + 8);
	uint_fast64_t c = read_uint64_le(s + len - 24);
	uint_fast64_t d = read_uint64_le(s + len - 32);
	uint_fast64_t e = read_uint64_le(s + 16) * k2;
	uint_fast64_t f = read_uint64_le(s + 24) * 9;
	uint_fast64_t g = read_uint64_le(s + len - 8);
	uint_fast64_t h = read_uint64_le(s + len - 16) * mul;
	uint_fast64_t u = rotr64(a + g, 43) + (rotr64(b, 30) + c) * 9;
	uint_fast64_t v = ((a + g) ^ d) + f + 1;
	uint_fast64_t w = BSWAP64((u + v) * mul) + h;
	uint_fast64_t x = rotr64(e + f, 42) + c;
	uint_fast64_t y = (BSWAP64((v + w) * mul) + g) * mul;
	uint_fast64_t z = e + f + c;
	a = BSWAP64((x + z) * mul + y) + b;
	b = shift_mix((z + a) * mul + d + h) * mul;
	return b + x;
}

static uint_fast64_t CityHash64(const void *restrict ptr, size_t len)
{
	const unsigned char *s = ptr;
	if (len <= 32) {
		if (len <= 16) {
			return HashLen0to16(s, len);
		}
		return HashLen17to32(s, len);
	}
	if (len <= 64) {
		return HashLen33to64(s, len);
	}

	/* For strings over 64 bytes we hash the end first, and then as we
	 * loop we keep 56 bytes of state: v, w, x, y, and z. */
	uint_fast64_t x = read_uint64_le(s + len - 40);
	uint_fast64_t y =
		read_uint64_le(s + len - 16) + read_uint64_le(s + len - 56);
	uint_fast64_t z = HashLen16(
		read_uint64_le(s + len - 48) + len,
		read_uint64_le(s + len - 24));
	uint_fast64_t v[2];
	WeakHashLen32WithSeedsStr(v, s + len - 64, len, z);
	uint_fast64_t w[2];
	WeakHashLen32WithSeedsStr(w, s + len - 32, y + k1, x);
	x = x * k1 + read_uint64_le(s);

	/* Decrease len to the nearest multiple of 64, and operate on 64-byte chunks. */
	len = (len - 1) & ~(size_t)(63);
	do {
		x = rotr64(x + y + v[0] + read_uint64_le(s + 8), 37) * k1;
		y = rotr64(y + v[1] + read_uint64_le(s + 48), 42) * k1;
		x ^= w[1];
		y += v[0] + read_uint64_le(s + 40);
		z = rotr64(z + w[0], 33) * k1;
		WeakHashLen32WithSeedsStr(v, s, v[1] * k1, x + w[0]);
		WeakHashLen32WithSeedsStr(
			w, s + 32, z + w[1], y + read_uint64_le(s + 16));
		INTSWAP(z, x);
		s += 64;
		len -= 64;
	} while (len != 0);
	return HashLen16(
		HashLen16(v[0], w[0]) + shift_mix(y) * k1 + z,
		HashLen16(v[1], w[1]) + x);
}

static uint_fast64_t CityHash64WithSeeds(
	const void *restrict ptr, size_t len, uint_fast64_t seed0,
	uint_fast64_t seed1)
{
	return HashLen16(CityHash64(ptr, len) - seed0, seed1);
}

static uint_fast64_t
CityHash64WithSeed(const void *restrict ptr, size_t len, uint_fast64_t seed)
{
	return CityHash64WithSeeds(ptr, len, k2, seed);
}

/* A subroutine for CityHash128().  Returns a decent 128-bit hash for strings
 * of any length representable in signed long.  Based on City and Murmur. */
static void CityMurmur(
	unsigned char hash[16], const unsigned char *s, size_t len,
	const unsigned char seed[16])
{
	uint_fast64_t a = read_uint64_le(seed);
	uint_fast64_t b = read_uint64_le(seed + 8u);
	uint_fast64_t c = 0;
	uint_fast64_t d = 0;
	if (len <= 16) {
		a = shift_mix(a * k1) * k1;
		c = b * k1 + HashLen0to16(s, len);
		d = shift_mix(a + (len >= 8 ? read_uint64_le(s) : c));
	} else {
		c = HashLen16(read_uint64_le(s + len - 8) + k1, a);
		d = HashLen16(b + len, c + read_uint64_le(s + len - 16));
		a += d;
		/* len > 16 here, so do...while is safe */
		do {
			a ^= shift_mix(read_uint64_le(s) * k1) * k1;
			a *= k1;
			b ^= a;
			c ^= shift_mix(read_uint64_le(s + 8) * k1) * k1;
			c *= k1;
			d ^= c;
			s += 16;
			len -= 16;
		} while (len > 16);
	}
	a = HashLen16(a, c);
	b = HashLen16(d, b);

	write_uint64_le(hash, a ^ b);
	write_uint64_le(hash + 8u, HashLen16(b, a));
}

static void CityHash128WithSeed(
	unsigned char hash[restrict 16], const void *restrict ptr, size_t len,
	const unsigned char seed[restrict 16])
{
	const unsigned char *s = ptr;
	if (len < 128) {
		CityMurmur(hash, s, len, seed);
		return;
	}

	/* We expect len >= 128 to be the common case.  Keep 56 bytes of state:
	 * v, w, x, y, and z. */
	uint_fast64_t v[2], w[2];
	uint_fast64_t x = read_uint64_le(seed);
	uint_fast64_t y = read_uint64_le(seed + 8u);
	uint_fast64_t z = len * k1;
	v[0] = rotr64(y ^ k1, 49) * k1 + read_uint64_le(s);
	v[1] = rotr64(v[0], 42) * k1 + read_uint64_le(s + 8);
	w[0] = rotr64(y + z, 35) * k1 + x;
	w[1] = rotr64(x + read_uint64_le(s + 88), 53) * k1;

	/* This is the same inner loop as CityHash64(), manually unrolled. */
	do {
		x = rotr64(x + y + v[0] + read_uint64_le(s + 8), 37) * k1;
		y = rotr64(y + v[1] + read_uint64_le(s + 48), 42) * k1;
		x ^= w[1];
		y += v[0] + read_uint64_le(s + 40);
		z = rotr64(z + w[0], 33) * k1;
		WeakHashLen32WithSeedsStr(v, s, v[1] * k1, x + w[0]);
		WeakHashLen32WithSeedsStr(
			w, s + 32, z + w[1], y + read_uint64_le(s + 16));
		INTSWAP(z, x);
		s += 64;
		x = rotr64(x + y + v[0] + read_uint64_le(s + 8), 37) * k1;
		y = rotr64(y + v[1] + read_uint64_le(s + 48), 42) * k1;
		x ^= w[1];
		y += v[0] + read_uint64_le(s + 40);
		z = rotr64(z + w[0], 33) * k1;
		WeakHashLen32WithSeedsStr(v, s, v[1] * k1, x + w[0]);
		WeakHashLen32WithSeedsStr(
			w, s + 32, z + w[1], y + read_uint64_le(s + 16));
		INTSWAP(z, x);
		s += 64;
		len -= 128;
	} while (LIKELY(len >= 128));
	x += rotr64(v[0] + z, 49) * k0;
	y = y * k0 + rotr64(w[1], 37);
	z = z * k0 + rotr64(w[0], 27);
	w[0] *= 9;
	v[0] *= k0;
	/* If 0 < len < 128, hash up to 4 chunks of 32 bytes each from the end of s. */
	for (size_t tail_done = 0; tail_done < len;) {
		tail_done += 32;
		y = rotr64(x + y, 42) * k0 + v[1];
		w[0] += read_uint64_le(s + len - tail_done + 16);
		x = x * k0 + w[0];
		z += w[1] + read_uint64_le(s + len - tail_done);
		w[1] += v[0];
		WeakHashLen32WithSeedsStr(
			v, s + len - tail_done, v[0] + z, v[1]);
		v[0] *= k0;
	}
	/* At this point our 56 bytes of state should contain more than
	 * enough information for a strong 128-bit hash.  We use two
	 * different 56-byte-to-8-byte hashes to get a 16-byte final result. */
	x = HashLen16(x, v[0]);
	y = HashLen16(y + z, w[0]);

	write_uint64_le(hash, HashLen16(x + v[1], w[1]) + y);
	write_uint64_le(hash + 8u, HashLen16(x + w[1], y + v[1]));
}

/*
static void CityHash128(unsigned char hash[16], const void *ptr, size_t len)
{
	unsigned char seed[16];
	if (len < 16) {
		write_uint64_le(seed, k0);
		write_uint64_le(seed + 8u, k1);
		CityHash128WithSeed(hash, ptr, len, seed);
		return;
	}
	const unsigned char *s = ptr;
	write_uint64_le(seed, read_uint64_le(s));
	write_uint64_le(seed + 8u, read_uint64_le(s + 8) + k0);
	CityHash128WithSeed(hash, s + 16, len - 16, seed);
}
*/

uint_fast64_t cityhash64_64(
	const void *restrict ptr, const size_t len, const uint_fast64_t seed)
{
	return CityHash64WithSeed(ptr, len, seed);
}

uint_fast32_t cityhash64low_32(
	const void *restrict ptr, const size_t len, const uint_fast32_t seed)
{
	/* Explicit truncation to 32 bits; name implies low-32 output. */
	return CityHash64WithSeed(ptr, len, seed) & UINT32_C(0xffffffff);
}

void cityhash128_128(
	unsigned char hash[restrict 16], const void *restrict ptr,
	const size_t len, const unsigned char seed[restrict 16])
{
	CityHash128WithSeed(hash, ptr, len, seed);
}
