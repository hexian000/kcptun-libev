/* fnv - Fowler/Noll/Vo- hash code; Author: chongo (Landon Curt Noll) /\oo/\
 * This is free and unencumbered software released into the public domain. */

/* csnippets: The following implementations are modified to conform to the ISO C standard. */

#include "fnv1a.h"

#include <stdint.h>

#define FNV_32_PRIME UINT32_C(0x01000193)

/* fnv1a_32 - perform a 32 bit Fowler/Noll/Vo FNV-1a hash on a buffer */
uint_fast32_t
fnv1a_32(const void *restrict ptr, const size_t len, const uint_fast32_t seed)
{
	/* start of buffer */
	const unsigned char *bp = ptr;
	/* beyond end of buffer */
	const unsigned char *be = bp + len;
	uint_fast32_t h = seed;

	/* FNV-1a hash each octet in the buffer */
	while (bp < be) {
		/* xor the bottom with the current octet */
		h ^= (uint_fast32_t)*bp++;

		/* multiply by the 32 bit FNV magic prime mod 2^32 */
#if defined(NO_FNV_GCC_OPTIMIZATION)
		h *= FNV_32_PRIME;
#else
		h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
#endif
	}

	/* return our new hash value; explicit truncation keeps the result a
	 * true 32-bit FNV-1a value even where uint_fast32_t is wider.
	 * UINT32_C is mandated by C11 even where the optional uint32_t
	 * (and hence UINT32_MAX) is absent. */
	return h & UINT32_C(0xffffffff);
}

#define FNV_64_PRIME UINT64_C(0x100000001b3)

/* fnv1a_64 - perform a 64 bit Fowler/Noll/Vo FNV-1a hash on a buffer */
uint_fast64_t
fnv1a_64(const void *restrict ptr, const size_t len, const uint_fast64_t seed)
{
	/* start of buffer */
	const unsigned char *bp = ptr;
	/* beyond end of buffer */
	const unsigned char *be = bp + len;
	uint_fast64_t h = seed;

	/* FNV-1a hash each octet of the buffer */
	while (bp < be) {
		/* xor the bottom with the current octet */
		h ^= (uint_fast64_t)*bp++;

		/* multiply by the 64 bit FNV magic prime mod 2^64 */
#if defined(NO_FNV_GCC_OPTIMIZATION)
		h *= FNV_64_PRIME;
#else /* NO_FNV_GCC_OPTIMIZATION */
		h += (h << 1) + (h << 4) + (h << 5) + (h << 7) + (h << 8) +
		     (h << 40);
#endif /* NO_FNV_GCC_OPTIMIZATION */
	}

	/* return our new hash value; explicit truncation keeps the result a
	 * true 64-bit FNV-1a value even where uint_fast64_t is wider */
	return h & UINT64_C(0xffffffffffffffff);
}
