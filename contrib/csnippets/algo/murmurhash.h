/*-----------------------------------------------------------------------------
 * MurmurHash3 was written by Austin Appleby, and is placed in the public
 * domain. The author hereby disclaims copyright to this source code.
 */

/* csnippets: The following implements are modified to be portable. */

#ifndef MURMURHASH_H
#define MURMURHASH_H

#include <stddef.h>
#include <stdint.h>

uint32_t murmurhash2_32(const void *ptr, size_t len, uint32_t seed);

uint64_t murmurhash2_64(const void *ptr, size_t len, uint64_t seed);

uint32_t murmurhash3_32(const void *ptr, size_t len, uint32_t seed);

void murmurhash3_128(
	const void *ptr, size_t len, const unsigned char seed[16],
	unsigned char out[16]);

#endif /* MURMURHASH_H */
