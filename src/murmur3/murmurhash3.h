//-----------------------------------------------------------------------------
// MurmurHash3 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.

#ifndef MURMURHASH3_H
#define MURMURHASH3_H

#include <stddef.h>
#include <stdint.h>

// original: MurmurHash3_x86_32
uint32_t murmurhash3(const void *key, size_t len, uint32_t seed);

#endif /* MURMURHASH3_H */
