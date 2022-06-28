//-----------------------------------------------------------------------------
// MurmurHash3 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.

#ifndef _MURMURHASH3_H_
#define _MURMURHASH3_H_

#include <stdint.h>

// original: MurmurHash3_x86_32
uint32_t murmurhash3(const void *key, int len, uint32_t seed);

#endif // _MURMURHASH3_H_
