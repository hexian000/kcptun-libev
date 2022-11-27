/* csnippets (c) 2019-2022 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef XORSHIFT_H
#define XORSHIFT_H

#include <stdint.h>

static inline uint32_t xorshift32(uint32_t x)
{
	x ^= x << 13u;
	x ^= x >> 17u;
	x ^= x << 5u;
	return x;
}

static inline uint64_t xorshift64(uint64_t x)
{
	x ^= x << 13u;
	x ^= x >> 7u;
	x ^= x << 17u;
	return x;
}

uint32_t rand32(void);
uint64_t rand64(void);

#endif /* XORSHIFT_H */
