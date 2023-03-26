/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "xorshift.h"
#include <time.h>

uint32_t rand32(void)
{
	static uint32_t x = UINT32_C(0);
	if (x == UINT32_C(0)) {
		x = time(NULL);
	}
	x = xorshift32(x);
	return x;
}

uint64_t rand64(void)
{
	static uint64_t x = UINT64_C(0);
	if (x == UINT64_C(0)) {
		x = time(NULL);
	}
	x = xorshift64(x);
	return x;
}
