/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef BINARY_BSWAP_H
#define BINARY_BSWAP_H

#include <stdint.h>

/* a and b must be distinct lvalues; aliasing zeroes both (XOR swap). */
#ifndef INTSWAP
#define INTSWAP(a, b)                                                          \
	do {                                                                   \
		(a) ^= (b), (b) ^= (a), (a) ^= (b);                            \
	} while (0)
#endif

/* Fallbacks use C11 uint_fast* types (may be wider than nominal), masked
 * with UINTN_C constants to stay conforming without exact-width types or
 * type punning. */

#ifdef __has_builtin
#if __has_builtin(__builtin_bswap64)
#define BSWAP64 __builtin_bswap64
#endif
#endif /* __has_builtin */
#ifndef BSWAP64
static inline uint_fast64_t bswap64(uint_fast64_t x)
{
	x &= UINT64_C(0xffffffffffffffff);
	return ((x << 56u) | ((x & UINT64_C(0xff00)) << 40u) |
		((x & UINT64_C(0xff0000)) << 24u) |
		((x & UINT64_C(0xff000000)) << 8u) |
		((x >> 8u) & UINT64_C(0xff000000)) |
		((x >> 24u) & UINT64_C(0xff0000)) |
		((x >> 40u) & UINT64_C(0xff00)) | (x >> 56u)) &
	       UINT64_C(0xffffffffffffffff);
}

#define BSWAP64 bswap64
#endif /* BSWAP64 */
#ifdef __has_builtin
#if __has_builtin(__builtin_bswap32)
#define BSWAP32 __builtin_bswap32
#endif
#endif /* __has_builtin */
#ifndef BSWAP32
static inline uint_fast32_t bswap32(uint_fast32_t x)
{
	x &= UINT32_C(0xffffffff);
	return ((x << 24u) | ((x & UINT32_C(0xff00)) << 8u) |
		((x >> 8u) & UINT32_C(0xff00)) | (x >> 24u)) &
	       UINT32_C(0xffffffff);
}

#define BSWAP32 bswap32
#endif /* BSWAP32 */
#ifdef __has_builtin
#if __has_builtin(__builtin_bswap16)
#define BSWAP16 __builtin_bswap16
#endif
#endif /* __has_builtin */
#ifndef BSWAP16
static inline uint_fast16_t bswap16(const uint_fast16_t x)
{
	return (uint_fast16_t)(((x << 8u) | ((x >> 8u) & UINT16_C(0xff))) &
			       UINT16_C(0xffff));
}

#define BSWAP16 bswap16
#endif

#endif /* BINARY_BSWAP_H */
