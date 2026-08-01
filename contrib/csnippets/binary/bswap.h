/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef BINARY_BSWAP_H
#define BINARY_BSWAP_H

#include <stdint.h>

/* Swap two integer lvalues. a and b must be side-effect-free (each is
 * evaluated more than once); unlike the former XOR swap, self-aliasing is safe
 * (INTSWAP(x, x) is a no-op) instead of zeroing both.
 *
 * Contract: the operands must be unsigned, or signed holding a non-negative
 * value. Which of the two definitions below compiles depends on the toolchain,
 * and the portable one routes the value through uintmax_t, where a negative
 * signed value converts to a large unsigned one and back in an
 * implementation-defined way (C11 6.3.1.3p3). Restricting the contract is what
 * makes the two definitions interchangeable. */
#ifndef INTSWAP
#if defined(__GNUC__) && !defined(BINARY_INTSWAP_NO_TYPEOF)
#define INTSWAP(a, b)                                                          \
	do {                                                                   \
		__typeof__(a) intswap_tmp_ = (a);                              \
		(a) = (b);                                                     \
		(b) = intswap_tmp_;                                            \
	} while (0)
#else /* !defined(__GNUC__) || defined(BINARY_INTSWAP_NO_TYPEOF) */
/* Portable fallback without __typeof__: the round-trip through uintmax_t is
 * value-preserving for the operands the contract above admits -- unsigned, or
 * non-negative signed -- which is exactly why the contract is stated. The
 * assignment back to (b) narrows implicitly rather than through an explicit
 * cast: without __typeof__ there is no way to name the operand's type, and the
 * same reason rules out a typed temporary. On a __GNUC__ toolchain the
 * __typeof__ path above shadows this, so a test build defines
 * BINARY_INTSWAP_NO_TYPEOF to force this path to compile and be exercised,
 * mirroring BINARY_BSWAP_NO_BUILTIN below; production never defines it, so
 * shipped code is unchanged. */
#define INTSWAP(a, b)                                                          \
	do {                                                                   \
		uintmax_t intswap_tmp_ = (uintmax_t)(a);                       \
		(a) = (b);                                                     \
		(b) = intswap_tmp_;                                            \
	} while (0)
#endif /* defined(__GNUC__) && !defined(BINARY_INTSWAP_NO_TYPEOF) */
#endif /* INTSWAP */

/* Fallbacks use C11 uint_fast* types (may be wider than nominal), masked
 * with UINTN_C constants to stay conforming without exact-width types or
 * type punning. */

/* On a toolchain that provides __builtin_bswapN the scalar fallbacks below are
 * shadowed by the builtin and never compiled, so nothing exercises them. A test
 * build defines BINARY_BSWAP_NO_BUILTIN to suppress the builtin path and force
 * the fallbacks to compile, so they can be differential-tested against the
 * builtin; production never defines it, so shipped code is unchanged. */

#if defined(__has_builtin) && !defined(BINARY_BSWAP_NO_BUILTIN)
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
#if defined(__has_builtin) && !defined(BINARY_BSWAP_NO_BUILTIN)
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
#if defined(__has_builtin) && !defined(BINARY_BSWAP_NO_BUILTIN)
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
