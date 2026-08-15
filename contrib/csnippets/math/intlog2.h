/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef MATH_INTLOG2_H
#define MATH_INTLOG2_H

/**
 * @defgroup intlog2
 * @brief Integer logarithm base-2 and bit counting operations.
 * @details Provides optimized implementations using compiler builtins or
 * De Bruijn sequences. Prefers C23 stdbit.h when available.
 * @{
 */

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

/* Each __has_include/__has_builtin test is split into an outer defined() and an
 * inner call: a compiler without the operator (MSVC; GCC before 10 lacks
 * __has_builtin, before 5 __has_include) replaces the unknown identifier with 0
 * and cannot parse the call syntax that follows it, even behind a false
 * `defined(...) &&` in the same #if. */

/* If C23 is available, prefer stdc */
#if defined(__has_include)
#if __has_include(<stdbit.h>)
#include <stdbit.h>
#endif
#endif /* __has_include */

/* Layer 1: De Bruijn baseline — always available, no guards */

/** @brief De Bruijn lookup table for 32-bit BSR (bit scan reverse). */
extern const int intlog2_debruijn_bsr32[32];

/** @brief De Bruijn lookup table for 32-bit BSF (bit scan forward). */
extern const int intlog2_debruijn_bsf32[32];

/** @brief Base-2 logarithm for uint32_t via De Bruijn sequence. */
static inline int log2u32(uint32_t x)
{
	assert(x > 0);
	x |= x >> 1u;
	x |= x >> 2u;
	x |= x >> 4u;
	x |= x >> 8u;
	x |= x >> 16u;
	/* De Bruijn constant for 32-bit BSR; pairs with
	 * intlog2_debruijn_bsr32[]. */
	return intlog2_debruijn_bsr32
		[((x * UINT32_C(0x07C4ACDD)) & UINT32_C(0xFFFFFFFF)) >> 27u];
}

/** @brief Count trailing zeros for uint32_t using De Bruijn sequence. */
static inline int countr_zerou32(uint32_t x)
{
	assert(x > 0);
	/* De Bruijn constant for 32-bit BSF; pairs with
	 * intlog2_debruijn_bsf32[]. */
	return intlog2_debruijn_bsf32
		[(((x & -x) * UINT32_C(0x077CB531)) & UINT32_C(0xFFFFFFFF)) >>
		 27u];
}

/** @brief Count leading zeros for a 32-bit value (x=0 returns 32). */
static inline int countl_zerou32(uint32_t x)
{
	return x == 0 ? 32 : 31 - log2u32(x);
}

/** @brief De Bruijn lookup table for 64-bit BSR (bit scan reverse). */
extern const int intlog2_debruijn_bsr64[64];

/** @brief Base-2 logarithm for uint64_t via De Bruijn sequence. */
static inline int log2u64(uint64_t x)
{
	assert(x > 0);
	x |= x >> 1u;
	x |= x >> 2u;
	x |= x >> 4u;
	x |= x >> 8u;
	x |= x >> 16u;
	x |= x >> 32u;
	/* De Bruijn constant for 64-bit BSR; pairs with
	 * intlog2_debruijn_bsr64[] */
	return intlog2_debruijn_bsr64
		[((x * UINT64_C(0x03F79D71B4CB0A89)) &
		  UINT64_C(0xFFFFFFFFFFFFFFFF)) >>
		 58u];
}

/** @brief De Bruijn lookup table for 64-bit BSF (bit scan forward). */
extern const int intlog2_debruijn_bsf64[64];

/** @brief Count trailing zeros for uint64_t using De Bruijn sequence. */
static inline int countr_zerou64(uint64_t x)
{
	assert(x > 0);
	/* De Bruijn constant for 64-bit BSF; pairs with
	 * intlog2_debruijn_bsf64[] */
	return intlog2_debruijn_bsf64
		[(((x & -x) * UINT64_C(0x0257EDD4D0F22CE3)) &
		  UINT64_C(0xFFFFFFFFFFFFFFFF)) >>
		 58u];
}

/** @brief Count leading zeros for a 64-bit value (x=0 returns 64). */
static inline int countl_zerou64(uint64_t x)
{
	return x == 0 ? 64 : 63 - log2u64(x);
}

/* Layer 2: Per-type functions — stdc -> __builtin -> De Bruijn */

#if defined(__STDC_VERSION_STDBIT_H__) && __STDC_VERSION_STDBIT_H__ >= 202311L
/* stdbit.h already included above */

static inline int log2u(unsigned int x)
{
	assert(x > 0);
	return (int)stdc_bit_width(x) - 1;
}

static inline int log2ul(unsigned long x)
{
	assert(x > 0);
	return (int)stdc_bit_width(x) - 1;
}

static inline int log2ull(unsigned long long x)
{
	assert(x > 0);
	return (int)stdc_bit_width(x) - 1;
}

static inline int countr_zerou(unsigned int x)
{
	assert(x > 0);
	return (int)stdc_trailing_zeros(x);
}

static inline int countr_zeroul(unsigned long x)
{
	assert(x > 0);
	return (int)stdc_trailing_zeros(x);
}

static inline int countr_zeroull(unsigned long long x)
{
	assert(x > 0);
	return (int)stdc_trailing_zeros(x);
}

static inline int countl_zerou(unsigned int x)
{
	return (int)stdc_leading_zeros(x);
}

static inline int countl_zeroul(unsigned long x)
{
	return (int)stdc_leading_zeros(x);
}

static inline int countl_zeroull(unsigned long long x)
{
	return (int)stdc_leading_zeros(x);
}

#else
/* For C17 or earlier */

#if defined(__has_builtin)
#if __has_builtin(__builtin_clz)
#define INTLOG2_BUILTIN_CLZ
#endif
#if __has_builtin(__builtin_clzl)
#define INTLOG2_BUILTIN_CLZL
#endif
#if __has_builtin(__builtin_clzll)
#define INTLOG2_BUILTIN_CLZLL
#endif
#if __has_builtin(__builtin_ctz)
#define INTLOG2_BUILTIN_CTZ
#endif
#if __has_builtin(__builtin_ctzl)
#define INTLOG2_BUILTIN_CTZL
#endif
#if __has_builtin(__builtin_ctzll)
#define INTLOG2_BUILTIN_CTZLL
#endif
#endif /* __has_builtin */

static inline int log2u(unsigned int x)
{
	assert(x > 0);
#if defined(INTLOG2_BUILTIN_CLZ)
	return (int)(sizeof(x) * CHAR_BIT) - 1 - __builtin_clz(x);
#else
#if UINT_MAX == 0xFFFFFFFF
	return log2u32((uint32_t)x);
#else
	return log2u64((uint64_t)x);
#endif
#endif /* INTLOG2_BUILTIN_CLZ */
}

static inline int log2ul(unsigned long x)
{
	assert(x > 0);
#if defined(INTLOG2_BUILTIN_CLZL)
	return (int)(sizeof(x) * CHAR_BIT) - 1 - __builtin_clzl(x);
#else
#if ULONG_MAX == 0xFFFFFFFF
	return log2u32((uint32_t)x);
#else
	return log2u64((uint64_t)x);
#endif
#endif /* INTLOG2_BUILTIN_CLZL */
}

static inline int log2ull(unsigned long long x)
{
	assert(x > 0);
#if defined(INTLOG2_BUILTIN_CLZLL)
	return (int)(sizeof(x) * CHAR_BIT) - 1 - __builtin_clzll(x);
#else
	/* unsigned long long must fit in uint64_t for the
	 * fallback cast to be lossless. */
	static_assert(
		ULLONG_MAX <= UINT64_MAX,
		"unsigned long long exceeds uint64_t range: fallback cast would truncate");
	return log2u64((uint64_t)x);
#endif /* INTLOG2_BUILTIN_CLZLL */
}

static inline int countr_zerou(unsigned int x)
{
	assert(x > 0);
#if defined(INTLOG2_BUILTIN_CTZ)
	return __builtin_ctz(x);
#else
#if UINT_MAX == 0xFFFFFFFF
	return countr_zerou32((uint32_t)x);
#else
	return countr_zerou64((uint64_t)x);
#endif
#endif /* INTLOG2_BUILTIN_CTZ */
}

static inline int countr_zeroul(unsigned long x)
{
	assert(x > 0);
#if defined(INTLOG2_BUILTIN_CTZL)
	return __builtin_ctzl(x);
#else
#if ULONG_MAX == 0xFFFFFFFF
	return countr_zerou32((uint32_t)x);
#else
	return countr_zerou64((uint64_t)x);
#endif
#endif /* INTLOG2_BUILTIN_CTZL */
}

static inline int countr_zeroull(unsigned long long x)
{
	assert(x > 0);
#if defined(INTLOG2_BUILTIN_CTZLL)
	return __builtin_ctzll(x);
#else
	/* unsigned long long must fit in uint64_t for the
	 * fallback cast to be lossless. */
	static_assert(
		ULLONG_MAX <= UINT64_MAX,
		"unsigned long long exceeds uint64_t range: fallback cast would truncate");
	return countr_zerou64((uint64_t)x);
#endif /* INTLOG2_BUILTIN_CTZLL */
}

/* countl_zero: x=0 is valid and returns the full bit-width. */
static inline int countl_zerou(unsigned int x)
{
#if defined(INTLOG2_BUILTIN_CLZ)
	return x == 0 ? (int)(sizeof(x) * CHAR_BIT) : __builtin_clz(x);
#else
#if UINT_MAX == 0xFFFFFFFF
	return countl_zerou32((uint32_t)x);
#else
	return countl_zerou64((uint64_t)x);
#endif
#endif /* INTLOG2_BUILTIN_CLZ */
}

static inline int countl_zeroul(unsigned long x)
{
#if defined(INTLOG2_BUILTIN_CLZL)
	return x == 0 ? (int)(sizeof(x) * CHAR_BIT) : __builtin_clzl(x);
#else
#if ULONG_MAX == 0xFFFFFFFF
	return countl_zerou32((uint32_t)x);
#else
	return countl_zerou64((uint64_t)x);
#endif
#endif /* INTLOG2_BUILTIN_CLZL */
}

static inline int countl_zeroull(unsigned long long x)
{
#if defined(INTLOG2_BUILTIN_CLZLL)
	return x == 0 ? (int)(sizeof(x) * CHAR_BIT) : __builtin_clzll(x);
#else
	/* unsigned long long must fit in uint64_t for the
	 * fallback cast to be lossless. */
	static_assert(
		ULLONG_MAX <= UINT64_MAX,
		"unsigned long long exceeds uint64_t range: fallback cast would truncate");
	return countl_zerou64((uint64_t)x);
#endif /* INTLOG2_BUILTIN_CLZLL */
}

#undef INTLOG2_BUILTIN_CLZ
#undef INTLOG2_BUILTIN_CLZL
#undef INTLOG2_BUILTIN_CLZLL
#undef INTLOG2_BUILTIN_CTZ
#undef INTLOG2_BUILTIN_CTZL
#undef INTLOG2_BUILTIN_CTZLL

#endif /* __STDC_VERSION_STDBIT_H__ >= 202311L */

/* Layer 3: uintmax_t support */

#if UINTMAX_MAX <= ULLONG_MAX
/* Fast path: uintmax_t is no wider than unsigned long long on this platform. */
static inline int log2umax(uintmax_t x)
{
	return log2ull((unsigned long long)x);
}

static inline int countr_zeromax(uintmax_t x)
{
	return countr_zeroull((unsigned long long)x);
}

static inline int countl_zeromax(uintmax_t x)
{
	return countl_zeroull((unsigned long long)x);
}
#else
/* Wide path: declared here and dispatched to by the macros below, but defined
 * nowhere. Their implementation in intlog2.c is an untested reference kept
 * under #if 0, so a uintmax_t argument to intlog2(), countr_zero() or
 * countl_zero() on such a platform fails to link until that block is
 * re-enabled. */
int log2umax(uintmax_t x);
int countr_zeromax(uintmax_t x);
int countl_zeromax(uintmax_t x);
#endif /* UINTMAX_MAX <= ULLONG_MAX */

/* size_t must alias unsigned int, long, or long long for the
 * _Generic dispatch in intlog2() and countr_zero() to cover it. */
static_assert(
	sizeof(size_t) <= sizeof(unsigned long long),
	"size_t wider than unsigned long long: intlog2/countr_zero dispatch incomplete");

/* Layer 4: Public _Generic macros */

/**
 * @brief Returns the floored base-2 logarithm of x.
 * @param x if 0, the behavior is undefined
 */
#if UINTMAX_MAX > ULLONG_MAX
#define intlog2(x)                                                             \
	_Generic(                                                              \
		(x),                                                           \
		unsigned int: log2u,                                           \
		unsigned long: log2ul,                                         \
		unsigned long long: log2ull,                                   \
		uintmax_t: log2umax)(x)
#else
#define intlog2(x)                                                             \
	_Generic(                                                              \
		(x),                                                           \
		unsigned int: log2u,                                           \
		unsigned long: log2ul,                                         \
		unsigned long long: log2ull)(x)
#endif /* UINTMAX_MAX > ULLONG_MAX */

/**
 * @brief Returns the number of consecutive 0 bits starting from the least
 * significant bit. If x is 0, the behavior is undefined.
 */
#if UINTMAX_MAX > ULLONG_MAX
#define countr_zero(x)                                                         \
	_Generic(                                                              \
		(x),                                                           \
		unsigned int: countr_zerou,                                    \
		unsigned long: countr_zeroul,                                  \
		unsigned long long: countr_zeroull,                            \
		uintmax_t: countr_zeromax)(x)
#else
#define countr_zero(x)                                                         \
	_Generic(                                                              \
		(x),                                                           \
		unsigned int: countr_zerou,                                    \
		unsigned long: countr_zeroul,                                  \
		unsigned long long: countr_zeroull)(x)
#endif /* UINTMAX_MAX > ULLONG_MAX */

/**
 * @brief Returns the number of consecutive 0 bits starting from the most
 * significant bit. If x is 0, returns the bit-width of the type.
 */
#if UINTMAX_MAX > ULLONG_MAX
#define countl_zero(x)                                                         \
	_Generic(                                                              \
		(x),                                                           \
		unsigned int: countl_zerou,                                    \
		unsigned long: countl_zeroul,                                  \
		unsigned long long: countl_zeroull,                            \
		uintmax_t: countl_zeromax)(x)
#else
#define countl_zero(x)                                                         \
	_Generic(                                                              \
		(x),                                                           \
		unsigned int: countl_zerou,                                    \
		unsigned long: countl_zeroul,                                  \
		unsigned long long: countl_zeroull)(x)
#endif /* UINTMAX_MAX > ULLONG_MAX */

/** @} */

#endif /* MATH_INTLOG2_H */
