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

/* If C23 is available, prefer stdc */
#if defined(__has_include) && __has_include(<stdbit.h>)
#include <stdbit.h>
#endif
#if defined(__STDC_VERSION_STDBIT_H__) && __STDC_VERSION_STDBIT_H__ >= 202311L
/* stdbit.h already included above */

static inline int log2u(unsigned int x)
{
	assert(x > 0);
	return stdc_bit_width(x) - 1;
}

static inline int log2ul(unsigned long x)
{
	assert(x > 0);
	return stdc_bit_width(x) - 1;
}

static inline int log2ull(unsigned long long x)
{
	assert(x > 0);
	return stdc_bit_width(x) - 1;
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

/* Layer 1: De Bruijn baseline — always available, no guards */

/** @brief De Bruijn lookup table for 32-bit BSR (bit scan reverse). */
extern const int intlog2_debruijn_bsr32[32];

/** @brief De Bruijn lookup table for 32-bit BSF (bit scan forward). */
extern const int intlog2_debruijn_bsf32[32];

/** @brief Calculate base-2 logarithm for uint_fast32_t using De Bruijn sequence. */
static inline int log2u32(uint_fast32_t x)
{
	assert(x > 0);
	x |= x >> 1u;
	x |= x >> 2u;
	x |= x >> 4u;
	x |= x >> 8u;
	x |= x >> 16u;
	/* De Bruijn constant for 32-bit BSR; pairs with intlog2_debruijn_bsr32[].
	 * Mask to 32 bits where uint_fast32_t is wider than 32 bits. */
	return intlog2_debruijn_bsr32
		[((x * (uint_fast32_t)0x07C4ACDDUL) & UINT32_C(0xFFFFFFFF)) >>
		 27u];
}

/** @brief Count trailing zeros for uint_fast32_t using De Bruijn sequence. */
static inline int countr_zerou32(uint_fast32_t x)
{
	assert(x > 0);
	/* De Bruijn constant for 32-bit BSF; pairs with intlog2_debruijn_bsf32[].
	 * Mask to 32 bits where uint_fast32_t is wider than 32 bits. */
	return intlog2_debruijn_bsf32
		[(((x & -x) * (uint_fast32_t)0x077CB531UL) &
		  UINT32_C(0xFFFFFFFF)) >>
		 27u];
}

/** @brief Count leading zeros for a 32-bit value (x=0 returns 32). */
static inline int countl_zerou32(uint_fast32_t x)
{
	return x == 0 ? 32 : 31 - log2u32(x);
}

/** @brief De Bruijn lookup table for 64-bit BSR (bit scan reverse). */
extern const int intlog2_debruijn_bsr64[64];

/** @brief Calculate base-2 logarithm for uint_fast64_t using De Bruijn sequence. */
static inline int log2u64(uint_fast64_t x)
{
	assert(x > 0);
	x |= x >> 1u;
	x |= x >> 2u;
	x |= x >> 4u;
	x |= x >> 8u;
	x |= x >> 16u;
	x |= x >> 32u;
	/* De Bruijn constant for 64-bit BSR; pairs with intlog2_debruijn_bsr64[] */
	return intlog2_debruijn_bsr64
		[((x * (uint_fast64_t)0x03F79D71B4CB0A89ULL) &
		  UINT64_C(0xFFFFFFFFFFFFFFFF)) >>
		 58u];
}

/** @brief De Bruijn lookup table for 64-bit BSF (bit scan forward). */
extern const int intlog2_debruijn_bsf64[64];

/** @brief Count trailing zeros for uint_fast64_t using De Bruijn sequence. */
static inline int countr_zerou64(uint_fast64_t x)
{
	assert(x > 0);
	/* De Bruijn constant for 64-bit BSF; pairs with intlog2_debruijn_bsf64[] */
	return intlog2_debruijn_bsf64
		[(((x & -x) * (uint_fast64_t)0x0257EDD4D0F22CE3ULL) &
		  UINT64_C(0xFFFFFFFFFFFFFFFF)) >>
		 58u];
}

/** @brief Count leading zeros for a 64-bit value (x=0 returns 64). */
static inline int countl_zerou64(uint_fast64_t x)
{
	return x == 0 ? 64 : 63 - log2u64(x);
}

/* Layer 2: Per-type functions — stdc -> __builtin -> De Bruijn */

static inline int log2u(unsigned int x)
{
	assert(x > 0);
#if defined(__has_builtin) && __has_builtin(__builtin_clz)
	return (int)(sizeof(x) << 3u) - 1 - __builtin_clz(x);
#else
#if UINT_MAX == 0xFFFFFFFF
	return log2u32((uint_fast32_t)x);
#else
	return log2u64((uint_fast64_t)x);
#endif
#endif /* __has_builtin */
}

static inline int log2ul(unsigned long x)
{
	assert(x > 0);
#if defined(__has_builtin) && __has_builtin(__builtin_clzl)
	return (int)(sizeof(x) << 3u) - 1 - __builtin_clzl(x);
#else
#if ULONG_MAX == 0xFFFFFFFF
	return log2u32((uint_fast32_t)x);
#else
	return log2u64((uint_fast64_t)x);
#endif
#endif /* __has_builtin */
}

static inline int log2ull(unsigned long long x)
{
	assert(x > 0);
#if defined(__has_builtin) && __has_builtin(__builtin_clzll)
	return (int)(sizeof(x) << 3u) - 1 - __builtin_clzll(x);
#else
	/* unsigned long long must fit in uint_fast64_t for the fallback cast to be lossless. */
	static_assert(
		ULLONG_MAX <= UINT_FAST64_MAX,
		"unsigned long long exceeds uint_fast64_t range: fallback cast would truncate");
	return log2u64((uint_fast64_t)x);
#endif /* __has_builtin */
}

static inline int countr_zerou(unsigned int x)
{
	assert(x > 0);
#if defined(__has_builtin) && __has_builtin(__builtin_ctz)
	return __builtin_ctz(x);
#else
#if UINT_MAX == 0xFFFFFFFF
	return countr_zerou32((uint_fast32_t)x);
#else
	return countr_zerou64((uint_fast64_t)x);
#endif
#endif /* __has_builtin */
}

static inline int countr_zeroul(unsigned long x)
{
	assert(x > 0);
#if defined(__has_builtin) && __has_builtin(__builtin_ctzl)
	return __builtin_ctzl(x);
#else
#if ULONG_MAX == 0xFFFFFFFF
	return countr_zerou32((uint_fast32_t)x);
#else
	return countr_zerou64((uint_fast64_t)x);
#endif
#endif /* __has_builtin */
}

static inline int countr_zeroull(unsigned long long x)
{
	assert(x > 0);
#if defined(__has_builtin) && __has_builtin(__builtin_ctzll)
	return __builtin_ctzll(x);
#else
	/* unsigned long long must fit in uint_fast64_t for the fallback cast to be lossless. */
	static_assert(
		ULLONG_MAX <= UINT_FAST64_MAX,
		"unsigned long long exceeds uint_fast64_t range: fallback cast would truncate");
	return countr_zerou64((uint_fast64_t)x);
#endif /* __has_builtin */
}

/* countl_zero: x=0 is valid and returns the full bit-width. */
static inline int countl_zerou(unsigned int x)
{
#if defined(__has_builtin) && __has_builtin(__builtin_clz)
	return x == 0 ? (int)(sizeof(x) << 3u) : __builtin_clz(x);
#else
#if UINT_MAX == 0xFFFFFFFF
	return countl_zerou32((uint_fast32_t)x);
#else
	return countl_zerou64((uint_fast64_t)x);
#endif
#endif /* __has_builtin */
}

static inline int countl_zeroul(unsigned long x)
{
#if defined(__has_builtin) && __has_builtin(__builtin_clzl)
	return x == 0 ? (int)(sizeof(x) << 3u) : __builtin_clzl(x);
#else
#if ULONG_MAX == 0xFFFFFFFF
	return countl_zerou32((uint_fast32_t)x);
#else
	return countl_zerou64((uint_fast64_t)x);
#endif
#endif /* __has_builtin */
}

static inline int countl_zeroull(unsigned long long x)
{
#if defined(__has_builtin) && __has_builtin(__builtin_clzll)
	return x == 0 ? (int)(sizeof(x) << 3u) : __builtin_clzll(x);
#else
	/* unsigned long long must fit in uint_fast64_t for the fallback cast to be lossless. */
	static_assert(
		ULLONG_MAX <= UINT_FAST64_MAX,
		"unsigned long long exceeds uint_fast64_t range: fallback cast would truncate");
	return countl_zerou64((uint_fast64_t)x);
#endif /* __has_builtin */
}

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
/* Wide path: defined in intlog2.c using thread-local De Bruijn tables. */
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

/* size_t must alias unsigned int, long, or long long for the
 * _Generic dispatch in intlog2() and countr_zero() to cover it. */
static_assert(
	sizeof(size_t) <= sizeof(unsigned long long),
	"size_t wider than unsigned long long: intlog2/countr_zero dispatch incomplete");

/** @} */

#endif /* MATH_INTLOG2_H */
