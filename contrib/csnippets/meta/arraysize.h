/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef META_ARRAYSIZE_H
#define META_ARRAYSIZE_H

#ifndef ARRAY_SIZE
/* META_FORCE_FALLBACK selects the portable non-GNU definition even under GCC/
 * Clang, so a test can compile and exercise that otherwise-unreachable path. */
#if defined(__GNUC__) && !defined(META_FORCE_FALLBACK)
/* Reject a pointer argument at compile time, mirroring the type safety the rest
 * of meta/ invests in. For a real array, x and &(x)[0] have different types
 * (array vs pointer-to-element), so __builtin_types_compatible_p is 0, the
 * bit-field width is 1 (a valid named field whose sizeof is discarded by the
 * `* 0`), and the result is the plain element count. For a pointer the two
 * types match, the width becomes -1, and a negative-width bit-field is
 * ill-formed -- turning the classic ARRAY_SIZE-of-a-decayed-array overrun into
 * a compile error. The whole expression stays an integer constant expression,
 * so ARRAY_SIZE remains usable in static_assert and array dimensions. */
#define ARRAY_SIZE(x)                                                          \
	((sizeof(x) / sizeof((x)[0])) +                                        \
	 sizeof(struct {                                                       \
		 int meta_must_be_array_ : 1 -                                 \
			 2 * !!__builtin_types_compatible_p(                   \
				     __typeof__(x), __typeof__(&(x)[0]));      \
	 }) * 0)
#else /* !defined(__GNUC__) || defined(META_FORCE_FALLBACK) */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif /* defined(__GNUC__) && !defined(META_FORCE_FALLBACK) */
#endif /* ARRAY_SIZE */

#endif /* META_ARRAYSIZE_H */
