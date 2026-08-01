/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef META_INTCAST_H
#define META_INTCAST_H

#include <stdint.h>

/**
 * @defgroup intcast
 * @brief Range-check a cast to an integer type named only by a value.
 * @details The point of these macros is that the destination need not be
 * spelled out: a caller with an opaque platform typedef (`uid_t`, `off_t`, ...)
 * passes a value of it and gets the right bounds without having to know which
 * type that is.
 *
 * What the destination *must* be is one of the eight exact-width types
 * `int8_t`..`uint64_t`, or a typedef that resolves to one of them --
 * `uid_t` and `gid_t` do, which is why `os/daemon.c` can use them here. There
 * is deliberately no `default:` branch: for a type whose range these macros
 * cannot name, silently letting the cast through would defeat the purpose, so
 * an unsupported destination is a compile error instead.
 *
 * That leaves standard types that alias none of the eight on a given platform,
 * and the set differs per platform: plain `char` never matches (it is a
 * distinct type from both `signed char` and `unsigned char`), `long long` and
 * `unsigned long long` do not match where `int64_t` is `long` (LP64), and
 * `long` does not match where `int64_t` is `long long` (LLP64). Branches for
 * them cannot simply be added, because on the platforms where they *do* alias
 * an exact-width type the association list would contain the same type twice,
 * which is ill-formed. A caller in that position must name the destination
 * width itself, e.g. `INTCAST_CHECK((int64_t)0, src)`.
 *
 * The implementation must support all types from int8_t to uint64_t.
 * @{
 */

/**
 * @brief Check whether a signed src value fits in dst's range.
 * @param dst A value of the destination type (unevaluated, type only).
 * @param src The value to be cast, of a signed integer type.
 * @return true if the cast is safe.
 * @note The selected _Generic branch evaluates src up to twice; src
 * must be side-effect-free (matching binary/bswap.h's INTSWAP constraint).
 */
#define INTCAST_CHECK(dst, src)                                                 \
	(_Generic(                                                              \
		(dst),                                                          \
		 int8_t: ((INT8_MIN) <= (src) && (src) <= (INT8_MAX)),          \
		 int16_t: ((INT16_MIN) <= (src) && (src) <= (INT16_MAX)),       \
		 int32_t: ((INT32_MIN) <= (src) && (src) <= (INT32_MAX)),       \
		 int64_t: ((INT64_MIN) <= (src) && (src) <= (INT64_MAX)),       \
		 uint8_t: (                                                     \
			 0 <= (src) && (sizeof(intmax_t) <= sizeof(uint8_t) ||  \
					(src) <= (intmax_t)UINT8_MAX)),         \
		 uint16_t: (                                                    \
			 0 <= (src) && (sizeof(intmax_t) <= sizeof(uint16_t) || \
					(src) <= (intmax_t)UINT16_MAX)),        \
		 uint32_t: (                                                    \
			 0 <= (src) && (sizeof(intmax_t) <= sizeof(uint32_t) || \
					(src) <= (intmax_t)UINT32_MAX)),        \
		 uint64_t: (                                                    \
			 0 <= (src) && (sizeof(intmax_t) <= sizeof(uint64_t) || \
					(src) <= (intmax_t)UINT64_MAX))))

/**
 * @brief Check whether an unsigned src value fits in dst's range.
 * @param dst A value of the destination type (unevaluated, type only).
 * @param src The value to be cast, of an unsigned integer type.
 * @return true if the cast is safe.
 * @note The selected _Generic branch evaluates src once; src must be
 * side-effect-free (matching binary/bswap.h's INTSWAP constraint).
 */
#define UINTCAST_CHECK(dst, src)                                               \
	(_Generic(                                                             \
		(dst),                                                         \
		 uint8_t: ((src) <= UINT8_MAX),                                \
		 uint16_t: ((src) <= UINT16_MAX),                              \
		 uint32_t: ((src) <= UINT32_MAX),                              \
		 uint64_t: ((src) <= UINT64_MAX),                              \
		 int8_t: ((src) <= (uintmax_t)INT8_MAX),                       \
		 int16_t: ((src) <= (uintmax_t)INT16_MAX),                     \
		 int32_t: ((src) <= (uintmax_t)INT32_MAX),                     \
		 int64_t: ((src) <= (uintmax_t)INT64_MAX)))

/** @} */

#endif /* META_INTCAST_H */
