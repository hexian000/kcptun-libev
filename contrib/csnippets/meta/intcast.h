/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef META_INTCAST_H
#define META_INTCAST_H

#include <stdint.h>

/**
 * @defgroup intcast
 * @brief Safely cast stdint types to unknown int types.
 * @details The compiler implementation must support all types from int8_t to uint64_t.
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
