/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_INTCAST_H
#define UTILS_INTCAST_H

#include <stdint.h>

/**
 * @defgroup intcast
 * @brief Safely cast stdint types to unknown int types.
 * @details The compiler implementation must support all types from int8_t to uint64_t.
 * @{
 */

#define INTCAST_CHECK(dst, src)                                                \
	(_Generic(                                                             \
		(dst),                                                         \
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

#define UINTCAST_CHECK(dst, src)                                               \
	(_Generic(                                                             \
		(dst),                                                         \
		uint8_t: ((src) <= UINT8_MAX),                                 \
		uint16_t: ((src) <= UINT16_MAX),                               \
		uint32_t: ((src) <= UINT32_MAX),                               \
		uint64_t: ((src) <= UINT64_MAX),                               \
		int8_t: (                                                      \
			sizeof(uintmax_t) <= sizeof(int8_t) ||                 \
			(src) <= (uintmax_t)INT8_MAX),                         \
		int16_t: (                                                     \
			sizeof(uintmax_t) <= sizeof(int16_t) ||                \
			(src) <= (uintmax_t)INT16_MAX),                        \
		int32_t: (                                                     \
			sizeof(uintmax_t) <= sizeof(int32_t) ||                \
			(src) <= (uintmax_t)INT32_MAX),                        \
		int64_t: (                                                     \
			sizeof(uintmax_t) <= sizeof(int64_t) ||                \
			(src) <= (uintmax_t)INT64_MAX)))

/** @} */

#endif /* UTILS_INTCAST_H */
