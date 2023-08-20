/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_SERIALIZE_H
#define UTILS_SERIALIZE_H

/**
 * @brief serialize.h is a primitive type serializer
 * These functions are carefully tuned for compilers to generate fast code.
 */

#include <stdint.h>

static inline uint8_t read_uint8(const void *p)
{
	const unsigned char *restrict b = p;
	return b[0];
}

static inline void write_uint8(void *p, uint8_t v)
{
	unsigned char *restrict b = p;
	b[0] = v;
}

static inline uint16_t read_uint16(const void *p)
{
	const unsigned char *restrict b = p;
	return (((uint_fast16_t)b[0]) << 8U) | ((uint_fast16_t)b[1]);
}

static inline uint16_t read_uint16_le(const void *p)
{
	const unsigned char *restrict b = p;
	return (((uint_fast16_t)b[0])) | ((uint_fast16_t)b[1] << 8U);
}

static inline void write_uint16(void *p, uint16_t v)
{
	unsigned char *restrict b = p;
	b[0] = (uint8_t)(v >> 8U);
	b[1] = (uint8_t)v;
}

static inline void write_uint16_le(void *p, uint16_t v)
{
	unsigned char *restrict b = p;
	b[0] = (uint8_t)v;
	b[1] = (uint8_t)(v >> 8U);
}

static inline uint32_t read_uint32(const void *p)
{
	const unsigned char *restrict b = p;
	return (uint_fast32_t)(b[0]) << 24U | (uint_fast32_t)(b[1]) << 16U |
	       (uint_fast32_t)(b[2]) << 8U | (uint_fast32_t)(b[3]);
}

static inline uint32_t read_uint32_le(const void *p)
{
	const unsigned char *restrict b = p;
	return (uint_fast32_t)(b[0]) | (uint_fast32_t)(b[1]) << 8U |
	       (uint_fast32_t)(b[2]) << 16U | (uint_fast32_t)(b[3]) << 24U;
}

static inline void write_uint32(void *p, uint32_t v)
{
	unsigned char *restrict b = p;
	b[0] = (uint8_t)(v >> 24U);
	b[1] = (uint8_t)(v >> 16U);
	b[2] = (uint8_t)(v >> 8U);
	b[3] = (uint8_t)v;
}

static inline void write_uint32_le(void *p, uint32_t v)
{
	unsigned char *restrict b = p;
	b[0] = (uint8_t)v;
	b[1] = (uint8_t)(v >> 8U);
	b[2] = (uint8_t)(v >> 16U);
	b[3] = (uint8_t)(v >> 24U);
}

static inline uint64_t read_uint64(const void *p)
{
	const unsigned char *restrict b = p;
	return (uint_fast64_t)(b[0]) << 56U | (uint_fast64_t)(b[1]) << 48U |
	       (uint_fast64_t)(b[2]) << 40U | (uint_fast64_t)(b[3]) << 32U |
	       (uint_fast64_t)(b[4]) << 24U | (uint_fast64_t)(b[5]) << 16U |
	       (uint_fast64_t)(b[6]) << 8U | (uint_fast64_t)(b[7]);
}

static inline uint64_t read_uint64_le(const void *p)
{
	const unsigned char *restrict b = p;
	return (uint_fast64_t)(b[0]) | (uint_fast64_t)(b[1]) << 8U |
	       (uint_fast64_t)(b[2]) << 16U | (uint_fast64_t)(b[3]) << 24U |
	       (uint_fast64_t)(b[4]) << 32U | (uint_fast64_t)(b[5]) << 40U |
	       (uint_fast64_t)(b[6]) << 48U | (uint_fast64_t)(b[7]) << 56U;
}

static inline void write_uint64(void *p, uint64_t v)
{
	unsigned char *restrict b = p;
	b[0] = (uint8_t)(v >> 56U);
	b[1] = (uint8_t)(v >> 48U);
	b[2] = (uint8_t)(v >> 40U);
	b[3] = (uint8_t)(v >> 32U);
	b[4] = (uint8_t)(v >> 24U);
	b[5] = (uint8_t)(v >> 16U);
	b[6] = (uint8_t)(v >> 8U);
	b[7] = (uint8_t)v;
}

static inline void write_uint64_le(void *p, uint64_t v)
{
	unsigned char *restrict b = p;
	b[0] = (uint8_t)v;
	b[1] = (uint8_t)(v >> 8U);
	b[2] = (uint8_t)(v >> 16U);
	b[3] = (uint8_t)(v >> 24U);
	b[4] = (uint8_t)(v >> 32U);
	b[5] = (uint8_t)(v >> 40U);
	b[6] = (uint8_t)(v >> 48U);
	b[7] = (uint8_t)(v >> 56U);
}

#endif /* UTILS_SERIALIZE_H */
