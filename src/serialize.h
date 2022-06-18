#ifndef SERIALIZE_H
#define SERIALIZE_H

/**
 * @brief serialize.h is a primitive type serializer
 * These functions are carefully tuned for compilers to generate fast code.
 */

#include <stdint.h>

static inline uint8_t read_uint8(const unsigned char *restrict b)
{
	return b[0];
}

static inline void write_uint8(unsigned char *restrict b, uint8_t v)
{
	b[0] = v;
}

static inline uint16_t read_uint16(const unsigned char *restrict b)
{
	return ((((uint_fast16_t)b[0]) << 8U) | ((uint_fast16_t)b[1]));
}

static inline void write_uint16(unsigned char *restrict b, uint16_t v)
{
	b[1] = (uint8_t)v;
	b[0] = (uint8_t)(v >> 8U);
}

static inline uint32_t read_uint32(const unsigned char *restrict b)
{
	return (uint_fast32_t)(b[0]) << 24U | (uint_fast32_t)(b[1]) << 16U |
	       (uint_fast32_t)(b[2]) << 8U | (uint_fast32_t)(b[3]);
}

static inline void write_uint32(unsigned char *restrict b, uint32_t v)
{
	b[3] = (uint8_t)v;
	b[2] = (uint8_t)(v >> 8U);
	b[1] = (uint8_t)(v >> 16U);
	b[0] = (uint8_t)(v >> 24U);
}

static inline uint64_t read_uint64(const unsigned char *restrict b)
{
	return (uint_fast64_t)(b[0]) << 56U | (uint_fast64_t)(b[1]) << 48U |
	       (uint_fast64_t)(b[2]) << 40U | (uint_fast64_t)(b[3]) << 32U |
	       (uint_fast64_t)(b[4]) << 24U | (uint_fast64_t)(b[5]) << 16U |
	       (uint_fast64_t)(b[6]) << 8U | (uint_fast64_t)(b[7]);
}

static inline void write_uint64(unsigned char *restrict b, uint64_t v)
{
	b[7] = (uint8_t)v;
	b[6] = (uint8_t)(v >> 8U);
	b[5] = (uint8_t)(v >> 16U);
	b[4] = (uint8_t)(v >> 24U);
	b[3] = (uint8_t)(v >> 32U);
	b[2] = (uint8_t)(v >> 40U);
	b[1] = (uint8_t)(v >> 48U);
	b[0] = (uint8_t)(v >> 56U);
}

#endif /* SERIALIZE_H */
