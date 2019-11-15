#ifndef ENDIAN_H
#define ENDIAN_H

#include <stdint.h>

static inline uint16_t read_uint16(const uint8_t *b)
{
	return ((uint16_t)b[1]) | ((uint16_t)b[0]) << 8U;
}

static inline void write_uint16(uint8_t *b, uint16_t v)
{
	b[1] = (uint8_t)v;
	b[0] = (uint8_t)(v >> 8U);
}

static inline uint32_t read_uint32(const uint8_t *b)
{
	uint32_t v = (uint32_t)(b[3]);
	v |= (uint32_t)(b[2]) << 8U;
	v |= (uint32_t)(b[1]) << 16U;
	v |= (uint32_t)(b[0]) << 24U;
	return v;
}

static inline void write_uint32(uint8_t *b, uint32_t v)
{
	b[3] = (uint8_t)v;
	b[2] = (uint8_t)(v >> 8U);
	b[1] = (uint8_t)(v >> 16U);
	b[0] = (uint8_t)(v >> 24U);
}

static inline uint64_t read_uint64(const uint8_t *b)
{
	uint64_t v = (uint64_t)(b[7]);
	v |= (uint64_t)(b[6]) << 8U;
	v |= (uint64_t)(b[5]) << 16U;
	v |= (uint64_t)(b[4]) << 24U;
	v |= (uint64_t)(b[3]) << 32U;
	v |= (uint64_t)(b[2]) << 40U;
	v |= (uint64_t)(b[1]) << 48U;
	v |= (uint64_t)(b[0]) << 56U;
	return v;
}

static inline void write_uint64(uint8_t *b, uint64_t v)
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

#endif /* ENDIAN_H */
