/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef BUFFER_H
#define BUFFER_H

#include "minmax.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_HDR                                                             \
	struct {                                                               \
		const size_t cap;                                              \
		size_t len;                                                    \
	}

/* fixed-size inline buffer usage:
struct {
	BUFFER_HDR;
	unsigned char data[BUF_SIZE];
} rbuf, wbuf;
*/

struct vbuffer {
	BUFFER_HDR;
	unsigned char data[];
};

static inline void buf_init(void *buf, const size_t size)
{
	struct vbuffer *restrict vbuf = buf;
	assert(size >= sizeof(struct vbuffer));
	*((size_t *)&vbuf->cap) = size;
	vbuf->len = 0;
}

static inline void buf_consume(void *buf, const size_t n)
{
	struct vbuffer *restrict vbuf = buf;
	assert(n <= vbuf->len);
	unsigned char *b = vbuf->data;
	if (n < vbuf->len) {
		(void)memmove(b, b + n, vbuf->len - n);
	}
	vbuf->len -= n;
}

static inline size_t buf_append(void *buf, const unsigned char *data, size_t n)
{
	struct vbuffer *restrict vbuf = buf;
	unsigned char *b = vbuf->data + vbuf->len;
	n = MIN(n, vbuf->cap - vbuf->len);
	(void)memcpy(b, data, n);
	vbuf->len += n;
	return n;
}

#define BUF_APPENDCONST(buf, str)                                              \
	buf_append((buf), (const unsigned char *)(str), sizeof(str) - 1u)

#define BUF_APPENDSTR(vbuf, str)                                               \
	buf_append((vbuf), (const unsigned char *)(str), strlen(str))

int buf_appendf(void *buf, const char *format, ...);

static inline bool buf_equals(const void *buf_a, const void *buf_b)
{
	const struct vbuffer *restrict a = buf_a, *restrict b = buf_b;
	if (a->len != b->len) {
		return false;
	}
	return memcmp(a->data, b->data, a->len) == 0;
}

struct vbuffer *vbuf_alloc(struct vbuffer *vbuf, size_t cap);

static inline void vbuf_free(struct vbuffer *buf)
{
	free(buf);
}

struct vbuffer *vbuf_reserve(struct vbuffer *vbuf, size_t want);

struct vbuffer *
vbuf_append(struct vbuffer *vbuf, const unsigned char *data, size_t n);

#define VBUF_APPENDCONST(vbuf, str)                                            \
	vbuf_append((vbuf), (const unsigned char *)(str), sizeof(str) - 1u)

#define VBUF_APPENDSTR(vbuf, str)                                              \
	vbuf_append((vbuf), (const unsigned char *)(str), strlen(str))

struct vbuffer *vbuf_appendf(struct vbuffer *vbuf, const char *format, ...);

#endif /* BUFFER_H */
