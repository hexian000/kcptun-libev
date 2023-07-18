/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_BUFFER_H
#define UTILS_BUFFER_H

#include "minmax.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/**
 * @defgroup buffer
 * @brief Generic buffer utilities.
 * @{
 */

#define BUFFER_HDR                                                             \
	struct {                                                               \
		const size_t cap;                                              \
		size_t len;                                                    \
	}

/* generic buffer type */
struct vbuffer {
	BUFFER_HDR;
	unsigned char data[];
};

/* These internal functions should NOT be called directly, use macros */

/** @internal */
static inline size_t
buf_append(struct vbuffer *restrict buf, const unsigned char *data, size_t n)
{
	unsigned char *b = buf->data + buf->len;
	n = MIN(n, buf->cap - buf->len);
	(void)memcpy(b, data, n);
	buf->len += n;
	return n;
}

/** @internal */
int buf_appendf(struct vbuffer *buf, const char *format, ...);

/** @internal */
struct vbuffer *vbuf_alloc(struct vbuffer *vbuf, size_t cap);

/** @internal */
struct vbuffer *
vbuf_append(struct vbuffer *vbuf, const unsigned char *data, size_t n);

/** @internal */
struct vbuffer *vbuf_appendf(struct vbuffer *vbuf, const char *format, ...);

/**
 * @defgroup BUF
 * @ingroup buffer
 * @brief Fixed length buffer.
 * @details BUF_* macros do not change the buffer allocation.
 * @{
 */

/**
 * @brief Initialize a fixed-length buffer.
 * @details usage:
 * ```C
 * struct {
 * 	BUFFER_HDR;
 * 	unsigned char data[8192];
 * } rbuf, wbuf;
 * BUF_INIT(rbuf, sizeof(rbuf.data));
 * BUF_INIT(wbuf, sizeof(wbuf.data));
 * ```
 */
#define BUF_INIT(buf, size)                                                    \
	do {                                                                   \
		*((size_t *)&(buf).cap) = (size);                              \
		(buf).len = 0;                                                 \
	} while (0)

/**
 * @brief Append fixed-length data to buffer.
 * @return Number of bytes transferred.
 * @details Data will be truncated if there is not enough space.
 * usage: `size_t n = BUF_APPEND(buf, data, len);`
 */
#define BUF_APPEND(buf, data, n)                                               \
	(assert((buf).len <= (buf).cap),                                       \
	 buf_append((struct vbuffer *)&(buf), (data), (n)))

/**
 * @brief Append constant null-terminated string to buffer.
 * @details The string will be truncated if there is not enough space.
 * usage: `buf = BUF_APPENDCONST(buf, "some string");`
 */
#define BUF_APPENDCONST(buf, str)                                              \
	(assert((buf).len <= (buf).cap),                                       \
	 buf_append(                                                           \
		 (struct vbuffer *)&(buf), (const unsigned char *)(str),       \
		 sizeof(str) - 1u))

/**
 * @brief Append null-terminated string to buffer.
 * @details The string will be truncated if there is not enough space.
 * usage: `buf = BUF_APPENDSTR(buf, str);`
 */
#define BUF_APPENDSTR(buf, str)                                                \
	(assert((buf).len <= (buf).cap),                                       \
	 buf_append(                                                           \
		 (struct vbuffer *)&(buf), (const unsigned char *)(str),       \
		 strlen(str)))

/**
 * @brief Append formatted string to buffer.
 * @details The string will be truncated if there is not enough space.
 * usage: `buf = BUF_APPENDF(buf, "%s: %s\r\n", "Content-Type", "text/plain");`
 */
#define BUF_APPENDF(buf, format, ...)                                          \
	(assert((buf).len <= (buf).cap),                                       \
	 buf_appendf((struct vbuffer *)&(buf), (format), __VA_ARGS__))

/**
 * @brief Remove n bytes from the start of the buffer.
 * @details usage: `BUF_CONSUME(buf, sizeof(struct protocol_header));`
 */
#define BUF_CONSUME(buf, n)                                                    \
	do {                                                                   \
		assert(n <= (buf).len && (buf).len <= (buf).cap);              \
		unsigned char *b = (buf).data;                                 \
		if (n < (buf).len) {                                           \
			(void)memmove(b, b + n, (buf).len - n);                \
		}                                                              \
		(buf).len -= n;                                                \
	} while (0)

/**
 * @brief Tests whether two buffers have the same content.
 * @details usage: `if(BUF_EQUALS(vbuf_a, vbuf_b)) { ... }`
 */
#define BUF_EQUALS(a, b)                                                       \
	(assert((a).len <= (a).cap && (b).len <= (b).cap),                     \
	 ((a).len == (b).len && memcmp((a).data, (b).data, (a).len) == 0))

/** @} BUF */

/**
 * @defgroup VBUF
 * @ingroup buffer
 * @brief Variable length buffer.
 * @details VBUF_* macros may change the buffer allocation, and therefore
 * require the buffer is a heap object (not inlined)
 * @{
 */

/**
 * @brief Allocate a new vbuffer object.
 * @param size If 0, returns NULL.
 * @return NULL if the allocation fails.
 * @details struct vbuffer *vbuf = VBUF_NEW(256);
 */
#define VBUF_NEW(size) vbuf_alloc(NULL, (size))

/**
 * @brief Resize vbuffer allocation.
 * @param vbuf If NULL, the behavior is undefined.
 * @return If failed, the allocation remains unchanged.
 * @details usage: `vbuf = VBUF_RESIZE(vbuf, 100);`
 */
#define VBUF_RESIZE(vbuf, size)                                                \
	((vbuf)->cap != (size) ? vbuf_alloc((vbuf), (size)) : (vbuf))

/**
 * @brief Free vbuffer object.
 * @param vbuf If NULL, no operation is performed.
 * @return Always NULL.
 * @details usage: `vbuf = VBUF_FREE(vbuf, 100);`
 */
#define VBUF_FREE(vbuf) vbuf_alloc((vbuf), 0)

/**
 * @brief Adjust vbuffer allocation if data can be preserved.
 * @param vbuf If NULL, the behavior is undefined.
 * @return If failed, the allocation remains unchanged.
 * @details usage: `vbuf = VBUF_RESERVE(vbuf, 16384);`
 */
#define VBUF_RESERVE(vbuf, want) VBUF_RESIZE((vbuf), MAX((vbuf)->len, (want)))

#define VBUF_ASSERT_BOUND(vbuf)                                                \
	assert((vbuf) == NULL || ((struct vbuffer *)(vbuf))->len <=            \
					 ((struct vbuffer *)(vbuf))->cap)

/**
 * @brief Append fixed-length data to vbuffer.
 * @param vbuf If NULL, the minimum required size is allocated.
 * @return If the allocation fails, the data remains unchanged.
 * @details Allocation will be expanded if there is not enough space.
 * usage: `vbuf = VBUF_APPEND(vbuf, data, len);`
 */
#define VBUF_APPEND(vbuf, data, n)                                             \
	(VBUF_ASSERT_BOUND(vbuf), vbuf_append((vbuf), (data), (n)))

/**
 * @brief Append constant null-terminated string to vbuffer.
 * @param vbuf If NULL, the minimum required size is allocated.
 * @return If the allocation fails, the data remains unchanged.
 * @details Allocation will be expanded if there is not enough space.
 * usage: `vbuf = VBUF_APPENDCONST(vbuf, "some string");`
 */
#define VBUF_APPENDCONST(vbuf, str)                                            \
	(VBUF_ASSERT_BOUND(vbuf),                                              \
	 vbuf_append((vbuf), (const unsigned char *)(str), sizeof(str) - 1u))

/**
 * @brief Append null-terminated string to vbuffer.
 * @param vbuf If NULL, the minimum required size is allocated.
 * @return If the allocation fails, the data remains unchanged.
 * @details Allocation will be expanded if there is not enough space.
 * usage: `vbuf = VBUF_APPENDSTR(vbuf, str);`
 */
#define VBUF_APPENDSTR(vbuf, str)                                              \
	(VBUF_ASSERT_BOUND(vbuf),                                              \
	 vbuf_append((vbuf), (const unsigned char *)(str), strlen(str)))

/**
 * @brief Append formatted string to vbuffer.
 * @param vbuf If NULL, the minimum required size is allocated.
 * @return If the allocation fails, the data remains unchanged.
 * @details Allocation will be expanded if there is not enough space.
 * usage: vbuf = VBUF_APPENDF(vbuf, "%s: %s\r\n", "Content-Type", "text/plain");
 */
#define VBUF_APPENDF(vbuf, format, ...)                                        \
	(VBUF_ASSERT_BOUND(vbuf), vbuf_appendf((vbuf), (format), __VA_ARGS__))

/**
 * @brief Remove n bytes from the start of the vbuffer.
 * @param vbuf If NULL, the behavior is undefined.
 * @details usage: `VBUF_CONSUME(vbuf, sizeof(struct protocol_header));`
 */
#define VBUF_CONSUME(vbuf, n) BUF_CONSUME(*(vbuf), (n))

/**
 * @brief Tests whether two vbuffers have the same content.
 * @param vbuf If NULL, the behavior is undefined.
 * @details usage: `if(VBUF_EQUALS(vbuf_a, vbuf_b)) { ... }`
 */
#define VBUF_EQUALS(a, b) BUF_EQUALS(*(a), *(b))

/** @} VBUF */

/** @} */

#endif /* UTILS_BUFFER_H */
