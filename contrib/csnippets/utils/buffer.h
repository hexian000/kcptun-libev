/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_BUFFER_H
#define UTILS_BUFFER_H

#include "minmax.h"

#include <assert.h>
#include <stdarg.h>
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
		size_t cap;                                                    \
		size_t len;                                                    \
	}

/* fixed buffer */
struct buffer {
	BUFFER_HDR;
	unsigned char data[];
};

/* heap allocated buffer */
struct vbuffer {
	BUFFER_HDR;
	unsigned char data[];
};

/* These internal functions should NOT be called directly, use macros */

/** @internal */
size_t buf_append(struct buffer *buf, const unsigned char *data, size_t n);

/** @internal */
int buf_appendf(struct buffer *buf, const char *format, ...);

/** @internal */
int buf_vappendf(struct buffer *buf, const char *format, va_list args);

/** @internal */
struct vbuffer *vbuf_alloc(struct vbuffer *vbuf, size_t cap);

/** @internal */
struct vbuffer *vbuf_grow(struct vbuffer *vbuf, size_t want);

/** @internal */
struct vbuffer *
vbuf_append(struct vbuffer *vbuf, const unsigned char *data, size_t n);

/** @internal */
struct vbuffer *vbuf_appendf(struct vbuffer *vbuf, const char *format, ...);

/** @internal */
struct vbuffer *
vbuf_vappendf(struct vbuffer *vbuf, const char *format, va_list args);

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
 * BUF_INIT(rbuf, 0);
 * BUF_INIT(wbuf, 0);
 * ```
 */
#define BUF_INIT(buf, n)                                                       \
	do {                                                                   \
		(buf).cap = sizeof((buf).data);                                \
		(buf).len = (n);                                               \
	} while (0)

/**
 * @brief Append fixed-length data to buffer.
 * @return Number of bytes transferred.
 * @details Data will be truncated if there is not enough space.
 * usage: `size_t n = BUF_APPEND(buf, data, len);`
 */
#define BUF_APPEND(buf, data, n)                                               \
	(assert((buf).len <= (buf).cap),                                       \
	 buf_append((struct buffer *)&(buf), (data), (n)))

/**
 * @brief Append constant null-terminated string to buffer.
 * @details The string will be truncated if there is not enough space.
 * usage: `size_t n = BUF_APPENDCONST(buf, "some string");`
 */
#define BUF_APPENDCONST(buf, str)                                              \
	(assert((buf).len <= (buf).cap),                                       \
	 buf_append(                                                           \
		 (struct buffer *)&(buf), (const unsigned char *)(str),        \
		 sizeof(str) - 1u))

/**
 * @brief Append null-terminated string to buffer.
 * @details The string will be truncated if there is not enough space.
 * usage: `size_t n = BUF_APPENDSTR(buf, str);`
 */
#define BUF_APPENDSTR(buf, str)                                                \
	(assert((buf).len <= (buf).cap),                                       \
	 buf_append(                                                           \
		 (struct buffer *)&(buf), (const unsigned char *)(str),        \
		 strlen(str)))

/**
 * @brief Append formatted string to buffer.
 * @details The string will be truncated if there is not enough space.
 * usage: `int ret = BUF_APPENDF(buf, "%s: %s\r\n", "Content-Type", "text/plain");`
 */
#define BUF_APPENDF(buf, format, ...)                                          \
	(assert((buf).len <= (buf).cap),                                       \
	 buf_appendf((struct buffer *)&(buf), (format), __VA_ARGS__))

#define BUF_VAPPENDF(buf, format, args)                                        \
	(assert((buf).len <= (buf).cap),                                       \
	 buf_vappendf((struct buffer *)&(buf), (format), (args)))

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
 * @brief Free vbuffer object.
 * @param vbuf If NULL, no operation is performed.
 * @return Always NULL.
 * @details usage: `vbuf = VBUF_FREE(vbuf);`
 */
#define VBUF_FREE(vbuf) vbuf_alloc((vbuf), 0)

/**
 * @brief Resize vbuffer allocation. Data maybe truncated.
 * @param vbuf If NULL, new buffer may be allocated.
 * @param want Expected vbuffer overall size in bytes.
 * @return If failed, the allocation remains unchanged.
 * @details usage: `vbuf = VBUF_RESIZE(vbuf, 100);`
 */
#define VBUF_RESIZE(vbuf, size)  vbuf_alloc((vbuf), (size)) : (vbuf))

/**
 * @brief Adjust vbuffer allocation only if data can be preserved.
 * @param vbuf If NULL, new buffer may be allocated.
 * @param want Expected vbuffer overall size in bytes.
 * @return If failed, the allocation remains unchanged.
 * @details usage: `vbuf = VBUF_RESERVE(vbuf, 0); // shrink the buffer to fit`
 */
#define VBUF_RESERVE(vbuf, want)                                               \
	vbuf_alloc((vbuf), (vbuf) != NULL ? MAX((vbuf)->len, (want)) : (want))

/**
 * @brief Expand vbuffer allocation.
 * @param vbuf If NULL, new buffer may be allocated.
 * @param want Expected additional vbuffer space in bytes.
 * @return If failed, the allocation remains unchanged.
 * @details usage: `vbuf = VBUF_GROW(vbuf, 16384);`
 */
#define VBUF_GROW(vbuf, want) vbuf_grow((vbuf), (want))

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

#define VBUF_VAPPENDF(vbuf, format, args)                                      \
	(VBUF_ASSERT_BOUND(vbuf), vbuf_vappendf((vbuf), (format), (args)))

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
