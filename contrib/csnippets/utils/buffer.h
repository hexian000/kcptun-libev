/* csnippets (c) 2019-2025 He Xian <hexian000@outlook.com>
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

/* These internal functions should NOT be called directly, use macros */

/** @internal */
static inline size_t
buf_append(struct buffer *restrict buf, const void *data, size_t n)
{
	n = MIN(n, buf->cap - buf->len);
	if (n == 0) {
		return 0;
	}
	unsigned char *b = buf->data + buf->len;
	(void)memcpy(b, data, n);
	buf->len += n;
	return n;
}

/** @internal */
int buf_vappendf(struct buffer *buf, const char *format, va_list args);

/** @internal */
int buf_appendf(struct buffer *buf, const char *format, ...);

/* heap allocated buffer */
struct vbuffer {
	BUFFER_HDR;
	unsigned char data[];
};

/** @internal */
static inline struct vbuffer *
vbuf_alloc(struct vbuffer *restrict vbuf, const size_t cap)
{
	if (cap == 0) {
		free(vbuf);
		return NULL;
	}
	const size_t len = (vbuf != NULL) ? vbuf->len : 0;
	/* reserve 1 byte for null terminator */
	struct vbuffer *restrict newbuf =
		realloc(vbuf, sizeof(struct vbuffer) + cap + 1);
	if (newbuf == NULL) {
		return vbuf;
	}
	vbuf = newbuf;
	vbuf->cap = cap;
	vbuf->len = MIN(cap, len);
	return vbuf;
}

/** @internal */
struct vbuffer *vbuf_grow(struct vbuffer *vbuf, size_t want, size_t maxcap);

/** @internal */
struct vbuffer *vbuf_append(struct vbuffer *vbuf, const void *data, size_t n);

/** @internal */
struct vbuffer *
vbuf_vappendf(struct vbuffer *vbuf, const char *format, va_list args);

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
 * BUF_INIT(rbuf, 0);
 * BUF_INIT(wbuf, 0);
 * ```
 */
#define BUF_INIT(buf, n)                                                       \
	do {                                                                   \
		_Static_assert((n) <= sizeof((buf).data), "buffer overflow");  \
		(buf).cap = sizeof((buf).data);                                \
		(buf).len = (n);                                               \
	} while (0)

#define BUF_CONST(buf, str)                                                    \
	do {                                                                   \
		static struct {                                                \
			BUFFER_HDR;                                            \
			unsigned char data[sizeof(str)];                       \
		} literalbuf = {                                               \
			.cap = sizeof(str) - 1,                                \
			.len = sizeof(str) - 1,                                \
			.data = str,                                           \
		};                                                             \
		(buf) = (struct buffer *)&literalbuf;                          \
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
 * @brief Append literal string to buffer.
 * @details The string will be truncated if there is not enough space.
 * usage: `size_t n = BUF_APPENDSTR(buf, "some string");`
 */
#define BUF_APPENDSTR(buf, str)                                                \
	(assert((buf).len <= (buf).cap),                                       \
	 buf_append(                                                           \
		 (struct buffer *)&(buf), (const void *)("" str),              \
		 sizeof(str) - 1u))

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
		const unsigned char *b = (buf).data;                           \
		(void)memmove((buf).data, b + n, (buf).len - n);               \
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

#define VBUF_ASSERT_BOUND(vbuf)                                                \
	assert((vbuf)->cap > 0 && (vbuf)->len <= (vbuf)->cap)

/**
 * @brief Free vbuffer object.
 * @param vbuf If NULL, no operation is performed.
 * @return Always NULL.
 * @details usage: `vbuf = VBUF_FREE(vbuf);`
 */
#define VBUF_FREE(vbuf) (vbuf_alloc((vbuf), 0))

/**
 * @brief Get vbuffer capacity.
 * @return Capacity in bytes.
 */
#define VBUF_CAP(vbuf) ((vbuf) != NULL ? (vbuf)->cap : 0)

/**
 * @brief Get vbuffer length.
 * @return Length in bytes.
 */
#define VBUF_LEN(vbuf) ((vbuf) != NULL ? (vbuf)->len : 0)

/**
 * @brief Get vbuffer remaining space.
 * @return Space in bytes.
 */
#define VBUF_REMAINING(vbuf) ((vbuf) != NULL ? (vbuf)->cap - (vbuf)->len : 0)

/**
 * @brief Get raw pointer to the buffered data.
 * @return Length in bytes.
 */
#define VBUF_DATA(vbuf) ((vbuf) != NULL ? (void *)(vbuf)->data : (void *)"")

/**
 * @brief Clear the vbuffer without changing the allocation.
 * @return Passthrough.
 * @details usage: `vbuf = VBUF_RESET(vbuf);`
 */
#define VBUF_RESET(vbuf) ((vbuf) != NULL ? ((vbuf)->len = 0, (vbuf)) : NULL)

/**
 * @brief Clear and resize the vbuffer for specified number of bytes.
 * @param vbuf If NULL, new buffer is allocated.
 * @param want Expected vbuffer overall capacity in bytes.
 * @return If failed, the allocation remains unchanged.
 * @details usage: `vbuf = VBUF_RESIZE(vbuf, 1024);`
 */
#define VBUF_RESIZE(vbuf, want) (vbuf_alloc(VBUF_RESET(vbuf), (want) + 1))

/**
 * @brief Prepare the vbuffer for specified number of bytes.
 * @param want Expected vbuffer overall capacity in bytes.
 * @return If failed, the allocation remains unchanged.
 * @details usage: `vbuf = VBUF_RESERVE(vbuf, 0); // shrink the buffer to fit`
 */
#define VBUF_RESERVE(vbuf, want)                                               \
	(vbuf_alloc((vbuf), MAX(VBUF_LEN(vbuf), (want)) + 1))

/**
 * @brief Append fixed-length data to vbuffer.
 * @param vbuf If NULL, new vbuffer is allocated.
 * @return If the allocation fails, the data is truncated.
 * @details vbuf will be expanded if there is not enough space. <br>
 * If the input buffer is full, no operation is performed and the original
 * buffer is returned. <br>
 * When vbuf is expanded, 1 extra byte is always reserved. Therefore,
 * a returned buffer full indicates an allocation failure. <br>
 * usage: `vbuf = VBUF_APPEND(vbuf, data, len);`
 */
#define VBUF_APPEND(vbuf, data, n)                                             \
	(VBUF_ASSERT_BOUND(vbuf), vbuf_append((vbuf), (data), (n)))

/**
 * @brief Append literal string to vbuffer.
 * @param vbuf If NULL, new buffer is allocated.
 * @return If the allocation fails, the data is truncated.
 * @see VBUF_APPEND
 * @details usage: `vbuf = VBUF_APPENDSTR(vbuf, "some string");`
 */
#define VBUF_APPENDSTR(vbuf, str)                                              \
	(VBUF_ASSERT_BOUND(vbuf),                                              \
	 vbuf_append((vbuf), (const void *)("" str), sizeof(str) - sizeof("")))

/**
 * @brief Append formatted string to vbuffer.
 * @param vbuf If NULL, new buffer is allocated.
 * @return If the allocation fails, the data is truncated.
 * @see VBUF_APPEND
 * @details usage: vbuf = VBUF_APPENDF(vbuf, "%s: %s\r\n", "Content-Type", "text/plain");
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
#define VBUF_CONSUME(vbuf, n)                                                  \
	do {                                                                   \
		if ((n) == 0) {                                                \
			break;                                                 \
		}                                                              \
		BUF_CONSUME(*(vbuf), (n));                                     \
	} while (0)

/**
 * @brief Tests whether two vbuffers have the same content.
 * @param vbuf If NULL, the behavior is undefined.
 * @details usage: `if(VBUF_EQUALS(vbuf_a, vbuf_b)) { ... }`
 */
#define VBUF_EQUALS(a, b)                                                      \
	(VBUF_LEN(a) == 0 ? VBUF_LEN(b) == 0 :                                 \
			    a->len == VBUF_LEN(b) &&                           \
				    memcmp(a->data, b->data, a->len) == 0)

/** @} VBUF */

/** @} */

#endif /* UTILS_BUFFER_H */
