/* csnippets (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_BUFFER_H
#define UTILS_BUFFER_H

#include "minmax.h"

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * @defgroup buffer
 * @brief Generic buffer utilities.
 *
 * This header provides two buffer abstractions: fixed-size buffers that never
 * allocate and heap-allocated growable buffers that can expand as needed.
 *
 * Design:
 * - All buffers share a common header `BUFFER_HDR` storing `cap` and `len`.
 * - Growable buffers internally reserve one extra byte to simplify placing a
 *   trailing '\0' for textual data; this byte is not counted in `cap` and `len`.
 * - Append helpers for raw bytes do not add a null terminator. Formatting
 *   helpers use the reserved slot to keep data NUL-terminated without
 *   affecting `len`.
 * - None of the APIs are thread-safe; add external synchronization if shared.
 *
 * Error handling:
 * - Fixed buffers truncate to available space and report bytes transferred.
 * - Growable buffers attempt to expand; on failure, they append what fits.
 *   When a growable buffer becomes full (`len == cap`), it indicates a prior
 *   allocation failure and further appends are skipped.
 * @{ 
 */

/**
 * @brief Common header for both fixed and growable buffers.
 * - cap: total capacity in bytes of the data region
 * - len: number of valid payload bytes (0 <= len <= cap)
 */
#define BUFFER_HDR                                                             \
	struct {                                                               \
		size_t cap;                                                    \
		size_t len;                                                    \
	}

/**
 * @brief Opaque helper type used internally for fixed-size buffers.
 * Do not instantiate directly; embed BUFFER_HDR and a concrete data[N] in your own struct.
 */
struct buffer {
	BUFFER_HDR;
	unsigned char data[];
};

/* These internal functions should NOT be called directly, use macros instead */

/**
 * @internal
 * Append up to n bytes into a fixed buffer.
 * Copies min(n, cap - len) bytes from data into buf->data + buf->len.
 * Does not add a trailing NUL.
 * Returns: number of bytes actually appended (may be 0 if no space).
 */
static inline size_t
buf_append(struct buffer *restrict buf, const void *restrict data, size_t n)
{
	n = MIN(n, buf->cap - buf->len);
	if (n == 0) {
		return 0;
	}
	void *restrict dest = buf->data + buf->len;
	(void)memcpy(dest, data, n);
	buf->len += n;
	return n;
}

/**
 * @internal
 * Append formatted text into a fixed buffer using a va_list.
 * Writes at most remaining capacity; output is NUL-terminated in place.
 * len is advanced by up to maxlen - 1.
 * Returns: vsnprintf-style count of chars that would have been written (excluding NUL).
 */
int buf_vappendf(struct buffer *buf, const char *format, va_list args);

/**
 * @internal
 * Convenience wrapper over buf_vappendf with variadic arguments.
 */
int buf_appendf(struct buffer *buf, const char *format, ...);

/* heap allocated buffer */
/**
 * @brief Header + flexible array used for growable heap buffers.
 */
struct vbuffer {
	BUFFER_HDR;
	unsigned char data[];
};

/**
 * @internal
 * Allocate or resize a growable buffer to exactly `cap` bytes.
 * - When vbuf == NULL, behaves like malloc for a new object.
 * - When cap == 0, frees and returns NULL.
 * - On allocation failure, returns the original vbuf unchanged.
 * - One extra byte is always reserved (cap + 1 total) for internal NUL.
 * - Preserves len up to the new cap if shrinking.
 */
static inline struct vbuffer *vbuf_alloc(struct vbuffer *vbuf, const size_t cap)
{
	if (cap == 0) {
		free(vbuf);
		return NULL;
	}
	if (cap > SIZE_MAX - sizeof(struct vbuffer) - 1) {
		return vbuf;
	}
	const size_t len = (vbuf != NULL) ? vbuf->len : 0;
	/* reserve 1 byte for null terminator */
	struct vbuffer *newbuf =
		realloc(vbuf, sizeof(struct vbuffer) + cap + 1);
	if (newbuf == NULL) {
		return vbuf;
	}
	vbuf = newbuf;
	vbuf->cap = cap;
	vbuf->len = MIN(cap, len);
	return vbuf;
}

/**
 * @internal
 * Ensure capacity is at least `want` bytes (not counting reserved NUL).
 * Uses a growth strategy tuned for small and large buffers, with overflow
 * checks. On failure, returns the original pointer unchanged.
 */
struct vbuffer *vbuf_grow(struct vbuffer *vbuf, size_t want);

/**
 * @internal
 * Append up to n bytes to a growable buffer.
 * Attempts to grow to fit; if growth fails, appends as much as possible.
 * Writes a trailing NUL in the reserved byte without affecting len.
 * Precondition: vbuf != NULL. If len == cap, append is skipped.
 */
struct vbuffer *vbuf_append(struct vbuffer *vbuf, const void *data, size_t n);

/**
 * @internal
 * Append formatted text using a va_list. Two-pass attempt: write into
 * remaining capacity first, then grow and retry if needed. Keeps a trailing
 * NUL in the reserved byte. On failure, may truncate to what fits.
 */
struct vbuffer *
vbuf_vappendf(struct vbuffer *vbuf, const char *format, va_list args);

/**
 * @internal
 * Convenience wrapper over vbuf_vappendf with variadic arguments.
 */
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

/**
 * @brief Bind a buffer handle to a literal string without copying.
 * @details The lifetime of `buf` is limited to the current scope.
 */
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
 * @details Data will be truncated if there is not enough space. No
 * NUL-terminator is added.
 * usage: `size_t n = BUF_APPEND(buf, data, len);`
 */
#define BUF_APPEND(buf, data, n)                                               \
	(assert((buf).len <= (buf).cap),                                       \
	 buf_append((struct buffer *)&(buf), (data), (n)))

/**
 * @brief Append literal string to buffer.
 * @details The string will be truncated if there is not enough space. No
 * NUL-terminator is added.
 * usage: `size_t n = BUF_APPENDSTR(buf, "some string");`
 */
#define BUF_APPENDSTR(buf, str)                                                \
	(assert((buf).len <= (buf).cap),                                       \
	 buf_append(                                                           \
		 (struct buffer *)&(buf), (const void *)("" str),              \
		 sizeof(str) - 1u))

/**
 * @brief Append formatted string to buffer.
 * @details The string will be truncated if there is not enough space. A
 * trailing NUL is written in-place but not counted by `len`.
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
 * require the buffer be a heap object (not inlined)
 * @{
 */

/**
 * @brief Allocate a new vbuffer object.
 * @param size Requested capacity in bytes (excludes reserved NUL).
 * @return NULL if `size == 0` or the allocation fails.
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
