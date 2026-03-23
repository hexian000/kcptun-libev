/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
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
 * - Growable buffers reserve one extra byte internally for NUL-termination;
 *   this detail is fully hidden by the API.
 * - Append helpers for raw bytes do not add a null terminator. Formatting
 *   helpers keep data NUL-terminated in an internal reserved slot without
 *   affecting `len`.
 * - None of the APIs are thread-safe; add external synchronization if shared.
 *
 * Error handling:
 * - Fixed buffers truncate to available space and report bytes transferred.
 * - Growable buffers attempt to expand; on allocation failure they append what
 *   fits and record an OOM condition. Further appends are skipped. Check with
 *   `VBUF_HAS_OOM`.
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
 * Returns vsnprintf-style count (chars that would have been written, excluding
 * NUL). Returns -1 when OOM has already been recorded and the append is skipped.
 */
int vbuf_vappendf(struct vbuffer **pvbuf, const char *format, va_list args);

/**
 * @internal
 * Convenience wrapper over vbuf_vappendf with variadic arguments.
 */
int vbuf_appendf(struct vbuffer **pvbuf, const char *format, ...);

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

/* Asserts cap > 0 and len within [0, cap]. */
#define BUF_ASSERT_SANITY(buf) assert((buf).cap > 0 && (buf).len <= (buf).cap)

/* Asserts at least n bytes of valid data reside in the buffer. */
#define BUF_ASSERT_LEAST(buf, n)                                               \
	assert((buf).cap > 0 && (n) <= (buf).len && (buf).len <= (buf).cap)

/**
 * @brief Bind a buffer handle to a literal string without copying.
 * @details The buffer has static storage duration; its content must not be
 * modified.
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
 * @details Data will be truncated if there is not enough space. No
 * NUL-terminator is added.
 * usage: `BUF_APPEND(buf, data, len);`
 */
#define BUF_APPEND(buf, data, n)                                               \
	do {                                                                   \
		BUF_ASSERT_SANITY(buf);                                        \
		buf_append((struct buffer *)&(buf), (data), (n));              \
	} while (0)

/**
 * @brief Append literal string to buffer.
 * @details The string will be truncated if there is not enough space. No
 * NUL-terminator is added.
 * usage: `BUF_APPENDSTR(buf, "some string");`
 */
#define BUF_APPENDSTR(buf, str)                                                \
	do {                                                                   \
		BUF_ASSERT_SANITY(buf);                                        \
		buf_append(                                                    \
			(struct buffer *)&(buf), (const void *)("" str),       \
			sizeof(str) - 1u);                                     \
	} while (0)

/**
 * @brief Append formatted string to buffer.
 * @details The string will be truncated if there is not enough space. A
 * trailing NUL is written in-place but not counted by `len`.
 * usage: `BUF_APPENDF(buf, "%s: %s\r\n", "Content-Type", "text/plain");`
 */
#define BUF_APPENDF(buf, format, ...)                                          \
	(BUF_ASSERT_SANITY(buf),                                               \
	 buf_appendf((struct buffer *)&(buf), (format), __VA_ARGS__))

/**
 * @brief Append formatted string to buffer using a va_list.
 * @details The string will be truncated if there is not enough space. A
 * trailing NUL is written in-place but not counted by `len`.
 * usage: `BUF_VAPPENDF(buf, "%s: %s\r\n", args);`
 */
#define BUF_VAPPENDF(buf, format, args)                                        \
	(BUF_ASSERT_SANITY(buf),                                               \
	 buf_vappendf((struct buffer *)&(buf), (format), (args)))

/**
 * @brief Remove n bytes from the start of the buffer.
 * @details usage: `BUF_CONSUME(buf, sizeof(struct protocol_header));`
 */
#define BUF_CONSUME(buf, n)                                                    \
	do {                                                                   \
		BUF_ASSERT_LEAST(buf, n);                                      \
		const unsigned char *b = (buf).data;                           \
		(void)memmove((buf).data, b + n, (buf).len - n);               \
		(buf).len -= n;                                                \
	} while (0)

/**
 * @brief Clear the buffer without changing the allocation.
 * @details usage: `BUF_RESET(buf);`
 */
#define BUF_RESET(buf)                                                         \
	do {                                                                   \
		BUF_ASSERT_SANITY(buf);                                        \
		(buf).len = 0;                                                 \
	} while (0)

/**
 * @brief Tests whether two buffers have the same content.
 * @details usage: `if(BUF_EQUALS(vbuf_a, vbuf_b)) { ... }`
 */
#define BUF_EQUALS(a, b)                                                       \
	(BUF_ASSERT_SANITY(a), BUF_ASSERT_SANITY(b),                           \
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
 * @param size Requested capacity in bytes.
 * @return NULL on allocation failure.
 * @details usage: `struct vbuffer *vbuf = VBUF_NEW(256);`
 */
#define VBUF_NEW(size) vbuf_alloc(NULL, (size) + 1)

/* Asserts cap > 0 and len within [0, cap]. */
#define VBUF_ASSERT_SANITY(vbuf)                                               \
	assert((vbuf)->cap > 0 && (vbuf)->len <= (vbuf)->cap)

/* Asserts at least n bytes of valid data reside in the vbuffer. */
#define VBUF_ASSERT_LEAST(vbuf, n)                                             \
	assert((vbuf)->cap > 0 && (n) <= (vbuf)->len &&                        \
	       (vbuf)->len <= (vbuf)->cap)

/**
 * @brief Free the vbuffer object and set the variable to NULL.
 * @param vbuf Must be a valid lvalue of type `struct vbuffer *`.
 * @details usage: `VBUF_FREE(vbuf);`
 */
#define VBUF_FREE(vbuf)                                                        \
	do {                                                                   \
		(vbuf) = vbuf_alloc((vbuf), 0);                                \
	} while (0)

/**
 * @brief Get vbuffer capacity.
 * @return Capacity in bytes.
 */
#define VBUF_CAP(vbuf) (VBUF_ASSERT_SANITY(vbuf), (vbuf)->cap - 1)

/**
 * @brief Get vbuffer length.
 * @return Length in bytes.
 */
#define VBUF_LEN(vbuf) (VBUF_ASSERT_SANITY(vbuf), (vbuf)->len)

/**
 * @brief Get vbuffer free space (bytes appendable without reallocation).
 * @return Bytes remaining without reallocation, or 0 if at capacity.
 */
#define VBUF_REMAINING(vbuf)                                                   \
	(VBUF_ASSERT_SANITY(vbuf),                                             \
	 ((vbuf)->len < (vbuf)->cap ? (vbuf)->cap - (vbuf)->len - 1 : 0))

/**
 * @brief Test whether a previous operation on the vbuffer has failed due to OOM.
 * @return true if OOM was detected, false otherwise.
 */
#define VBUF_HAS_OOM(vbuf)                                                     \
	((vbuf) == NULL ||                                                     \
	 (VBUF_ASSERT_SANITY(vbuf), (vbuf)->len == (vbuf)->cap))

/**
 * @brief Get raw pointer to the start of the buffered data.
 * @return Pointer to the buffered data.
 */
#define VBUF_DATA(vbuf) (VBUF_ASSERT_SANITY(vbuf), (void *)((vbuf)->data))

/**
 * @brief Get a pointer and length view into the vbuffer at an offset.
 * @param b Lvalue to receive the pointer to the data at the given offset.
 * @param n Lvalue to receive the number of bytes from offset to end.
 * @param vbuf The vbuffer to view.
 * @param offset Byte offset from the start of the buffer.
 */
#define VBUF_VIEW(b, n, vbuf, offset)                                          \
	do {                                                                   \
		VBUF_ASSERT_LEAST(vbuf, (offset));                             \
		(b) = (void *)((vbuf)->data + (offset));                       \
		(n) = (vbuf)->len - (offset);                                  \
	} while (0)

/**
 * @brief Get a pointer and length view into the free space after the vbuffer data.
 * @param b Lvalue to receive the pointer to the first writable byte.
 * @param n Lvalue to receive the number of writable bytes available.
 * @param vbuf The vbuffer to slice.
 * @details This is the write counterpart of VBUF_VIEW: where VBUF_VIEW exposes
 * existing data for reading, VBUF_SPACE exposes the unused tail for writing.
 * After writing n bytes via the returned pointer, advance len manually with
 * `(vbuf)->len += n`.
 * usage: `VBUF_SPACE(b, n, vbuf);`
 */
#define VBUF_SPACE(b, n, vbuf)                                                 \
	do {                                                                   \
		VBUF_ASSERT_SANITY(vbuf);                                      \
		(b) = (void *)((vbuf)->data + (vbuf)->len);                    \
		(n) = (vbuf)->cap > (vbuf)->len ?                              \
			      (vbuf)->cap - 1 - (vbuf)->len :                  \
			      0;                                               \
	} while (0)

/**
 * @brief Clear the vbuffer without changing the allocation.
 * @details usage: `VBUF_RESET(vbuf);`
 */
#define VBUF_RESET(vbuf)                                                       \
	do {                                                                   \
		VBUF_ASSERT_SANITY(vbuf);                                      \
		(vbuf)->len = 0;                                               \
	} while (0)

/**
 * @brief Resize the vbuffer to the specified capacity.
 * @param vbuf Must be a valid lvalue of type `struct vbuffer *`.
 * @param want New capacity in bytes. If smaller than current length, data is
 * truncated.
 * @details On failure, the allocation remains unchanged.
 * usage: `VBUF_RESIZE(vbuf, 1024);`
 */
#define VBUF_RESIZE(vbuf, want)                                                \
	do {                                                                   \
		VBUF_ASSERT_SANITY(vbuf);                                      \
		(vbuf) = vbuf_alloc((vbuf), (want) + 1);                       \
		(vbuf)->len = MIN((vbuf)->len, (want));                        \
	} while (0)

/**
 * @brief Prepare the vbuffer for specified number of bytes.
 * @param vbuf Must be a valid lvalue of type `struct vbuffer *`.
 * @param want Expected vbuffer capacity in bytes.
 * @details On failure, the allocation remains unchanged.
 * usage: `VBUF_RESERVE(vbuf, 0);` (with want=0, shrinks the buffer to fit)
 */
#define VBUF_RESERVE(vbuf, want)                                               \
	do {                                                                   \
		const size_t n = ((vbuf) != NULL) ? (vbuf)->len : 0;           \
		(vbuf) = vbuf_alloc((vbuf), MAX(n, (want)) + 1);               \
	} while (0)

/**
 * @brief Append fixed-length data to vbuffer.
 * @param vbuf Must be a valid lvalue of type `struct vbuffer *`.
 * @details vbuf will be expanded if there is not enough space. On allocation
 * failure, data is truncated and OOM is set; check with `VBUF_HAS_OOM`.
 * usage: `VBUF_APPEND(vbuf, data, len);`
 */
#define VBUF_APPEND(vbuf, data, n)                                             \
	do {                                                                   \
		VBUF_ASSERT_SANITY(vbuf);                                      \
		(vbuf) = vbuf_append((vbuf), (data), (n));                     \
	} while (0)

/**
 * @brief Append literal string to vbuffer.
 * @param vbuf Must be a valid lvalue of type `struct vbuffer *`.
 * @see VBUF_APPEND
 * @details usage: `VBUF_APPENDSTR(vbuf, "some string");`
 */
#define VBUF_APPENDSTR(vbuf, str)                                              \
	do {                                                                   \
		VBUF_ASSERT_SANITY(vbuf);                                      \
		(vbuf) = vbuf_append(                                          \
			(vbuf), (const void *)("" str),                        \
			sizeof(str) - sizeof(""));                             \
	} while (0)

/**
 * @brief Append formatted string to vbuffer.
 * @param vbuf Must be a valid lvalue of type `struct vbuffer *`.
 * @see VBUF_APPEND
 * @return vsnprintf-style count; -1 if OOM was already recorded.
 * @details usage: `VBUF_APPENDF(vbuf, "%s: %s\r\n", "Content-Type", "text/plain");`
 */
#define VBUF_APPENDF(vbuf, format, ...)                                        \
	(VBUF_ASSERT_SANITY(vbuf),                                             \
	 vbuf_appendf((struct vbuffer **)&(vbuf), (format), __VA_ARGS__))

/**
 * @brief Append formatted string to vbuffer using a va_list.
 * @param vbuf Must be a valid lvalue of type `struct vbuffer *`.
 * @see VBUF_APPENDF
 * @return vsnprintf-style count; -1 if OOM was already recorded.
 * @details usage: `VBUF_VAPPENDF(vbuf, "%s: %s\r\n", args);`
 */
#define VBUF_VAPPENDF(vbuf, format, args)                                      \
	(VBUF_ASSERT_SANITY(vbuf),                                             \
	 vbuf_vappendf((struct vbuffer **)&(vbuf), (format), (args)))

/**
 * @brief Remove n bytes from the start of the vbuffer.
 * @param vbuf If NULL, the behavior is undefined.
 * @details usage: `VBUF_CONSUME(vbuf, sizeof(struct protocol_header));`
 */
#define VBUF_CONSUME(vbuf, n)                                                  \
	do {                                                                   \
		VBUF_ASSERT_LEAST(vbuf, (n));                                  \
		const unsigned char *b = (vbuf)->data;                         \
		(void)memmove((vbuf)->data, b + (n), (vbuf)->len - (n));       \
		(vbuf)->len -= (n);                                            \
	} while (0)

/**
 * @brief Tests whether two vbuffers have the same content.
 * @param vbuf If NULL, the behavior is undefined.
 * @details usage: `if(VBUF_EQUALS(vbuf_a, vbuf_b)) { ... }`
 */
#define VBUF_EQUALS(a, b)                                                      \
	(VBUF_ASSERT_SANITY(a), VBUF_ASSERT_SANITY(b),                         \
	 ((a)->len == (b)->len &&                                              \
	  memcmp((a)->data, (b)->data, (a)->len) == 0))

/** @} VBUF */

/** @} */

#endif /* UTILS_BUFFER_H */
