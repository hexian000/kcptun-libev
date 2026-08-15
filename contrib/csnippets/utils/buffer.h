/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_BUFFER_H
#define UTILS_BUFFER_H

#include "meta/format.h"
#include "meta/minmax.h"

#include <assert.h>
#include <stdarg.h>
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
 * - The fixed `BUF_APPEND` raw-byte helper does not add a null terminator.
 *   The growable `VBUF_APPEND` and the formatting helpers keep data
 *   NUL-terminated in an internal reserved slot without affecting `len`.
 *   Every growable allocation, append and truncation therefore leaves
 *   `data[len]` NUL; only `VBUF_SPACE`, which hands out raw space, leaves
 *   restoring it to the caller.
 * - The formatting helpers use u8vsnprintf (strings/string.h):
 *   locale-independent and async-signal-safe, with its documented divergences
 *   from printf(3); truncation never splits a UTF-8 sequence.
 * - `BUF_*` and `VBUF_*` macros may evaluate some operands more than once, and
 *   the count can differ between debug and release builds because of
 *   assertions. Repeated operands must therefore have no side effects; store
 *   expressions such as `n++` in a temporary before calling
 *   `BUF_CONSUME` or `VBUF_APPEND`.
 * - None of the APIs are thread-safe; add external synchronization if shared.
 *
 * Error handling:
 * - Fixed buffers truncate to available space and report bytes transferred.
 * - Growable buffers attempt to expand; on allocation failure they append what
 *   fits and record an OOM condition. Further appends are skipped. Check with
 *   `VBUF_HAS_OOM`.
 * - A NULL vbuffer, which `VBUF_NEW` returns on allocation failure, is an OOM
 *   condition too: `VBUF_HAS_OOM` reports it, the append, format and resize
 *   macros skip it (the formatters return negative), `VBUF_RESERVE`
 *   allocates a new vbuffer from it, and `VBUF_FREE` accepts it. Every other
 *   VBUF_* macro requires a non-NULL vbuffer.
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
 * Do not instantiate directly; embed BUFFER_HDR and a concrete data[N] in
 * your own struct.
 * @details Such a struct is a distinct type, not compatible with this one
 * (C11 6.2.7), so it must not be accessed through a `struct buffer *`
 * (6.5p7). The BUF_* macros therefore hand the internal functions below the
 * buffer's members rather than a punned pointer to the whole object.
 */
struct buffer {
	BUFFER_HDR;
	unsigned char data[];
};

/* These internal functions should NOT be called directly, use macros instead */

/**
 * @internal
 * Append up to n bytes into a fixed buffer, given as its members: the
 * capacity, the length to advance, and the data region.
 * Copies min(n, cap - *len) bytes from src into data + *len.
 * Does not add a trailing NUL.
 * Returns: number of bytes actually appended (may be 0 if no space).
 */
static inline size_t buf_append(
	const size_t cap, size_t *restrict len, unsigned char *restrict data,
	const void *restrict src, size_t n)
{
	n = MIN(n, cap - *len);
	if (n == 0) {
		return 0;
	}
	(void)memcpy(data + *len, src, n);
	*len += n;
	return n;
}

/**
 * @internal
 * Append formatted text into a fixed buffer, given as its members (see
 * buf_append), using a va_list.
 * Writes at most remaining capacity; output is NUL-terminated in place.
 * *len is advanced by the bytes actually stored, which on truncation may fall
 * up to UTF8_MAX_LEN - 1 short of the capacity (whole codepoints only).
 * Returns: snprintf-style count of chars that would have been written
 * (excluding NUL), or negative when u8vsnprintf cannot represent that count,
 * in which case nothing is appended.
 */
int buf_vappendf(
	size_t cap, size_t *restrict len, unsigned char *restrict data,
	const char *restrict format, va_list args) FORMAT_PRINTF(4, 0);

/**
 * @internal
 * Convenience wrapper over buf_vappendf with variadic arguments.
 */
int buf_appendf(
	size_t cap, size_t *restrict len, unsigned char *restrict data,
	const char *restrict format, ...) FORMAT_PRINTF(4, 5);

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
 * - Writes the reserved NUL at the resulting len, so the module-wide
 *   NUL-termination invariant holds from allocation onwards.
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
	/* data holds cap + 1 bytes, so this slot always exists */
	vbuf->data[vbuf->len] = '\0';
	return vbuf;
}

/**
 * @internal
 * Ensure capacity is at least `want` bytes (not counting reserved NUL).
 * Uses a growth strategy tuned for small and large buffers, with overflow
 * checks. When vbuf == NULL, allocates a new object and writes the reserved
 * NUL as vbuf_alloc does. On failure, returns the original pointer unchanged.
 */
struct vbuffer *vbuf_grow(struct vbuffer *vbuf, size_t want);

/**
 * @internal
 * Append up to n bytes to a growable buffer.
 * Attempts to grow to fit; if growth fails, appends as much as possible.
 * Writes a trailing NUL in the reserved byte without affecting len.
 * If vbuf == NULL or len == cap (an OOM condition), append is skipped.
 */
struct vbuffer *
vbuf_append(struct vbuffer *restrict vbuf, const void *restrict data, size_t n);

/**
 * @internal
 * Append formatted text using a va_list. Two-pass attempt: write into
 * remaining capacity first, then grow and retry if needed. Keeps a trailing
 * NUL in the reserved byte. On failure, may truncate to what fits.
 * Skipped with a negative return when *pvbuf == NULL (an OOM condition).
 * pvbuf's pointee is restrict-qualified so that the address of a plain or a
 * restrict-qualified `struct vbuffer *` lvalue converts to it without a cast,
 * while the address of any other pointer type is diagnosed.
 * Returns vsnprintf-style count (chars that would have been written,
 * excluding NUL). A negative return means nothing was appended and the
 * vbuffer is unchanged: either OOM was already recorded, or u8vsnprintf could
 * not represent the count; `VBUF_HAS_OOM` tells the two apart.
 */
int vbuf_vappendf(
	struct vbuffer *restrict *pvbuf, const char *restrict format,
	va_list args) FORMAT_PRINTF(2, 0);

/**
 * @internal
 * Convenience wrapper over vbuf_vappendf with variadic arguments.
 */
int vbuf_appendf(
	struct vbuffer *restrict *pvbuf, const char *restrict format, ...)
	FORMAT_PRINTF(2, 3);

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
#define BUF_INIT(buf, n)                                                        \
	do {                                                                    \
		/* assert against sizeof directly (a named enum could collide \
		 * with the caller's `n`); the size_t cast keeps `n == 0` from \
		 * reading as a tautological sizeof comparison */ \
		static_assert(                                                  \
			(size_t)(n) <= sizeof((buf).data), "buffer overflow");  \
		(buf).cap = sizeof((buf).data);                                 \
		(buf).len = (n);                                                \
	} while (0)

/* Asserts cap > 0 and len within [0, cap]. */
#define BUF_ASSERT_SANITY(buf) assert((buf).cap > 0 && (buf).len <= (buf).cap)

/* Asserts at least n bytes of valid data reside in the buffer. */
#define BUF_ASSERT_LEAST(buf, n)                                               \
	assert((buf).cap > 0 && (n) <= (buf).len && (buf).len <= (buf).cap)

/**
 * @brief Bind a buffer handle to a literal string without copying.
 * @param buf Lvalue of type `struct buffer *` to receive the handle.
 * @details The buffer has static storage duration; its content must not be
 * modified.
 */
/* The literal is stored through the union's sized member and read back through
 * its `struct buffer` member: a union may be read through a member other than
 * the one last stored (C11 6.5.2.3p3), so the handle designates an object of
 * the type it is accessed as, and the bytes of the flexible array member are
 * the literal's own. */
#define BUF_CONST(buf, str)                                                      \
	do {                                                                     \
		static union {                                                   \
			struct buffer view;                                      \
			struct {                                                 \
				BUFFER_HDR;                                      \
				unsigned char data[sizeof(str)];                 \
			} literal;                                               \
		} literalbuf = {                                               \
			.literal = {                                           \
				.cap = sizeof(str) - 1,                        \
				.len = sizeof(str) - 1,                        \
				.data = str,                                   \
			},                                                     \
		}; \
		(buf) = &literalbuf.view;                                        \
	} while (0)

/**
 * @brief Append fixed-length data to buffer.
 * @details Data will be truncated if there is not enough space. No
 * NUL-terminator is added.
 * usage: `BUF_APPEND(buf, data, len);`
 */
#define BUF_APPEND(buf, src, n)                                                \
	do {                                                                   \
		BUF_ASSERT_SANITY(buf);                                        \
		buf_append((buf).cap, &(buf).len, (buf).data, (src), (n));     \
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
			(buf).cap, &(buf).len, (buf).data,                     \
			(const void *)("" str), sizeof(str) - 1u);             \
	} while (0)

/**
 * @brief Append formatted string to buffer.
 * @details The string will be truncated if there is not enough space. A
 * trailing NUL is written in-place but not counted by `len`.
 * usage: `BUF_APPENDF(buf, "%s: %s\r\n", "Content-Type", "text/plain");`
 */
#define BUF_APPENDF(buf, format, ...)                                          \
	(BUF_ASSERT_SANITY(buf),                                               \
	 buf_appendf((buf).cap, &(buf).len, (buf).data, (format), __VA_ARGS__))

/**
 * @brief Append formatted string to buffer using a va_list.
 * @details The string will be truncated if there is not enough space. A
 * trailing NUL is written in-place but not counted by `len`.
 * usage: `BUF_VAPPENDF(buf, "%s: %s\r\n", args);`
 */
#define BUF_VAPPENDF(buf, format, args)                                        \
	(BUF_ASSERT_SANITY(buf),                                               \
	 buf_vappendf((buf).cap, &(buf).len, (buf).data, (format), (args)))

/**
 * @brief Remove n bytes from the start of the buffer.
 * @details usage: `BUF_CONSUME(buf, sizeof(struct protocol_header));`
 */
#define BUF_CONSUME(buf, n)                                                    \
	do {                                                                   \
		BUF_ASSERT_LEAST(buf, (n));                                    \
		(void)memmove((buf).data, (buf).data + (n), (buf).len - (n));  \
		(buf).len -= (n);                                              \
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

/* Asserts vbuf is NULL (an OOM condition) or passes VBUF_ASSERT_SANITY. */
#define VBUF_ASSERT_SANITY_OR_NULL(vbuf)                                       \
	assert((vbuf) == NULL ||                                               \
	       ((vbuf)->cap > 0 && (vbuf)->len <= (vbuf)->cap))

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
 * @brief Test whether a previous operation on the vbuffer has failed due to
 * OOM.
 * @return true if OOM was detected, false otherwise.
 */
#define VBUF_HAS_OOM(vbuf)                                                     \
	((vbuf) == NULL ||                                                     \
	 (VBUF_ASSERT_SANITY(vbuf), (vbuf)->len == (vbuf)->cap))

/**
 * @brief Get raw pointer to the start of the buffered data.
 * @return Pointer to the buffered data, NUL-terminated at `VBUF_LEN`.
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
 * @brief Get a pointer and length view into the free space after the
 * vbuffer data.
 * @param b Lvalue to receive the pointer to the first writable byte.
 * @param n Lvalue to receive the number of writable bytes available.
 * @param vbuf The vbuffer to slice.
 * @details This is the write counterpart of VBUF_VIEW: where VBUF_VIEW exposes
 * existing data for reading, VBUF_SPACE exposes the unused tail for writing.
 * After writing n bytes via the returned pointer, advance len manually with
 * `(vbuf)->len += n`, then restore the terminator with
 * `(vbuf)->data[(vbuf)->len] = '\0'`.
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
 * The reserved NUL terminator is restored, preserving the module-wide
 * invariant that vbuffer data stays NUL-terminated; without it the cleared
 * buffer would still read back as the stale contents.
 */
#define VBUF_RESET(vbuf)                                                       \
	do {                                                                   \
		VBUF_ASSERT_SANITY(vbuf);                                      \
		(vbuf)->len = 0;                                               \
		(vbuf)->data[0] = '\0';                                        \
	} while (0)

/**
 * @brief Resize the vbuffer to the specified capacity.
 * @param vbuf Must be a valid lvalue of type `struct vbuffer *`; NULL is an
 * OOM condition, which the call skips.
 * @param want New capacity in bytes. If smaller than current length, data is
 * truncated.
 * @details On failure, the allocation remains unchanged. Skipped entirely once
 * an OOM condition is recorded (see `VBUF_HAS_OOM`), including a NULL vbuf,
 * so a resize cannot clear the marker while the data stays truncated; use
 * `VBUF_RESET` to clear it.
 * usage: `VBUF_RESIZE(vbuf, 1024);`
 */
#define VBUF_RESIZE(vbuf, want)                                                  \
	do {                                                                     \
		VBUF_ASSERT_SANITY_OR_NULL(vbuf);                                \
		/* An OOM condition is recorded as NULL or len == cap; a       \
		 * realloc here would clear the marker while the data stays    \
		 * truncated, so skip it, mirroring VBUF_RESERVE. */ \
		if ((vbuf) != NULL && (vbuf)->len != (vbuf)->cap &&              \
		    (want) < SIZE_MAX) {                                         \
			(vbuf) = vbuf_alloc((vbuf), (want) + 1);                 \
			if ((vbuf) != NULL) {                                    \
				(vbuf)->len = MIN((vbuf)->len, (want));          \
				/* truncating here drops len below the NUL \
				 * vbuf_alloc wrote, so restore it */     \
				(vbuf)->data[(vbuf)->len] = '\0';                \
			}                                                        \
		}                                                                \
	} while (0)

/**
 * @brief Prepare the vbuffer for specified number of bytes.
 * @param vbuf Must be a valid lvalue of type `struct vbuffer *`.
 * @param want Expected vbuffer capacity in bytes.
 * @details On failure, the allocation remains unchanged. Skipped entirely once
 * the OOM marker (`len == cap`) is set on an existing buffer, so the marker and
 * the truncated data are preserved; use `VBUF_RESET` to clear it.
 * usage: `VBUF_RESERVE(vbuf, 0);` (with want=0, shrinks the buffer to fit)
 */
#define VBUF_RESERVE(vbuf, want)                                                   \
	do {                                                                       \
		/* A SIZE_MAX reserve is unsatisfiable (target + 1 would wrap to \
		 * 0, the free-and-return-NULL shrink path); leave the allocation \
		 * unchanged, mirroring VBUF_RESIZE. */ \
		/* An OOM condition is recorded as len == cap, so any \
		 * reallocation here would silently clear the marker while the \
		 * data stays truncated. Skip instead, as vbuf_append and \
		 * vbuf_vappendf already do once OOM is set. */            \
		if (((vbuf) == NULL || (vbuf)->len != (vbuf)->cap) &&              \
		    (want) < SIZE_MAX) {                                           \
			const size_t len_ =                                        \
				((vbuf) != NULL) ? (vbuf)->len : 0;                \
			const size_t cap_ =                                        \
				((vbuf) != NULL) ? (vbuf)->cap : 1;                \
			/* A reserve only grows: keep at least `want` usable \
			 * bytes without shrinking below the current capacity \
			 * (use VBUF_RESIZE to shrink). want == 0 is the \
			 * documented shrink-to-fit. MAX((want), ...) keeps \
			 * `want` first so a literal 0 does not trip \
			 * -Wtype-limits. */     \
			const size_t target_ =                                     \
				((want) != 0) ? MAX((want), cap_ - 1) : len_;      \
			(vbuf) = vbuf_alloc((vbuf), target_ + 1);                  \
		}                                                                  \
	} while (0)

/**
 * @brief Append fixed-length data to vbuffer.
 * @param vbuf Must be a valid lvalue of type `struct vbuffer *`; NULL is an
 * OOM condition, which the call skips.
 * @details vbuf will be expanded if there is not enough space. On allocation
 * failure, data is truncated and OOM is set; check with `VBUF_HAS_OOM`.
 * Skipped once OOM is set.
 * usage: `VBUF_APPEND(vbuf, data, len);`
 */
#define VBUF_APPEND(vbuf, data, n)                                             \
	do {                                                                   \
		VBUF_ASSERT_SANITY_OR_NULL(vbuf);                              \
		(vbuf) = vbuf_append((vbuf), (data), (n));                     \
	} while (0)

/**
 * @brief Append literal string to vbuffer.
 * @param vbuf Must be a valid lvalue of type `struct vbuffer *`; NULL is an
 * OOM condition, which the call skips.
 * @see VBUF_APPEND
 * @details usage: `VBUF_APPENDSTR(vbuf, "some string");`
 */
#define VBUF_APPENDSTR(vbuf, str)                                              \
	do {                                                                   \
		VBUF_ASSERT_SANITY_OR_NULL(vbuf);                              \
		(vbuf) = vbuf_append(                                          \
			(vbuf), (const void *)("" str),                        \
			sizeof(str) - sizeof(""));                             \
	} while (0)

/**
 * @brief Append formatted string to vbuffer.
 * @param vbuf Must be a valid lvalue of type `struct vbuffer *`; NULL is an
 * OOM condition, which the call skips.
 * @see VBUF_APPEND
 * @return vsnprintf-style count; negative if nothing was appended.
 * @details usage: `VBUF_APPENDF(vbuf, "%s: %s\r\n", "Content-Type", "text/plain");`
 */
#define VBUF_APPENDF(vbuf, format, ...)                                        \
	(VBUF_ASSERT_SANITY_OR_NULL(vbuf),                                     \
	 vbuf_appendf(&(vbuf), (format), __VA_ARGS__))

/**
 * @brief Append formatted string to vbuffer using a va_list.
 * @param vbuf Must be a valid lvalue of type `struct vbuffer *`; NULL is an
 * OOM condition, which the call skips.
 * @see VBUF_APPENDF
 * @return vsnprintf-style count; negative if nothing was appended.
 * @details usage: `VBUF_VAPPENDF(vbuf, "%s: %s\r\n", args);`
 */
#define VBUF_VAPPENDF(vbuf, format, args)                                      \
	(VBUF_ASSERT_SANITY_OR_NULL(vbuf),                                     \
	 vbuf_vappendf(&(vbuf), (format), (args)))

/**
 * @brief Remove n bytes from the start of the vbuffer.
 * @param vbuf If NULL, the behavior is undefined.
 * @details usage: `VBUF_CONSUME(vbuf, sizeof(struct protocol_header));`
 * The reserved NUL terminator is restored at the new length, preserving the
 * module-wide invariant that vbuffer data stays NUL-terminated.
 */
#define VBUF_CONSUME(vbuf, n)                                                  \
	do {                                                                   \
		VBUF_ASSERT_LEAST(vbuf, (n));                                  \
		(void)memmove(                                                 \
			(vbuf)->data, (vbuf)->data + (n), (vbuf)->len - (n));  \
		(vbuf)->len -= (n);                                            \
		(vbuf)->data[(vbuf)->len] = '\0';                              \
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
