/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef IO_STREAM_H
#define IO_STREAM_H

#include "io.h"

#include <stddef.h>

/**
 * @defgroup stream
 * @brief Generic streaming IO interface for module decoupling.
 * @details Every error code here is 0 for OK or a positive `errno` value, never
 * a bare -1, so a caller can hand it to `strerror()` whichever backend produced
 * it. A stream with no `direct_read`, read or `write` slot reports the call as
 * `ENOTSUP`. The optional `flush` and `close` slots are not errors when
 * missing: `io_stream_flush` returns 0 and `io_stream_close` frees the stream.
 * @{
 */

struct io_stream_vftable {
	io_direct_reader direct_read;
	io_reader read;
	io_writer write;
	io_flusher flush;
	io_closer close;
};

struct io_stream {
	const struct io_stream_vftable *restrict vftable;
	void *data;
};

/**
 * @brief Read a stream directly from the internal buffer. (optional support)
 * @param[in] s The stream.
 * @param[out] buf Pointer to the internal buffer.
 * @param[inout] len Max length / returned length.
 * @return Error code, 0 for OK; `ENOTSUP` with `*len` set to 0 if the stream
 * has no direct_read slot.
 * @details Any output length > 0 should be considered normal.
 */
int io_stream_direct_read(struct io_stream *s, const void **buf, size_t *len);

/**
 * @brief Read from a stream.
 * @param[in] s The stream.
 * @param[out] buf The read buffer.
 * @param[inout] len Buffer size / returned length.
 * @return Error code, 0 for OK; `ENOTSUP` with `*len` set to 0 if the stream
 * has neither read slot.
 * @details The buffer should be filled up whenever possible.
 * Caller can assume short read as EOF or error.
 */
int io_stream_read(struct io_stream *s, void *buf, size_t *len);

/**
 * @brief Write to a stream.
 * @param[in] s The stream.
 * @param[in] buf Data to write.
 * @param[inout] len Data length / consumed length.
 * @return Error code, 0 for OK; `ENOTSUP` with `*len` set to 0 if the stream
 * has no write slot.
 * @details All data should be written whenever possible.
 * Caller can assume short write as error.
 */
int io_stream_write(struct io_stream *s, const void *buf, size_t *len);

/**
 * @brief Flush a stream.
 * @param[in] s The stream.
 * @return Error code, 0 for OK.
 * @details Base stream is flushed too. If error occurs,
 * stop flushing and return the error.
 */
int io_stream_flush(struct io_stream *s);

/**
 * @brief Close a stream.
 * @param[in] s The stream.
 * @return Error code, 0 for OK.
 * @details Base stream is closed too. If error occurs,
 * still close all resources and return the first error. A stream that installs
 * a `close` slot is released by that slot alone -- nothing is freed for it
 * here -- so whether the `struct io_stream` storage goes away is that
 * implementation's own contract; see `io_closer`.
 * @warning A stream whose vftable leaves `close` NULL is passed to `free()`
 * here, so such a stream must be a single `malloc`'d block whose address is
 * the `struct io_stream` itself -- which is what the `memory.h` constructors
 * return. An implementation whose stream is static, automatic, or embedded in
 * a larger object must install a `close` slot, even a do-nothing one, or this
 * call is undefined behavior.
 */
int io_stream_close(struct io_stream *s);

/**
 * @brief Copy all data from one stream to another.
 * @param[in] dst The destination stream.
 * @param[in] src The source stream.
 * @param[in] buf Buffer used for copy.
 * @param[in] bufsize Size of buffer in bytes. Must be nonzero; a zero size
 * caps every read at zero and is rejected with `EINVAL`.
 * @return Error code, 0 for OK. The first error either stream reports is
 * returned as is; a short write that `dst` reports with no error returns
 * `ENOSPC`.
 */
int io_stream_copy(
	struct io_stream *dst, struct io_stream *src, void *buf,
	size_t bufsize);

/** @} */

#endif /* IO_STREAM_H */
