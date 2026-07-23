/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef IO_STREAM_H
#define IO_STREAM_H

#include "io.h"

#include <stddef.h>

/**
 * @defgroup stream
 * @brief Generic streaming IO interface for module decoupling.
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
 * @return Error code, 0 for OK.
 * @details Any output length > 0 should be considered normal.
 */
int io_stream_direct_read(struct io_stream *s, const void **buf, size_t *len);

/**
 * @brief Read from a stream.
 * @param[in] s The stream.
 * @param[out] buf The read buffer.
 * @param[inout] len Buffer size / returned length.
 * @return Error code, 0 for OK.
 * @details The buffer should be filled up whenever possible.
 * Caller can assume short read as EOF or error.
 */
int io_stream_read(struct io_stream *s, void *buf, size_t *len);

/**
 * @brief Write to a stream.
 * @param[in] s The stream.
 * @param[in] buf Data to write.
 * @param[inout] len Data length / consumed length.
 * @return Error code, 0 for OK.
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
 * still close all resources and return the first error.
 */
int io_stream_close(struct io_stream *s);

/**
 * @brief Copy all data from one stream to another.
 * @param[in] dst The destination stream.
 * @param[in] src The source stream.
 * @param[in] buf Buffer used for copy.
 * @param[in] bufsize Size of buffer in bytes.
 * @return Error code, 0 for OK.
 */
int io_stream_copy(
	struct io_stream *dst, struct io_stream *src, void *buf,
	size_t bufsize);

/** @} */

#endif /* IO_STREAM_H */
