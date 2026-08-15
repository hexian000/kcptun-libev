/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef IO_IO_H
#define IO_IO_H

#include <stddef.h>

#define IO_BUFSIZE 4096

/**
 * @defgroup io
 * @brief Backend interface behind `struct io_stream`.
 * @details Each callback below receives the `struct io_stream *` it was
 * invoked on, never `s->data`. `data` is the implementation's own slot and is
 * never read or written by the interface, so an implementation recovers its
 * state either from `s->data`, or by making `struct io_stream` the first
 * member of its own struct and casting the argument to that struct.
 *
 * Each callback's error code is 0 for OK or a positive `errno` value -- the
 * one the failing call reported, or the code that names the condition (for
 * example `ENOMEM`, `ENOSPC`, or `EIO` when the failure carries no errno) --
 * never a bare -1.
 * @{
 */

/**
 * @brief Hand out readable bytes without copying them into a caller buffer.
 * @param[in] s The stream.
 * @param[out] buf The bytes, valid until the next call on this stream.
 * Unspecified when `*len` is 0.
 * @param[inout] len Max requested / returned length. 0 marks EOF.
 * @return Error code, 0 for OK.
 */
typedef int (*io_direct_reader)(void *s, const void **buf, size_t *len);

/**
 * @brief Read into the caller's buffer.
 * @param[in] s The stream.
 * @param[out] buf The read buffer.
 * @param[inout] len Buffer size / returned length, set on failure too.
 * @return Error code, 0 for OK.
 * @details Fill the buffer whenever possible: a short return is read as EOF
 * or error.
 */
typedef int (*io_reader)(void *s, void *buf, size_t *len);

/**
 * @brief Write from the caller's buffer.
 * @param[in] s The stream.
 * @param[in] buf Data to write.
 * @param[inout] len Data length / consumed length, set on failure too.
 * @return Error code, 0 for OK.
 * @details Write all data whenever possible: a short return is read as an
 * error.
 */
typedef int (*io_writer)(void *s, const void *buf, size_t *len);

/**
 * @brief Push buffered data to the underlying sink. (optional support)
 * @param[in] s The stream.
 * @return Error code, 0 for OK.
 * @details Flushes the base stream too, if any.
 */
typedef int (*io_flusher)(void *s);

/**
 * @brief Close the stream and release what it owns. (optional support)
 * @param[in] s The stream.
 * @return Error code, 0 for OK.
 * @details `io_stream_close` calls this slot and does nothing afterwards, so
 * the release is the slot's alone: it closes the base stream, if any, and
 * frees the storage the `struct io_stream` lives in when the implementation
 * owns that storage -- which is the enclosing struct, not the
 * `struct io_stream` alone, wherever the stream is embedded in one. An
 * implementation whose storage is not its own to free -- static, automatic,
 * or embedded in a longer-lived object -- frees nothing here, yet still
 * installs the slot, even a do-nothing one: leaving it NULL makes
 * `io_stream_close` free the stream instead -- see its `@warning`.
 */
typedef int (*io_closer)(void *s);

/** @} */

#endif /* IO_IO_H */
