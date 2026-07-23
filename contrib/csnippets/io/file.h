/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef IO_FILE_H
#define IO_FILE_H

#include "stream.h"

#include <stdbool.h>
#include <stdio.h>

/**
 * @defgroup file
 * @brief File I/O utilities.
 * @{
 */

/**
 * @brief Create reader from a file object.
 * @param[in] f Transfer ownership of the file object.
 * @return If malloc failed or f == NULL, returns NULL.
 * @details The stream is unbuffered.
 */
struct io_stream *io_filereader(FILE *f);

/**
 * @brief Create writer from a file object.
 * @param[in] f Transfer ownership of the file object.
 * @return If malloc failed or f == NULL, returns NULL.
 * @details The stream is unbuffered.
 */
struct io_stream *io_filewriter(FILE *f);

/**
 * @brief Read the entire file into memory.
 * @param[in] path The file path to read.
 * @param[in,out] len On input, the buffer capacity including the null
 *                    terminator; on output, the number of data bytes
 *                    read; on error, unchanged.
 * @return A null-terminated buffer containing `*len` bytes of data,
 *         which the caller must free. NULL on error.
 * @details Never truncates: if the data is too large, the function
 *          returns NULL.
 */
unsigned char *io_readfile(const char *restrict path, size_t *restrict len);

/**
 * @brief Write data to a file.
 * @param[in] path The file path to write to.
 * @param[in] data The data to write.
 * @param[in,out] len On input, the number of bytes to write; on output, the number of bytes actually written.
 * @return true on success, false on error.
 */
bool io_writefile(
	const char *restrict path, const unsigned char *restrict data,
	size_t *restrict len);

/**
 * @brief Read UTF-8 text data, handling the byte order mark (BOM).
 * @param[in] data The data buffer (passed by value; the BOM-adjusted pointer
 *            is returned, not written back through this parameter).
 * @param[in,out] len The length of the data; adjusted for BOM removal.
 * @return A pointer to the UTF-8 text content, or NULL if the data starts with
 *         a UTF-16 or UTF-32 BOM (unsupported encodings).
 * @note Only UTF-8 is supported: a leading UTF-8 BOM (EF BB BF) is stripped,
 *       and any UTF-16/UTF-32 BOM causes a NULL return. Data without a BOM is
 *       assumed to be UTF-8 and returned as-is.
 */
const char *
io_readutf8(const unsigned char *restrict data, size_t *restrict len);

/** @} */

#endif /* IO_FILE_H */
