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

/** @} */

#endif /* IO_FILE_H */
