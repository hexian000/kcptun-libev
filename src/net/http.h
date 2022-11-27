/* csnippets (c) 2019-2022 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef HTTP_H
#define HTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum http_status_code {
	HTTP_OK = 200,
	HTTP_MOVED_TEMPORARILY = 302,
	HTTP_BAD_REQUEST = 400,
	HTTP_FORBIDDEN = 403,
	HTTP_NOT_FOUND = 404,
	HTTP_REQUEST_TIMEOUT = 408,
	HTTP_ENTITY_TOO_LARGE = 413,
	HTTP_INTERNAL_SERVER_ERROR = 500,
	HTTP_NOT_IMPLEMENTED = 501,
};

struct http_header {
	char *field1;
	char *field2;
	char *field3;
};

/**
 * @brief Parse a HTTP request/response line.
 * @param buf Raw message buffer.
 * @param hdr [OUT] Parsed header fields.
 * @details No allocations, raw message is destructed.
 * @return The start position of next parsing, or NULL when error occurs.
 */
char *http_parse(char *buf, struct http_header *hdr);

/**
 * @brief Parse HTTP header.
 * @param buf HTTP header line start.
 * @param key [OUT] Header key, or NULL when message finished.
 * @param value [OUT] Header value, or NULL when message finished.
 * @details No allocations, raw message is destructed.
 * @return The start position of next parsing, or NULL when error occurs.
 */
char *http_parsehdr(char *buf, char **key, char **value);

/**
 * @brief Get the name of a HTTP status code.
 * @param code HTTP status code
 * @return Name of HTTP status code, or NULL when failed.
 */
const char *http_status(uint16_t code);

/**
 * @brief Generate a date string in RFC 1123 format.
 * @param buf [OUT] string buffer
 * @param buf_size size of string buffer
 * @return Length of the generated string, or 0 when failed.
 */
size_t http_date(char *buf, size_t buf_size);

/**
 * @brief Generate an error response.
 * @param buf [OUT] string buffer
 * @param buf_size size of string buffer
 * @param code HTTP status code
 * @return Length of the generated response, or 0 when failed.
 */
size_t http_error(char *buf, size_t buf_size, uint16_t code);

#endif /* HTTP_H */
