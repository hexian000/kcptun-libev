/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
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

struct http_message {
	union {
		struct {
			char *field1;
			char *field2;
			char *field3;
		} any;
		struct {
			char *method;
			char *url;
			char *version;
		} req;
		struct {
			char *version;
			char *code;
			char *status;
		} rsp;
	};
};

/**
 * @brief Parse a HTTP request/response line.
 * @details No allocations, the raw message until next position is destructed.
 * @param buf Raw message buffer.
 * @param msg [OUT] Parsed header fields.
 * @return The start position of next parsing, or NULL when parsing failed.
 * If the position is not moved, wait for more data.
 */
char *http_parse(char *buf, struct http_message *msg);

/**
 * @brief Parse a HTTP header line.
 * @details No allocations, the raw message until next position is destructed.
 * @param buf HTTP header line start.
 * @param key [OUT] Header key, or NULL when HTTP header ends.
 * @param value [OUT] Header value, or NULL when HTTP header ends.
 * @return The start position of next parsing, or NULL when parsing failed.
 * If the position is not moved, wait for more data.
 */
char *http_parsehdr(char *buf, char **key, char **value);

/**
 * @brief Get the name of a HTTP status code.
 * @param code HTTP status code
 * @return Name of HTTP status code, or NULL when failed.
 * @see enum http_status_code
 */
const char *http_status(uint16_t code);

/**
 * @brief Generate a date string in RFC 1123 format.
 * @param buf [OUT] string buffer
 * @param buf_size size of string buffer
 * @return Length of the generated string.
 */
size_t http_date(char *buf, size_t buf_size);

/**
 * @brief Generate an error response.
 * @param buf [OUT] string buffer
 * @param buf_size size of string buffer
 * @param code HTTP status code
 * @return Length of the generated response, or 0 if the code is unknown.
 * @see enum http_status_code
 */
size_t http_error(char *buf, size_t buf_size, uint16_t code);

#endif /* HTTP_H */
