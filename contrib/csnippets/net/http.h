/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef NET_HTTP_H
#define NET_HTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @defgroup http
 * @brief RFC 7231: Hypertext Transfer Protocol (HTTP/1.1)
 * @{
 */

enum http_status_code {
	HTTP_CONTINUE = 100,
	HTTP_OK = 200,
	HTTP_CREATED = 201,
	HTTP_ACCEPTED = 202,
	HTTP_NO_CONTENT = 204,
	HTTP_MOVED_PERMANENTLY = 301,
	HTTP_FOUND = 302,
	HTTP_NOT_MODIFIED = 304,
	HTTP_BAD_REQUEST = 400,
	HTTP_FORBIDDEN = 403,
	HTTP_NOT_FOUND = 404,
	HTTP_METHOD_NOT_ALLOWED = 405,
	HTTP_REQUEST_TIMEOUT = 408,
	HTTP_LENGTH_REQUIRED = 411,
	HTTP_ENTITY_TOO_LARGE = 413,
	HTTP_UNSUPPORTED_MEDIA_TYPE = 415,
	HTTP_EXPECTATION_FAILED = 417,
	HTTP_INTERNAL_SERVER_ERROR = 500,
	HTTP_NOT_IMPLEMENTED = 501,
	HTTP_BAD_GATEWAY = 502,
	HTTP_GATEWAY_TIMEOUT = 504,
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
 * @param[out] msg Parsed header fields.
 * @return The start position of next parsing, or NULL when parsing failed.
 * If the position is not moved, wait for more data.
 */
char *http_parse(char *buf, struct http_message *msg);

/**
 * @brief Parse a HTTP header line.
 * @details No allocations, the raw message until next position is destructed.
 * @param buf HTTP header line start, usually the return value of http_parse.
 * @param[out] key Header key, or NULL when HTTP header ends.
 * @param[out] value Header value, or NULL when HTTP header ends.
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
 * @brief Generate a date string in IMF-fixdate format.
 * @param[out] buf string buffer
 * @param buf_size size of string buffer
 * @return Length of the generated string.
 */
size_t http_date(char *buf, size_t buf_size);

/**
 * @brief Generate an error response.
 * @param[out] buf string buffer
 * @param buf_size size of string buffer
 * @param code HTTP status code
 * @return snprintf result, or 0 if the code is unknown.
 * @see enum http_status_code
 */
int http_error(char *buf, size_t buf_size, uint16_t code);

/** @} */

#endif /* NET_HTTP_H */
