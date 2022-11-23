#ifndef HTTP_H
#define HTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum http_status_code {
	HTTP_OK = 200,
	HTTP_MOVED_TEMPORARILY = 302,
	HTTP_BAD_REQUEST = 400,
	HTTP_NOT_FOUND = 404,
	HTTP_FORBIDDEN = 403,
	HTTP_ENTITY_TOO_LARGE = 413,
	HTTP_REQUEST_TIMEOUT = 408,
	HTTP_NOT_IMPLEMENTED = 501,
	HTTP_INTERNAL_SERVER_ERROR = 500,
};

struct http_header {
	char *field1;
	char *field2;
	char *field3;
};

typedef void (*http_header_cb)(
	const struct http_header *hdr, const char *key, const char *value,
	void *user);

/**
 * @brief Check if there is a full request or response.
 * @param buf HTTP message buffer.
 * @param len Length of available data.
 * @return Length of the whole HTTP header, or 0 when failed.
 */
size_t http_peek(const char *buf, size_t len);

/**
 * @brief Parse a known full request or response.
 * @param buf HTTP message buffer.
 * @param hdr [OUT] parse result.
 * @param cb Callback for handling HTTP headers.
 * @param user User defined data, passed to callback.
 * @warning [UNCHECKED] User shall perform a successful peek first.
 * @warning [DESTRUCTIVE] Regardless of whether parsing is successful or not,
 * the raw string of the request or response is destructed.
 * @warning [PARTIAL] Before returning fail, callback may be invoked.
 * @return Length of the parsed data, or 0 when failed.
 */
size_t
http_parse(char *buf, struct http_header *hdr, http_header_cb cb, void *user);

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
