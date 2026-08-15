/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef NET_HTTP_H
#define NET_HTTP_H

#include <stddef.h>
#include <stdint.h>

/**
 * @defgroup http
 * @brief RFC 9110: HTTP Semantics, RFC 9112: HTTP/1.1
 * @details Status codes, the token grammar and the date format follow
 * RFC 9110; the message syntax the parsers accept follows RFC 9112. These
 * obsolete RFC 7230 and RFC 7231.
 * @{
 */

enum http_status_code {
	HTTP_CONTINUE = 100,
	HTTP_SWITCHING_PROTOCOLS = 101,

	HTTP_OK = 200,
	HTTP_CREATED = 201,
	HTTP_ACCEPTED = 202,
	HTTP_NON_AUTHORITATIVE_INFORMATION = 203,
	HTTP_NO_CONTENT = 204,
	HTTP_RESET_CONTENT = 205,
	HTTP_PARTIAL_CONTENT = 206,

	HTTP_MULTIPLE_CHOICES = 300,
	HTTP_MOVED_PERMANENTLY = 301,
	HTTP_FOUND = 302,
	HTTP_SEE_OTHER = 303,
	HTTP_NOT_MODIFIED = 304,
	HTTP_USE_PROXY = 305, /* deprecated */
	HTTP_TEMPORARY_REDIRECT = 307,
	HTTP_PERMANENT_REDIRECT = 308,

	HTTP_BAD_REQUEST = 400,
	HTTP_UNAUTHORIZED = 401,
	HTTP_PAYMENT_REQUIRED = 402,
	HTTP_FORBIDDEN = 403,
	HTTP_NOT_FOUND = 404,
	HTTP_METHOD_NOT_ALLOWED = 405,
	HTTP_NOT_ACCEPTABLE = 406,
	HTTP_PROXY_AUTHENTICATION_REQUIRED = 407,
	HTTP_REQUEST_TIMEOUT = 408,
	HTTP_CONFLICT = 409,
	HTTP_GONE = 410,
	HTTP_LENGTH_REQUIRED = 411,
	HTTP_PRECONDITION_FAILED = 412,
	HTTP_ENTITY_TOO_LARGE = 413,
	HTTP_URI_TOO_LONG = 414,
	HTTP_UNSUPPORTED_MEDIA_TYPE = 415,
	HTTP_RANGE_NOT_SATISFIABLE = 416,
	HTTP_EXPECTATION_FAILED = 417,
	HTTP_MISDIRECTED_REQUEST = 421,
	HTTP_UNPROCESSABLE_CONTENT = 422,
	HTTP_TOO_EARLY = 425,
	HTTP_UPGRADE_REQUIRED = 426,
	HTTP_PRECONDITION_REQUIRED = 428,
	HTTP_TOO_MANY_REQUESTS = 429,
	HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE = 431,
	HTTP_UNAVAILABLE_FOR_LEGAL_REASONS = 451,

	HTTP_INTERNAL_SERVER_ERROR = 500,
	HTTP_NOT_IMPLEMENTED = 501,
	HTTP_BAD_GATEWAY = 502,
	HTTP_SERVICE_UNAVAILABLE = 503,
	HTTP_GATEWAY_TIMEOUT = 504,
	HTTP_VERSION_NOT_SUPPORTED = 505,
	HTTP_NETWORK_AUTHENTICATION_REQUIRED = 511,
};

/* http_parse() always fills .any; access as .req or .rsp once the
 * message kind is known from context. */
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
 * @param[inout] buf Raw message buffer.
 * @param[out] msg Parsed header fields.
 * Empty lines (CRLF) before the start line are skipped, as RFC 9112 Section
 * 2.2 asks of a server.
 * @return The start position of next parsing, or NULL when parsing failed.
 * If the position is not moved, wait for more data.
 */
char *http_parse(char *restrict buf, struct http_message *restrict msg);

/**
 * @brief Parse a HTTP header line.
 * @details No allocations, the raw message until next position is destructed.
 * @param[inout] buf HTTP header line start, usually the return value of http_parse.
 * @param[out] key Header key, or NULL when HTTP header ends.
 * @param[out] value Header value, or NULL when HTTP header ends.
 * @return The start position of next parsing, or NULL when parsing failed.
 * If the position is not moved, wait for more data.
 */
char *
http_parsehdr(char *restrict buf, char **restrict key, char **restrict value);

/**
 * @brief Get the name of a HTTP status code.
 * @param code HTTP status code
 * @return Name of HTTP status code, or NULL when failed.
 * @see enum http_status_code
 */
const char *http_status(uint_fast16_t code);

/**
 * @brief Generate a date string in IMF-fixdate format.
 * @details Renders the current time, e.g. "Sun, 06 Nov 1994 08:49:37 GMT".
 * @param[out] buf string buffer
 * @param buf_size size of string buffer, at least 30 bytes
 * @return Length of the generated string (always 29), or 0 on failure,
 * leaving the buffer unspecified. Failure means either @p buf_size is too
 * small, or the current time has no IMF-fixdate rendering -- the platform
 * cannot convert it to broken-down UTC, or the year falls outside the 4 digits
 * RFC 9110 Section 5.6.7 admits. A larger buffer therefore does not always
 * help; a caller that must emit Date has to be prepared to omit it.
 * @see http_error
 */
size_t http_date(char *restrict buf, size_t buf_size);

/**
 * @brief Generate an error response.
 * @param[out] buf string buffer
 * @param buf_size size of string buffer
 * @param code HTTP status code
 * @return snprintf result, or 0 if the code is unknown or its response
 * cannot carry content: 1xx, 204, 205 and 304 (RFC 9110 Section 15).
 * @see enum http_status_code
 */
int http_error(char *restrict buf, size_t buf_size, uint_fast16_t code);

/** @} */

#endif /* NET_HTTP_H */
