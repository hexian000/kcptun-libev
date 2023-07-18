/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http.h"
#include "utils/arraysize.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

static const struct {
	const uint16_t code;
	const char *name;
	const char *info;
} http_resp[] = {
	{ HTTP_CONTINUE, "Continue", NULL },
	{ HTTP_OK, "OK", NULL },
	{ HTTP_CREATED, "Created", NULL },
	{ HTTP_ACCEPTED, "Accepted", NULL },
	{ HTTP_NO_CONTENT, "No Content", NULL },
	{ HTTP_MOVED_PERMANENTLY, "Moved Permanently", NULL },
	{ HTTP_FOUND, "Found", NULL },
	{ HTTP_NOT_MODIFIED, "Not Modified", NULL },
	{ HTTP_REQUEST_TIMEOUT, "Request Timeout",
	  "Server timeout waiting for the HTTP request from the client." },
	{ HTTP_NOT_IMPLEMENTED, "Not Implemented",
	  "The requested method is not supported for current URL." },
	{ HTTP_NOT_FOUND, "Not Found",
	  "The requested URL was not found on this server." },
	{ HTTP_METHOD_NOT_ALLOWED, "Method Not Allowed",
	  "The requested method is not allowed for this URL." },
	{ HTTP_BAD_REQUEST, "Bad Request",
	  "Your browser sent a request that this server could not understand." },
	{ HTTP_FORBIDDEN, "Forbidden",
	  "You don't have permission to access this resource." },
	{ HTTP_INTERNAL_SERVER_ERROR, "Internal Server Error",
	  "The server encountered an internal error." },
	{ HTTP_ENTITY_TOO_LARGE, "Content Too Large",
	  "The amount of data provided in the request exceeds the capacity limit." },
	{ HTTP_BAD_GATEWAY, "Bad Gateway",
	  "The proxy server received an invalid response from an upstream server." },
	{ HTTP_GATEWAY_TIMEOUT, "Gateway Timeout",
	  "The gateway did not receive a timely response from the upstream server or application." },
};

static char *skip_whitespace(char *s)
{
	while (*s == ' ' || *s == '\t') {
		++s;
	}
	return s;
}

char *http_parse(char *buf, struct http_message *restrict msg)
{
	char *next = strstr(buf, "\r\n");
	if (next == NULL) {
		return buf;
	}
	next[0] = next[1] = '\0';
	next += 2; /* skip crlf */

	char *field1 = buf;

	char *field2 = strchr(field1, ' ');
	if (field2 == NULL) {
		return NULL;
	}
	field2++;

	char *field3 = strchr(field2, ' ');
	if (field3 == NULL) {
		return NULL;
	}
	field3++;

	/* break tokens */
	field2[-1] = field3[-1] = '\0';
	msg->any.field1 = field1;
	msg->any.field2 = field2;
	msg->any.field3 = field3;
	return next;
}

char *http_parsehdr(char *buf, char **key, char **value)
{
	char *next = strstr(buf, "\r\n");
	if (next == NULL) {
		return buf;
	}
	next[0] = next[1] = '\0';
	next += 2; /* skip crlf */

	if (buf + 2 == next) {
		/* EOF */
		*key = *value = NULL;
		return next;
	}

	char *v = strchr(buf, ':');
	if (v == NULL) {
		return NULL;
	}
	*v = '\0';
	v = skip_whitespace(v + 1);
	*key = buf, *value = v;
	return next;
}

size_t http_date(char *buf, const size_t buf_size)
{
	/* RFC 7231: Section 7.1.1.1 */
	static const char fmt[] = "%a, %d %b %Y %H:%M:%S GMT";
	const time_t now = time(NULL);
	const struct tm *gmt = gmtime(&now);
	return strftime(buf, buf_size, fmt, gmt);
}

const char *http_status(const uint16_t code)
{
	for (size_t i = 0; i < ARRAY_SIZE(http_resp); i++) {
		if (http_resp[i].code == code) {
			return http_resp[i].name;
		}
	}
	return NULL;
}

int http_error(char *buf, size_t buf_size, const uint16_t code)
{
	const char *name = NULL, *info = NULL;
	for (size_t i = 0; i < ARRAY_SIZE(http_resp); i++) {
		if (http_resp[i].code != code) {
			continue;
		}
		name = http_resp[i].name;
		info = http_resp[i].info;
		if (info == NULL) {
			info = name;
		}
		break;
	}
	if (name == NULL) {
		return 0;
	}
	char date_str[32];
	const size_t date_len = http_date(date_str, sizeof(date_str));
	return snprintf(
		buf, buf_size,
		"HTTP/1.1 %" PRIu16 " %s\r\n"
		"Date: %.*s\r\n"
		"Connection: close\r\n"
		"Content-type: text/html\r\n\r\n"
		"<HTML><HEAD><TITLE>%" PRIu16 " %s</TITLE></HEAD>\n"
		"<BODY><H1>%" PRIu16 " %s</H1>\n"
		"%s\n"
		"</BODY></HTML>\n",
		code, name, (int)date_len, date_str, code, name, code, name,
		info);
}
