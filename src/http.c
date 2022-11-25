#include "http.h"
#include "util.h"

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
	{ HTTP_OK, "OK", "" },
	{ HTTP_MOVED_TEMPORARILY, "Found", "" },
	{ HTTP_REQUEST_TIMEOUT, "Request Timeout",
	  "No request appeared within timeout" },
	{ HTTP_NOT_IMPLEMENTED, "Not Implemented",
	  "The requested method is not recognized" },
	{ HTTP_NOT_FOUND, "Not Found", "The requested URL was not found" },
	{ HTTP_BAD_REQUEST, "Bad Request", "Unsupported method" },
	{ HTTP_FORBIDDEN, "Forbidden", "" },
	{ HTTP_INTERNAL_SERVER_ERROR, "Internal Server Error",
	  "Internal Server Error" },
	{ HTTP_ENTITY_TOO_LARGE, "Entity Too Large", "Entity Too Large" },
};

size_t http_peek(const char *buf, const size_t len)
{
	unsigned lf = 0;
	for (size_t i = 0; i < len; i++) {
		switch (buf[i]) {
		case '\r':
			break;
		case '\n':
			lf++;
			break;
		default:
			lf = 0;
			break;
		}
		if (lf == 2) {
			return i + 1;
		}
	}
	return 0;
}

static char *skip_whitespace(char *s)
{
	while (*s == ' ' || *s == '\t') {
		++s;
	}
	return s;
}

char *http_parse(char *buf, struct http_header *restrict hdr)
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
	*hdr = (struct http_header){
		.field1 = field1,
		.field2 = field2,
		.field3 = field3,
	};
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
	/* RFC 1123: Section 5.2.14 */
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

size_t http_error(char *buf, size_t buf_size, const uint16_t code)
{
	const char *name = NULL, *info = NULL;
	for (size_t i = 0; i < ARRAY_SIZE(http_resp); i++) {
		if (http_resp[i].code == code) {
			name = http_resp[i].name;
			info = http_resp[i].info;
			break;
		}
	}
	if (name == NULL) {
		return 0;
	}
	char date_str[32];
	const size_t date_len = http_date(date_str, sizeof(date_str));
	const int ret = snprintf(
		buf, buf_size,
		"HTTP/1.0 %" PRIu16 " %s\r\n"
		"Date: %*s\r\n"
		"Connection: close\r\n"
		"Content-type: text/html\r\n\r\n"
		"<HTML><HEAD><TITLE>%" PRIu16 " %s</TITLE></HEAD>\n"
		"<BODY><H1>%" PRIu16 " %s</H1>\n"
		"%s\n"
		"</BODY></HTML>\n",
		code, name, (int)date_len, date_str, code, name, code, name,
		info);
	return ret > 0 ? ret : 0;
}
