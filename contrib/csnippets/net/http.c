/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http.h"

#include "meta/arraysize.h"
#include "utils/ascii.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct http_status_info {
	uint_least16_t code;
	const char *name;
	const char *desc;
};

/* sorted by code for binary search, keep this order */
static const struct http_status_info http_resp[] = {
	{ HTTP_CONTINUE, "Continue", NULL },

	{ HTTP_OK, "OK", NULL },
	{ HTTP_CREATED, "Created", NULL },
	{ HTTP_ACCEPTED, "Accepted", NULL },
	{ HTTP_NO_CONTENT, "No Content", NULL },
	{ HTTP_PARTIAL_CONTENT, "Partial Content", NULL },

	{ HTTP_MOVED_PERMANENTLY, "Moved Permanently", NULL },
	{ HTTP_FOUND, "Found", NULL },
	{ HTTP_NOT_MODIFIED, "Not Modified", NULL },

	{ HTTP_BAD_REQUEST, "Bad Request",
	  "Your browser sent a request that this server could not understand." },
	{ HTTP_UNAUTHORIZED, "Unauthorized",
	  "This server could not verify that you are authorized to access the document requested." },
	{ HTTP_FORBIDDEN, "Forbidden",
	  "You don't have permission to access this resource." },
	{ HTTP_NOT_FOUND, "Not Found",
	  "The requested URL was not found on this server." },
	{ HTTP_METHOD_NOT_ALLOWED, "Method Not Allowed",
	  "The requested method is not allowed for this URL." },
	{ HTTP_PROXY_AUTHENTICATION_REQUIRED, "Proxy Authentication Required",
	  NULL },
	{ HTTP_REQUEST_TIMEOUT, "Request Timeout",
	  "Server timeout waiting for the HTTP request from the client." },
	{ HTTP_LENGTH_REQUIRED, "Length Required",
	  "A request of the requested method requires a valid Content-Length." },
	{ HTTP_ENTITY_TOO_LARGE, "Content Too Large",
	  "The amount of data provided in the request exceeds the capacity limit." },
	{ HTTP_UNSUPPORTED_MEDIA_TYPE, "Unsupported Media Type",
	  "The server does not support the media type transmitted in the request." },
	{ HTTP_EXPECTATION_FAILED, "Expectation Failed",
	  "The expectation given in the Expect request-header field could not be met by this server." },
	{ HTTP_TOO_MANY_REQUESTS, "Too Many Requests",
	  "You have sent too many requests in a given amount of time." },

	{ HTTP_INTERNAL_SERVER_ERROR, "Internal Server Error",
	  "The server encountered an internal error." },
	{ HTTP_NOT_IMPLEMENTED, "Not Implemented",
	  "The requested method is not supported for current URL." },
	{ HTTP_BAD_GATEWAY, "Bad Gateway",
	  "The proxy server received an invalid response from an upstream server." },
	{ HTTP_SERVICE_UNAVAILABLE, "Service Unavailable",
	  "The server is temporarily unable to service your request." },
	{ HTTP_GATEWAY_TIMEOUT, "Gateway Timeout",
	  "The gateway did not receive a timely response from the upstream server or application." },
};

/* RFC 7230: the request/status line's tokens and reason-phrase admit VCHAR, SP
 * and HT but no other control byte. A bare CR or LF here (legal only before the
 * terminating CRLF) is a request-smuggling / header-injection vector, so reject
 * it -- the same hardening http_parsehdr applies to header field values, since
 * both come from the same untrusted stream. */
static bool http_line_has_ctl(const char *restrict s)
{
	for (; *s != '\0'; ++s) {
		const unsigned char c = (unsigned char)*s;
		if ((c < ' ' && c != '\t') || c == 0x7f) {
			return true;
		}
	}
	return false;
}

char *http_parse(char *restrict buf, struct http_message *restrict msg)
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

	/* reject a bare CR/LF (or other CTL) smuggled into any field */
	if (http_line_has_ctl(field1) || http_line_has_ctl(field2) ||
	    http_line_has_ctl(field3)) {
		return NULL;
	}

	msg->any.field1 = field1;
	msg->any.field2 = field2;
	msg->any.field3 = field3;
	return next;
}

static char *skip_whitespace(char *restrict s)
{
	while (*s == ' ' || *s == '\t') {
		++s;
	}
	return s;
}

/* RFC 7230 Section 3.2.6:
 *   token = 1*tchar
 *   tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
 *           "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
 * This is not RFC 2045's token (mime.c's istoken): HTTP additionally excludes
 * "{", "}" and "\". */
static int is_tchar(const unsigned char c)
{
	static const char tchar[] = "!#$%&'*+-.^_`|~";
	if (isalnum(c)) {
		return 1;
	}
	/* strchr would match the terminator, so exclude NUL explicitly */
	return c != '\0' && strchr(tchar, c) != NULL;
}

char *
http_parsehdr(char *restrict buf, char **restrict key, char **restrict value)
{
	char *next = strstr(buf, "\r\n");
	if (next == NULL) {
		return buf;
	}
	next[0] = next[1] = '\0';
	next += 2; /* skip crlf */

	if (buf[0] == '\0') {
		/* EOF */
		*key = *value = NULL;
		return next;
	}
	if (buf[0] == ' ' || buf[0] == '\t') {
		/* RFC 7230 Section 3.2.4: obs-fold (a header line beginning with
		 * SP/HT that continues the previous field) is deprecated and a
		 * request-smuggling vector; reject it rather than parsing a
		 * whitespace-prefixed field-name. */
		return NULL;
	}

	char *v = strchr(buf, ':');
	if (v == NULL) {
		return NULL;
	}
	/* RFC 7230 Section 3.2: the field-name must be a non-empty token.
	 * Validating it in full also covers Section 3.2.4's rule that a server
	 * MUST reject whitespace between the field-name and the colon (SP and
	 * HT are not tchar), since allowing that -- or an empty name, or a bare
	 * CR inside one -- creates a request-smuggling ambiguity. */
	if (v == buf) {
		return NULL;
	}
	for (const char *p = buf; p < v; ++p) {
		if (!is_tchar((unsigned char)*p)) {
			return NULL;
		}
	}
	*v = '\0';
	v = skip_whitespace(v + 1);
	/* RFC 7230 Section 3.2: trim trailing OWS from field value */
	char *end = v + strlen(v);
	while (end > v && (end[-1] == ' ' || end[-1] == '\t')) {
		end--;
	}
	*end = '\0';
	/* Reject control characters in the field value (e.g. a bare CR or LF
	 * smuggled before the terminating CRLF); SP and HT are allowed between
	 * words. This mirrors the whitespace-before-colon smuggling hardening
	 * above and url.c's decoded-CTL rejection. */
	for (const char *p = v; *p != '\0'; ++p) {
		const unsigned char c = (unsigned char)*p;
		if ((c < ' ' && c != '\t') || c == 0x7f) {
			return NULL;
		}
	}
	*key = buf, *value = v;
	return next;
}

static int code_cmp(const void *key, const void *elem)
{
	const uint_fast16_t code = *(const uint_least16_t *)key;
	const struct http_status_info *info = elem;
	return (code > info->code) - (code < info->code);
}

static const struct http_status_info *find_status(const uint_fast16_t code)
{
	/* uint_fast16_t is 8 bytes on glibc x86-64, so the assignment to the
	 * uint_least16_t search key below narrows implicitly: without this
	 * check an out-of-range code would alias a real one (65536 + 404 found
	 * "Not Found"). No status code has more than three digits. */
	if (code > 999) {
		return NULL;
	}
	const uint_least16_t code_key = code;
	return bsearch(
		&code_key, http_resp, ARRAY_SIZE(http_resp),
		sizeof(http_resp[0]), code_cmp);
}

const char *http_status(const uint_fast16_t code)
{
	const struct http_status_info *info = find_status(code);
	if (info != NULL) {
		return info->name;
	}
	return NULL;
}

#if HAVE_GMTIME_R
#define GMTIME(timer) gmtime_r((timer), &(struct tm){ 0 })
#else
#define GMTIME(timer) gmtime((timer))
#endif /* HAVE_GMTIME_R */

size_t http_date(char *restrict buf, const size_t buf_size)
{
	/* RFC 7231 Section 7.1.1.1: day-name and month are case-sensitive
	 * English literals, so strftime's locale-dependent %a/%b are unusable
	 * here. Indexing these tables keeps the layout fixed at 29 bytes. */
	static const char day[7][4] = { "Sun", "Mon", "Tue", "Wed",
					"Thu", "Fri", "Sat" };
	static const char mon[12][4] = { "Jan", "Feb", "Mar", "Apr",
					 "May", "Jun", "Jul", "Aug",
					 "Sep", "Oct", "Nov", "Dec" };
	const time_t now = time(NULL);
	/* gmtime_r returns NULL when the time_t is not representable */
	const struct tm *restrict gmt = GMTIME(&now);
	if (gmt == NULL) {
		return 0;
	}
	if (gmt->tm_wday < 0 || gmt->tm_wday >= (int)ARRAY_SIZE(day) ||
	    gmt->tm_mon < 0 || gmt->tm_mon >= (int)ARRAY_SIZE(mon)) {
		return 0;
	}
	const int n = snprintf(
		buf, buf_size, "%s, %02d %s %04d %02d:%02d:%02d GMT",
		day[gmt->tm_wday], gmt->tm_mday, mon[gmt->tm_mon],
		gmt->tm_year + 1900, gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
	/* as strftime: report a result that does not fit as zero length */
	if (n < 0 || (size_t)n >= buf_size) {
		return 0;
	}
	return (size_t)n;
}

int http_error(
	char *restrict buf, const size_t buf_size, const uint_fast16_t code)
{
	const struct http_status_info *info = find_status(code);
	if (info == NULL) {
		return 0;
	}
	const char *name = info->name;
	const char *desc = info->desc;
	if (desc == NULL) {
		desc = name;
	}
	char date_str[32];
	const size_t date_len = http_date(date_str, sizeof(date_str));
	return snprintf(
		buf, buf_size,
		"HTTP/1.1 %" PRIuFAST16 " %s\r\n"
		"Date: %.*s\r\n"
		"Connection: close\r\n"
		"Content-type: text/html\r\n\r\n"
		"<HTML><HEAD><TITLE>%" PRIuFAST16 " %s</TITLE></HEAD>\n"
		"<BODY><H1>%" PRIuFAST16 " %s</H1>\n"
		"%s\n"
		"</BODY></HTML>\n",
		code, name, (int)date_len, date_str, code, name, code, name,
		desc);
}
