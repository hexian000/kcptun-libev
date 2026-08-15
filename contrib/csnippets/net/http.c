/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http.h"

#include "meta/arraysize.h"
#include "utils/ctype_ascii.h"

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
	{ HTTP_SWITCHING_PROTOCOLS, "Switching Protocols", NULL },

	{ HTTP_OK, "OK", NULL },
	{ HTTP_CREATED, "Created", NULL },
	{ HTTP_ACCEPTED, "Accepted", NULL },
	{ HTTP_NON_AUTHORITATIVE_INFORMATION, "Non-Authoritative Information",
	  NULL },
	{ HTTP_NO_CONTENT, "No Content", NULL },
	{ HTTP_RESET_CONTENT, "Reset Content", NULL },
	{ HTTP_PARTIAL_CONTENT, "Partial Content", NULL },

	{ HTTP_MULTIPLE_CHOICES, "Multiple Choices", NULL },
	{ HTTP_MOVED_PERMANENTLY, "Moved Permanently", NULL },
	{ HTTP_FOUND, "Found", NULL },
	{ HTTP_SEE_OTHER, "See Other", NULL },
	{ HTTP_NOT_MODIFIED, "Not Modified", NULL },
	{ HTTP_USE_PROXY, "Use Proxy", NULL },
	{ HTTP_TEMPORARY_REDIRECT, "Temporary Redirect", NULL },
	{ HTTP_PERMANENT_REDIRECT, "Permanent Redirect", NULL },

	{ HTTP_BAD_REQUEST, "Bad Request",
	  "Your browser sent a request that this server could not understand." },
	{ HTTP_UNAUTHORIZED, "Unauthorized",
	  "This server could not verify that you are authorized to access the document requested." },
	{ HTTP_PAYMENT_REQUIRED, "Payment Required",
	  "This status code is reserved for future use." },
	{ HTTP_FORBIDDEN, "Forbidden",
	  "You don't have permission to access this resource." },
	{ HTTP_NOT_FOUND, "Not Found",
	  "The requested URL was not found on this server." },
	{ HTTP_METHOD_NOT_ALLOWED, "Method Not Allowed",
	  "The requested method is not allowed for this URL." },
	{ HTTP_NOT_ACCEPTABLE, "Not Acceptable",
	  "The requested resource has no representation acceptable to this client." },
	{ HTTP_PROXY_AUTHENTICATION_REQUIRED, "Proxy Authentication Required",
	  NULL },
	{ HTTP_REQUEST_TIMEOUT, "Request Timeout",
	  "Server timeout waiting for the HTTP request from the client." },
	{ HTTP_CONFLICT, "Conflict",
	  "The request conflicts with the current state of the resource." },
	{ HTTP_GONE, "Gone",
	  "The requested resource is no longer available on this server and no forwarding address is known." },
	{ HTTP_LENGTH_REQUIRED, "Length Required",
	  "A request of the requested method requires a valid Content-Length." },
	{ HTTP_PRECONDITION_FAILED, "Precondition Failed",
	  "A precondition given in the request header fields was not met by this server." },
	{ HTTP_ENTITY_TOO_LARGE, "Content Too Large",
	  "The amount of data provided in the request exceeds the capacity limit." },
	{ HTTP_URI_TOO_LONG, "URI Too Long",
	  "The requested URL's length exceeds the capacity limit for this server." },
	{ HTTP_UNSUPPORTED_MEDIA_TYPE, "Unsupported Media Type",
	  "The server does not support the media type transmitted in the request." },
	{ HTTP_RANGE_NOT_SATISFIABLE, "Range Not Satisfiable",
	  "The requested range is not satisfiable for this resource." },
	{ HTTP_EXPECTATION_FAILED, "Expectation Failed",
	  "The expectation given in the Expect request-header field could not be met by this server." },
	{ HTTP_MISDIRECTED_REQUEST, "Misdirected Request",
	  "This server is not able to produce a response for the requested authority." },
	{ HTTP_UNPROCESSABLE_CONTENT, "Unprocessable Content",
	  "The server is unable to process the instructions contained in the request." },
	{ HTTP_TOO_EARLY, "Too Early",
	  "The server is unwilling to risk processing a request that might be replayed." },
	{ HTTP_UPGRADE_REQUIRED, "Upgrade Required",
	  "The requested resource requires the client to switch to another protocol." },
	{ HTTP_PRECONDITION_REQUIRED, "Precondition Required",
	  "The server requires this request to be conditional." },
	{ HTTP_TOO_MANY_REQUESTS, "Too Many Requests",
	  "You have sent too many requests in a given amount of time." },
	{ HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE,
	  "Request Header Fields Too Large",
	  "The server is unwilling to process the request because its header fields are too large." },
	{ HTTP_UNAVAILABLE_FOR_LEGAL_REASONS, "Unavailable For Legal Reasons",
	  "The requested resource is unavailable due to a legal demand." },

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
	{ HTTP_VERSION_NOT_SUPPORTED, "HTTP Version Not Supported",
	  "The server does not support the HTTP version used in the request." },
	{ HTTP_NETWORK_AUTHENTICATION_REQUIRED,
	  "Network Authentication Required",
	  "The client needs to authenticate to gain network access." },
};

/* Report a control byte in a start-line field or a field value: every CTL
 * (including DEL) except, when allow_ht is set, HT. A bare CR or LF here (legal
 * only before the terminating CRLF) is a request-smuggling / header-injection
 * vector, so the parsers reject it -- the start line and the header fields come
 * from the same untrusted stream. */
static bool has_ctl(const char *restrict s, const bool allow_ht)
{
	for (; *s != '\0'; ++s) {
		const unsigned char c = (unsigned char)*s;
		if ((c < ' ' && !(allow_ht && c == '\t')) || c == 0x7f) {
			return true;
		}
	}
	return false;
}

char *http_parse(char *restrict buf, struct http_message *restrict msg)
{
	/* RFC 9112 Section 2.2: a server SHOULD ignore at least one empty line
	 * received before the request-line, as some clients send an extra CRLF
	 * after a request's content. Skip every leading one; when nothing but
	 * empty lines is buffered yet, report no progress and wait for more. */
	char *line = buf;
	while (line[0] == '\r' && line[1] == '\n') {
		line += 2;
	}
	char *next = strstr(line, "\r\n");
	if (next == NULL) {
		return buf;
	}
	next[0] = next[1] = '\0';
	next += 2; /* skip crlf */

	char *field1 = line;

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

	/* RFC 9112 Sections 3 and 4: the start-line separator is exactly one
	 * SP, so a run of them is not "excess whitespace to skip" but a line
	 * this parser cannot tokenize -- splitting on the first SP of a run
	 * yields an empty field and shifts the rest, e.g. "GET  / HTTP/1.1"
	 * would parse as method "GET", url "" and version "/ HTTP/1.1" and be
	 * reported as a success. Reject the line instead; a caller has no way
	 * to tell that split apart from a real one.
	 *
	 * Only the first two fields are checked. An empty third field is legal:
	 * on a status line it is the reason-phrase, which Section 4 makes
	 * optional while still requiring the SP that separates it from the
	 * status-code, so "HTTP/1.1 404 " is conforming. This parser serves
	 * requests and responses alike and cannot tell which it has, the same
	 * reason a run before the last field is accepted; a request whose
	 * version came out empty is rejected by the caller's version check. */
	if (field1[0] == '\0' || field2[0] == '\0') {
		return NULL;
	}

	/* RFC 9112 Sections 3 and 4: HT is admitted only by the status line's
	 * reason-phrase, 1*( HTAB / SP / VCHAR / obs-text ). The first two
	 * fields -- a request's method (a token, RFC 9110 Section 9.1) and
	 * request-target (no whitespace, Section 3.2), a response's
	 * HTTP-version and status-code -- admit none, and accepting one there
	 * would let a recipient that splits the line on any whitespace read a
	 * different request than this parser did. The third field may be a
	 * reason-phrase, so it keeps HT; a request's version is checked by the
	 * caller, as for the empty one above. */
	if (has_ctl(field1, false) || has_ctl(field2, false) ||
	    has_ctl(field3, true)) {
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

/* RFC 9110 Section 5.6.2:
 *   token = 1*tchar
 *   tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
 *           "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
 * This is not RFC 2045's token (mime.c's istoken): HTTP additionally excludes
 * "{" and "}" (RFC 2045 tspecials already exclude "\"). */
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
		/* RFC 9112 Section 5.2: obs-fold (a header line beginning with
		 * SP/HT that continues the previous field) is deprecated and a
		 * request-smuggling vector; reject it rather than parsing a
		 * whitespace-prefixed field-name. */
		return NULL;
	}

	char *v = strchr(buf, ':');
	if (v == NULL) {
		return NULL;
	}
	/* RFC 9110 Section 5.1: the field-name must be a non-empty token.
	 * Validating it in full also covers RFC 9112 Section 5.1's rule that a
	 * server MUST reject whitespace between the field-name and the colon
	 * (SP and HT are not tchar), since allowing that -- or an empty name,
	 * or a bare CR inside one -- creates a request-smuggling ambiguity. */
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
	/* RFC 9112 Section 5.1: trim trailing OWS from the field line value */
	char *end = v + strlen(v);
	while (end > v && (end[-1] == ' ' || end[-1] == '\t')) {
		end--;
	}
	*end = '\0';
	/* RFC 9110 Section 5.5: CR, LF and NUL in a field value must be
	 * rejected or scrubbed, and other CTLs are invalid too. Reject them all
	 * (e.g. a bare CR or LF smuggled before the terminating CRLF); SP and
	 * HT are allowed between words. This mirrors the smuggling hardening
	 * for whitespace before the colon above, and url.c's decoded-CTL
	 * rejection. */
	if (has_ctl(v, true)) {
		return NULL;
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
	/* RFC 9110 Section 5.6.7: day-name and month are case-sensitive
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
	/* the same section spells the year as exactly 4DIGIT: outside
	 * [0, 9999] there is no IMF-fixdate rendering, %04d would emit five
	 * digits or a sign, and tm_year + 1900 could overflow */
	if (gmt->tm_year < -1900 || gmt->tm_year > 9999 - 1900) {
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
	/* RFC 9110 Sections 15.2, 15.3.5, 15.3.6 and 15.4.5, RFC 9112 Section
	 * 6.3: a 1xx, 204 or 304 response ends with its header section, and a
	 * server MUST NOT generate content in a 205. The page below is content,
	 * and a client would read it as the next response, so these codes have
	 * no error response to generate. */
	if ((code >= 100 && code <= 199) || code == HTTP_NO_CONTENT ||
	    code == HTTP_RESET_CONTENT || code == HTTP_NOT_MODIFIED) {
		return 0;
	}
	const struct http_status_info *info = find_status(code);
	if (info == NULL) {
		return 0;
	}
	const char *name = info->name;
	const char *desc = info->desc;
	if (desc == NULL) {
		desc = name;
	}
	/* http_date returns 0 when the current time has no IMF-fixdate
	 * rendering; emitting "Date: \r\n" would then send a header whose
	 * field-value is empty, which RFC 9110 Section 6.6.1 does not admit.
	 * Omit the whole line instead -- an origin server without a clock must
	 * not send Date at all -- which also keeps the uninitialized date_str
	 * out of the output entirely. */
	char date_str[32];
	const size_t date_len = http_date(date_str, sizeof(date_str));
	char date_hdr[sizeof("Date: \r\n") + sizeof(date_str)];
	if (date_len > 0) {
		(void)snprintf(
			date_hdr, sizeof(date_hdr), "Date: %.*s\r\n",
			(int)date_len, date_str);
	} else {
		date_hdr[0] = '\0';
	}
	return snprintf(
		buf, buf_size,
		"HTTP/1.1 %" PRIuFAST16 " %s\r\n"
		"%s"
		"Connection: close\r\n"
		"Content-type: text/html\r\n\r\n"
		"<HTML><HEAD><TITLE>%" PRIuFAST16 " %s</TITLE></HEAD>\n"
		"<BODY><H1>%" PRIuFAST16 " %s</H1>\n"
		"%s\n"
		"</BODY></HTML>\n",
		code, name, date_hdr, code, name, code, name, desc);
}
