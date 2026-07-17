/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "url.h"

#include "utils/ascii.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define APPEND_STR(str)                                                        \
	do {                                                                   \
		size_t n = strlen(str);                                        \
		if (buf != NULL) {                                             \
			size_t copy_n =                                        \
				(written + n <= maxlen) ?                      \
					n :                                    \
					(maxlen > written ? maxlen - written : \
							    0);                \
			for (size_t i = 0; i < copy_n; i++) {                  \
				buf[written + i] = (str)[i];                   \
			}                                                      \
		}                                                              \
		written += n;                                                  \
	} while (0)

#define APPEND_CHAR(ch)                                                        \
	do {                                                                   \
		if (buf != NULL && written < maxlen) {                         \
			buf[written] = ch;                                     \
		}                                                              \
		written++;                                                     \
	} while (0)

/* Write the terminating NUL for an escape/build result: at buf[written] when
 * the whole output fit, otherwise at the last byte of the truncated buffer.
 * maxlen == 0 (the buf == NULL convention) leaves nothing to terminate. */
static void terminate(char *buf, const size_t maxlen, const size_t written)
{
	if (maxlen == 0) {
		return;
	}
	buf[written < maxlen ? written : maxlen - 1] = '\0';
}

/* Point (*p, *avail) at the unused tail of buf past `written` bytes, or at
 * (NULL, 0) when buf is absent or already full -- the sub-buffer the next
 * escape_* component is written into. */
static void
subbuf(char *buf, const size_t maxlen, const size_t written, char **restrict p,
       size_t *restrict avail)
{
	if (buf != NULL && written < maxlen) {
		*p = buf + written;
		*avail = maxlen - written;
	} else {
		*p = NULL;
		*avail = 0;
	}
}

static int
escape(char *buf, size_t maxlen, const char *str, const size_t len,
       const char *allowed_symbols, const bool space)
{
	size_t written = 0;
	for (size_t i = 0; i < len; i++) {
		const unsigned char ch = (unsigned char)str[i];
		if (isalnum(ch) || strchr(allowed_symbols, ch) != NULL) {
			APPEND_CHAR(ch);
			continue;
		}
		if (space && ch == ' ') {
			APPEND_CHAR('+');
			continue;
		}
		if (written < maxlen) {
			buf[written] = '%';
		}
		/* tohex() writes two bytes; guard each independently so a
		 * percent-escape straddling the end of buf never overflows. */
		char hex[2];
		tohex(hex, ch);
		if (written + 1 < maxlen) {
			buf[written + 1] = hex[0];
		}
		if (written + 2 < maxlen) {
			buf[written + 2] = hex[1];
		}
		written += 3;
	}
	terminate(buf, maxlen, written);
	return (int)written;
}

#define S_UNRESERVED "-_.~"
#define S_SUB_DELIMS "!$&'()*+,;="
#define S_PCHAR S_UNRESERVED S_SUB_DELIMS ":@"
/* Query sub-delimiters minus '+', '&', '=', which carry form-encoding meaning
 * (space<->'+' and the key/value/pair separators). A literal one of these in a
 * query component must be percent-encoded so it is not decoded back as a space
 * or misread as a parameter separator. */
#define S_QUERY_SUBDELIMS "!$'()*,;"

static int escape_hostport(
	char *buf, const size_t maxlen, const char *host, const size_t len)
{
	/* RFC 1738, RFC 2732 */
	return escape(
		buf, maxlen, host, len, S_UNRESERVED S_SUB_DELIMS ":[]", false);
}

static int escape_userinfo(
	char *buf, const size_t maxlen, const char *userinfo, const size_t len)
{
	/* No ':' in the allowed set: url_escape_userinfo inserts the single
	 * structural ':' between the escaped username and password itself, so a
	 * literal ':' inside either half must percent-encode to %3A. Otherwise
	 * url_unescape_userinfo, which splits at the first ':', would misattribute
	 * it as the delimiter and corrupt the round-trip. */
	return escape(
		buf, maxlen, userinfo, len, S_UNRESERVED S_SUB_DELIMS, false);
}

static int escape_query(
	char *buf, const size_t maxlen, const char *query, const size_t len)
{
	return escape(
		buf, maxlen, query, len, S_UNRESERVED S_QUERY_SUBDELIMS ":@/?",
		true);
}

static int escape_fragment(
	char *buf, const size_t maxlen, const char *fragment, const size_t len)
{
	return escape(buf, maxlen, fragment, len, S_PCHAR "/?", false);
}

int url_escape_userinfo(
	char *restrict buf, size_t maxlen, const char *restrict username,
	const char *restrict password)
{
	if (buf == NULL) {
		maxlen = 0;
	}
	size_t written = 0;

	int n = escape_userinfo(buf, maxlen, username, strlen(username));
	written += (size_t)n;

	if (password == NULL) {
		terminate(buf, maxlen, written);
		return (int)written;
	}

	APPEND_CHAR(':');

	char *p;
	size_t avail;
	subbuf(buf, maxlen, written, &p, &avail);
	n = escape_userinfo(p, avail, password, strlen(password));
	written += (size_t)n;

	terminate(buf, maxlen, written);
	return (int)written;
}

int url_escape_path(char *restrict buf, size_t maxlen, const char *restrict path)
{
	if (buf == NULL) {
		maxlen = 0;
	}
	return escape(buf, maxlen, path, strlen(path), "-_.~$&+,/:;=@", false);
}

int url_escape_query(
	char *restrict buf, size_t maxlen, const char *restrict query)
{
	if (buf == NULL) {
		maxlen = 0;
	}
	if (*query == '\0') {
		if (maxlen > 0) {
			buf[0] = '\0';
		}
		return 0;
	}
	size_t written = 0;
	for (;;) {
		const char *next = strchr(query, '&');
		if (next == NULL) {
			next = query + strlen(query);
		}
		const char *eq = memchr(query, '=', next - query);
		int n;
		if (eq != NULL) {
			char *p;
			size_t avail;
			subbuf(buf, maxlen, written, &p, &avail);
			n = escape_query(p, avail, query, eq - query);
			written += (size_t)n;
			APPEND_CHAR('=');
			query = eq + 1;
			subbuf(buf, maxlen, written, &p, &avail);
			n = escape_query(p, avail, query, next - query);
		} else {
			/* RFC 3986: key without value is a valid query component */
			char *p;
			size_t avail;
			subbuf(buf, maxlen, written, &p, &avail);
			n = escape_query(p, avail, query, next - query);
		}
		written += (size_t)n;
		if (*next == '\0') {
			break;
		}
		query = next + 1;
		APPEND_CHAR('&');
	}
	terminate(buf, maxlen, written);
	return (int)written;
}

int url_escape_path_segment(
	char *restrict buf, size_t maxlen, const char *restrict segment)
{
	if (buf == NULL) {
		maxlen = 0;
	}
	return escape(
		buf, maxlen, segment, strlen(segment), "-_.~$&+:=@", false);
}

int url_escape_query_component(
	char *restrict buf, size_t maxlen, const char *restrict component)
{
	if (buf == NULL) {
		maxlen = 0;
	}
	return escape_query(buf, maxlen, component, strlen(component));
}

int url_build(char *restrict buf, size_t maxlen, const struct url *restrict url)
{
	if (buf == NULL) {
		maxlen = 0;
	}
	size_t written = 0;

	/* [scheme:][//[userinfo@]host]/path[?query][#fragment] */
	if (url->scheme != NULL) {
		APPEND_STR(url->scheme);
		APPEND_CHAR(':');
	}

	if (url->defacto != NULL) {
		/* [scheme:]defacto */
		APPEND_STR(url->defacto);
	} else {
		if (url->host != NULL) {
			APPEND_CHAR('/');
			APPEND_CHAR('/');
			if (url->userinfo != NULL) {
				APPEND_STR(url->userinfo);
				APPEND_CHAR('@');
			}
			char *p;
			size_t avail;
			subbuf(buf, maxlen, written, &p, &avail);
			int n = escape_hostport(
				p, avail, url->host, strlen(url->host));
			written += (size_t)n;
		}
		if (url->path != NULL) {
			if (url->path[0] != '/') {
				APPEND_CHAR('/');
			}
			APPEND_STR(url->path);
		}
	}

	if (url->query != NULL) {
		APPEND_CHAR('?');
		APPEND_STR(url->query);
	}
	if (url->fragment != NULL) {
		APPEND_CHAR('#');
		char *p;
		size_t avail;
		subbuf(buf, maxlen, written, &p, &avail);
		int n = escape_fragment(
			p, avail, url->fragment, strlen(url->fragment));
		written += (size_t)n;
	}

	terminate(buf, maxlen, written);
	return (int)written;
}

/* RFC 3986 forbids raw control characters in a URI. Cast through unsigned
 * char so a high byte (0x80-0xFF) on a signed-char platform is not mistaken
 * for a control character. */
static bool has_ctl(const char *s)
{
	for (; *s != '\0'; ++s) {
		const unsigned char c = (unsigned char)*s;
		if (iscntrl(c)) {
			return true;
		}
	}
	return false;
}

static bool unescape(char *str, const bool space)
{
	/* unescape str in place: w <= r always */
	unsigned char *w = (unsigned char *)str;
	for (const char *r = str; *r != '\0'; r++) {
		unsigned char ch = (unsigned char)*r;
		switch (ch) {
		case '%':
			switch (r[1]) {
			case '\0':
				return false;
			case '%':
				r++;
				break;
			default: {
				const int hi = unhex(r[1]);
				if (hi < 0) {
					return false;
				}
				const int lo = unhex(r[2]);
				if (lo < 0) {
					return false;
				}
				ch = (unsigned char)((hi << 4u) | lo);
				r += 2;
				break;
			}
			}
			break;
		case '+':
			if (space) {
				ch = ' ';
			}
			break;
		default:
			break;
		}
		/* Reject any control character the percent-decode produced (e.g.
		 * a CR/LF smuggled via %0d/%0a), so no caller of unescape() can
		 * leak them into headers, redirects or logs.  This must happen
		 * here, while the decoded byte is in hand: a post-hoc C-string
		 * scan of the result would stop at a NUL from %00 rather than
		 * reject it, silently truncating the value instead. */
		if (iscntrl(ch)) {
			return false;
		}
		*w++ = ch;
	}
	*w = '\0';
	return true;
}

bool url_parse(char *raw, struct url *restrict url)
{
	if (has_ctl(raw)) {
		return false;
	}

	/* parse fragment */
	char *fragment = strchr(raw, '#');
	if (fragment != NULL) {
		*fragment = '\0';
		fragment++;
		if (!unescape(fragment, false)) {
			return false;
		}
	}
	*url = (struct url){ .fragment = fragment };

	if (*raw == '\0') {
		return false;
	}

	/* parse scheme */
	for (char *p = raw; *p != '\0'; ++p) {
		const unsigned char ch = (unsigned char)*p;
		/* RFC 2396: Section 3.1 */
		if (isalpha(ch)) {
			/* skip */
		} else if (isdigit(ch) || ch == '+' || ch == '-' || ch == '.') {
			if (p == raw) {
				break;
			}
		} else if (ch == ':') {
			if (p == raw) {
				return false;
			}
			*p = '\0';
			url->scheme = strlower(raw);
			raw = p + 1;
			break;
		} else {
			break;
		}
	}

	/* parse query */
	url->query = strchr(raw, '?');
	if (url->query != NULL) {
		*url->query = '\0';
		url->query++;
	}

	const bool has_1_slash = raw[0] == '/';
	const bool has_2_slashes = has_1_slash && raw[1] == '/';
	const bool has_3_slashes = has_2_slashes && raw[2] == '/';
	if (has_3_slashes) {
		raw += 3;
	} else if (has_2_slashes) {
		raw += 2;
		char *slash = strchr(raw, '/');
		if (slash != NULL) {
			*slash = '\0';
		}
		char *at = strrchr(raw, '@');
		if (at != NULL) {
			*at = '\0';
			url->userinfo = raw;
			raw = at + 1;
		}
		char *host = raw;
		if (!unescape(host, false)) {
			/* unescape() now also rejects any decoded control char */
			return false;
		}
		url->host = host;
		if (slash != NULL) {
			raw = slash + 1;
		} else {
			raw = NULL;
		}
	} else if (has_1_slash) {
		raw += 1;
	} else {
		url->defacto = raw;
		return true;
	}

	url->path = raw;
	return true;
}

bool url_path_segment(char **restrict path, char **restrict segment)
{
	char *s = *path;
	if (s == NULL) {
		return false;
	}
	while (*s == '/') {
		s++;
	}
	char *next = strchr(s, '/');
	if (next != NULL) {
		*next = '\0';
		next++;
	}
	if (!unescape(s, false)) {
		return false;
	}
	*segment = s;
	*path = next;
	return true;
}

bool url_query_component(
	char **restrict query, struct url_query_component *restrict comp)
{
	char *s = *query;
	if (s == NULL) {
		return false;
	}
	char *next = strchr(s, '&');
	if (next != NULL) {
		*next = '\0';
		next++;
	}
	char *k = s;
	char *v = strchr(s, '=');
	if (v != NULL) {
		*v = '\0';
		v++;
	}
	if (!unescape(k, true)) {
		return false;
	}
	/* RFC 3986: value is optional; NULL indicates key-only component */
	if (v != NULL && !unescape(v, true)) {
		return false;
	}
	*comp = (struct url_query_component){
		.key = k,
		.value = v,
	};
	*query = next;
	return true;
}

bool url_unescape_userinfo(
	char *raw, char **restrict username, char **restrict password)
{
	const char valid_chars[] = "-._:~!$&'()*+,;=%@";
	char *colon = NULL;
	for (char *p = raw; *p != '\0'; ++p) {
		const unsigned char c = (unsigned char)*p;
		/* RFC 3986: Section 3.2.1 */
		if (!isalnum(c) && strchr(valid_chars, c) == NULL) {
			return false;
		}
		if (colon == NULL && c == ':') {
			colon = p;
		}
	}
	char *user = raw;
	char *pass = NULL;
	if (colon != NULL) {
		*colon = '\0';
		pass = colon + 1;
	}
	if (!unescape(user, false)) {
		return false;
	}
	if (pass != NULL && !unescape(pass, false)) {
		return false;
	}
	*username = user;
	*password = pass;
	return true;
}

bool url_unescape_path(char *path)
{
	return unescape(path, false);
}

bool url_unescape_query(char *query)
{
	return unescape(query, true);
}
