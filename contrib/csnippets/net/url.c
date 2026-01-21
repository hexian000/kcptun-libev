/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "url.h"
#include "utils/ascii.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void hex(char *restrict p, const uint_fast8_t c)
{
	static const char hex[] = "0123456789ABCDEF";
	p[1] = hex[c & UINT8_C(0xF)];
	p[0] = hex[(c >> 4u) & UINT8_C(0xF)];
}

static int unhex(const unsigned char c)
{
	if (isdigit(c)) {
		return c - '0';
	}
	if ('A' <= c && c <= 'F') {
		return c - 'A' + 10;
	}
	if ('a' <= c && c <= 'f') {
		return c - 'a' + 10;
	}
	return -1;
}

#define APPEND_STR(str)                                                        \
	do {                                                                   \
		size_t n = strlen(str);                                        \
		size_t copy_n =                                                \
			(written + n <= buf_size) ?                            \
				n :                                            \
				(buf_size > written ? buf_size - written : 0); \
		for (size_t i = 0; i < copy_n; i++) {                          \
			buf[written + i] = (str)[i];                           \
		}                                                              \
		written += n;                                                  \
	} while (0)

#define APPEND_CHAR(ch)                                                        \
	do {                                                                   \
		if (written < buf_size) {                                      \
			buf[written] = ch;                                     \
		}                                                              \
		written++;                                                     \
	} while (0)

static int
escape(char *buf, size_t buf_size, const char *str, const size_t len,
       const char *allowed_symbols, const bool space)
{
	size_t written = 0;
	for (size_t i = 0; i < len; i++) {
		const unsigned char ch = str[i];
		if (isalnum(ch) || strchr(allowed_symbols, ch) != NULL) {
			APPEND_CHAR(ch);
			continue;
		}
		if (space && ch == ' ') {
			APPEND_CHAR('+');
			continue;
		}
		if (written < buf_size) {
			buf[written] = '%';
		}
		if (written + 1 < buf_size) {
			hex(buf + written + 1, (uint_fast8_t)(ch));
		}
		written += 3;
	}
	if (buf_size > 0 && written < buf_size) {
		buf[written] = '\0';
	} else if (buf_size > 0) {
		buf[buf_size - 1] = '\0';
	}
	return (int)written;
}

#define S_UNRESERVED "-_.~"
#define S_SUB_DELIMS "!$&'()*+,;="
#define S_PCHAR S_UNRESERVED S_SUB_DELIMS ":@"

static int escape_hostport(
	char *buf, const size_t buf_size, const char *host, const size_t len)
{
	/* RFC 1738, RFC 2732 */
	return escape(
		buf, buf_size, host, len, S_UNRESERVED S_SUB_DELIMS ":[]",
		false);
}

static int escape_userinfo(
	char *buf, const size_t buf_size, const char *userinfo,
	const size_t len)
{
	return escape(
		buf, buf_size, userinfo, len, S_UNRESERVED S_SUB_DELIMS ":",
		false);
}

static int escape_query(
	char *buf, const size_t buf_size, const char *query, const size_t len)
{
	return escape(buf, buf_size, query, len, S_PCHAR "/?", true);
}

static int escape_fragment(
	char *buf, const size_t buf_size, const char *fragment,
	const size_t len)
{
	return escape(buf, buf_size, fragment, len, S_PCHAR "/?", false);
}

int url_escape_userinfo(
	char *buf, size_t buf_size, char *username, char *password)
{
	size_t written = 0;

	int n = escape_userinfo(buf, buf_size, username, strlen(username));
	if (n < 0) {
		return -1;
	}
	written += (size_t)n;

	if (password == NULL) {
		if (buf_size > 0 && written < buf_size) {
			buf[written] = '\0';
		} else if (buf_size > 0) {
			buf[buf_size - 1] = '\0';
		}
		return (int)written;
	}

	APPEND_CHAR(':');

	n = escape_userinfo(
		written < buf_size ? buf + written : buf + buf_size - 1,
		written < buf_size ? buf_size - written : 1, password,
		strlen(password));
	if (n < 0) {
		return -1;
	}
	written += (size_t)n;

	if (buf_size > 0 && written < buf_size) {
		buf[written] = '\0';
	} else if (buf_size > 0) {
		buf[buf_size - 1] = '\0';
	}
	return (int)written;
}

int url_escape_path(char *buf, const size_t buf_size, const char *path)
{
	return escape(
		buf, buf_size, path, strlen(path), "-_.~$&+,/:;=@", false);
}

int url_escape_query(char *buf, size_t buf_size, const char *query)
{
	if (*query == '\0') {
		if (buf_size > 0) {
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
		if (eq == NULL) {
			return -1;
		}
		int n = escape_query(
			written < buf_size ? buf + written : buf + buf_size - 1,
			written < buf_size ? buf_size - written : 1, query,
			eq - query);
		if (n < 0) {
			return -1;
		}
		written += (size_t)n;
		APPEND_CHAR('=');
		query = eq + 1;
		n = escape_query(
			written < buf_size ? buf + written : buf + buf_size - 1,
			written < buf_size ? buf_size - written : 1, query,
			next - query);
		if (n < 0) {
			return -1;
		}
		written += (size_t)n;
		if (*next == '\0') {
			break;
		}
		query = next + 1;
		APPEND_CHAR('&');
	}
	if (buf_size > 0 && written < buf_size) {
		buf[written] = '\0';
	} else if (buf_size > 0) {
		buf[buf_size - 1] = '\0';
	}
	return (int)written;
}

int url_escape_path_segment(
	char *buf, const size_t buf_size, const char *segment)
{
	return escape(
		buf, buf_size, segment, strlen(segment), "-_.~$&+:=@", false);
}

int url_escape_query_component(
	char *buf, const size_t buf_size, const char *component)
{
	return escape_query(buf, buf_size, component, strlen(component));
}

int url_build(char *buf, size_t buf_size, const struct url *url)
{
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
			int n = escape_hostport(
				written < buf_size ? buf + written :
						     buf + buf_size - 1,
				written < buf_size ? buf_size - written : 1,
				url->host, strlen(url->host));
			if (n < 0) {
				return -1;
			}
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
		int n = escape_fragment(
			written < buf_size ? buf + written : buf + buf_size - 1,
			written < buf_size ? buf_size - written : 1,
			url->fragment, strlen(url->fragment));
		if (n < 0) {
			return -1;
		}
		written += (size_t)n;
	}

	if (buf_size > 0 && written < buf_size) {
		buf[written] = '\0';
	} else if (buf_size > 0) {
		buf[buf_size - 1] = '\0';
	}
	return (int)written;
}

static bool unescape(char *str, const bool space)
{
	unsigned char *w = (unsigned char *)str;
	for (const char *r = str; *r != '\0'; r++) {
		unsigned char ch = *r;
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
		*w++ = ch;
	}
	*w = '\0';
	return true;
}

bool url_parse(char *raw, struct url *restrict url)
{
	/* safety check */
	for (const char *p = raw; *p != '\0'; ++p) {
		if (*p < ' ' || *p == 0x7f) {
			return false;
		}
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
	*url = (struct url){
		.fragment = fragment,
	};

	if (*raw == '\0') {
		return false;
	}

	/* parse scheme */
	for (char *p = raw; *p != '\0'; ++p) {
		const unsigned char ch = *p;
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
	url->query = strrchr(raw, '?');
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
	if (v == NULL) {
		return false;
	}
	*v = '\0';
	v++;
	if (!unescape(k, true)) {
		return false;
	}
	if (!unescape(v, true)) {
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
	const char valid_chars[] = "-._:~!$&\'()*+,;=%@'";
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
