/* csnippets (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "url.h"

#include <ctype.h>
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

#define APPEND(str)                                                            \
	do {                                                                   \
		size_t n = strlen(str);                                        \
		if (buf_size < n) {                                            \
			n = buf_size;                                          \
		}                                                              \
		for (size_t i = 0; i < n; i++) {                               \
			buf[i] = (str)[i];                                     \
		}                                                              \
		buf += n;                                                      \
		buf_size -= n;                                                 \
	} while (0)

#define APPENDCH(ch)                                                           \
	do {                                                                   \
		if (buf_size >= 1) {                                           \
			*buf = ch;                                             \
			buf++;                                                 \
			buf_size--;                                            \
		}                                                              \
	} while (0)

#define APPENDESC(ch)                                                          \
	do {                                                                   \
		if (buf_size >= 3) {                                           \
			buf[0] = '%';                                          \
			hex(buf + 1, (uint_fast8_t)(ch));                      \
			buf += 3;                                              \
			buf_size -= 3;                                         \
		}                                                              \
	} while (0)

#define APPENDLIT(str)                                                         \
	do {                                                                   \
		size_t n = sizeof(str) - 1;                                    \
		if (buf_size < n) {                                            \
			n = buf_size;                                          \
		}                                                              \
		for (size_t i = 0; i < n; i++) {                               \
			buf[i] = (str)[i];                                     \
		}                                                              \
		buf += n;                                                      \
		buf_size -= n;                                                 \
	} while (0)

#define APPENDN(expr)                                                          \
	do {                                                                   \
		size_t n = (expr);                                             \
		buf += n;                                                      \
		buf_size -= n;                                                 \
	} while (0)

static size_t
escape(char *buf, size_t buf_size, const char *str, const size_t len,
       const char *allowed_symbols, const bool space)
{
	const size_t cap = buf_size;
	for (size_t i = 0; i < len; i++) {
		const unsigned char ch = str[i];
		if (isalnum(ch) || strchr(allowed_symbols, ch) != NULL) {
			APPENDCH(ch);
			continue;
		}
		if (space && ch == ' ') {
			APPENDCH('+');
			continue;
		}
		APPENDESC(ch);
	}
	return cap - buf_size;
}

static size_t escape_host(
	char *buf, const size_t buf_size, const char *host, const size_t len)
{
	/* RFC 1738, RFC 2732 */
	return escape(
		buf, buf_size, host, len, "-_.~!$&'()*+,;=:[]<>\"", false);
}

static size_t escape_userinfo(
	char *buf, const size_t buf_size, const char *userinfo,
	const size_t len)
{
	return escape(buf, buf_size, userinfo, len, "-_.~$&+,;=", false);
}

static size_t escape_query(
	char *buf, const size_t buf_size, const char *query, const size_t len)
{
	return escape(buf, buf_size, query, len, "-_.~", true);
}

static size_t escape_fragment(
	char *buf, const size_t buf_size, const char *fragment,
	const size_t len)
{
	return escape(
		buf, buf_size, fragment, len, "-_.~$&+,/:;=?@!()*", false);
}

size_t
url_escape_userinfo(char *buf, size_t buf_size, char *username, char *password)
{
	const size_t cap = buf_size;
	APPENDN(escape_userinfo(buf, buf_size, username, strlen(username)));
	if (password == NULL) {
		return cap - buf_size;
	}
	APPENDCH(':');
	APPENDN(escape_userinfo(buf, buf_size, password, strlen(password)));
	return cap - buf_size;
}

size_t url_escape_path(char *buf, const size_t buf_size, const char *path)
{
	return escape(
		buf, buf_size, path, strlen(path), "-_.~$&+,/:;=@", false);
}

size_t url_escape_query(char *buf, size_t buf_size, const char *query)
{
	const size_t cap = buf_size;
	for (;;) {
		const char *next = strchr(query, '&');
		if (next == NULL) {
			next = query + strlen(query);
		}
		const char *eq = memchr(query, '=', next - query);
		if (eq == NULL) {
			return 0;
		}
		APPENDN(escape_query(buf, buf_size, query, eq - query));
		APPENDCH('=');
		query = eq + 1;
		APPENDN(escape_query(buf, buf_size, query, next - query));
		if (*next == '\0') {
			break;
		}
		query = next + 1;
		APPENDCH('&');
	}
	return cap - buf_size;
}

size_t
url_escape_path_segment(char *buf, const size_t buf_size, const char *segment)
{
	return escape(
		buf, buf_size, segment, strlen(segment), "-_.~$&+:=@", false);
}

size_t url_escape_query_component(
	char *buf, const size_t buf_size, const char *component)
{
	return escape_query(buf, buf_size, component, strlen(component));
}

size_t url_build(char *buf, size_t buf_size, const struct url *url)
{
	const size_t cap = buf_size;

	/* [scheme:][//[userinfo@]host]/path[?query][#fragment] */
	if (url->scheme != NULL) {
		APPEND(url->scheme);
		APPENDCH(':');
	}

	if (url->defacto != NULL) {
		/* [scheme:]defacto */
		APPEND(url->defacto);
	} else {
		if (url->host != NULL) {
			APPENDLIT("//");
			if (url->userinfo != NULL) {
				APPEND(url->userinfo);
				APPENDCH('@');
			}
			APPENDN(escape_host(
				buf, buf_size, url->host, strlen(url->host)));
		}
		if (url->path != NULL) {
			if (url->path[0] != '/') {
				APPENDCH('/');
			}
			APPEND(url->path);
		}
	}

	if (url->query != NULL) {
		APPENDCH('?');
		APPEND(url->query);
	}
	if (url->fragment != NULL) {
		APPENDCH('#');
		APPENDN(escape_fragment(
			buf, buf_size, url->fragment, strlen(url->fragment)));
	}

	return cap - buf_size;
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

static inline char *strlower(char *restrict s)
{
	for (unsigned char *p = (unsigned char *)s; *p != '\0'; ++p) {
		*p = tolower(*p);
	}
	return s;
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
