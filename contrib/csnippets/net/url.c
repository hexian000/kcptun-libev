/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "url.h"

#include "utils/ctype_ascii.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* Copy up to strlen(str) bytes into the unused tail of buf and add the full
 * length to the running total. The amount copied is derived by subtraction
 * under the `written < maxlen` guard, so the truncation decision never depends
 * on a sum of the (saturating) counter that could wrap. */
#define APPEND_STR(str)                                                        \
	do {                                                                   \
		const size_t n = strlen(str);                                  \
		if (buf != NULL && written < maxlen) {                         \
			const size_t avail = maxlen - written;                 \
			const size_t copy_n = n < avail ? n : avail;           \
			for (size_t i = 0; i < copy_n; i++) {                  \
				buf[written + i] = (str)[i];                   \
			}                                                      \
		}                                                              \
		written = add_len(written, n);                                 \
	} while (0)

#define APPEND_CHAR(ch)                                                        \
	do {                                                                   \
		if (buf != NULL && written < maxlen) {                         \
			buf[written] = ch;                                     \
		}                                                              \
		written = add_len(written, 1);                                 \
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

/* Add `n` to the running output length, saturating just past INT_MAX so the
 * counter can never wrap. A total beyond INT_MAX is not representable in the
 * snprintf-style int return; result_len turns that into an error. */
static size_t add_len(const size_t written, const size_t n)
{
	if (written > (size_t)INT_MAX || n > (size_t)INT_MAX - written) {
		return (size_t)INT_MAX + 1;
	}
	return written + n;
}

/* Finish a serializer: NUL-terminate the (possibly truncated) buffer, then
 * return the snprintf-style length, or -1 when the required length exceeds the
 * int return type. */
static int result_len(char *buf, const size_t maxlen, const size_t written)
{
	terminate(buf, maxlen, written);
	if (written > (size_t)INT_MAX) {
		return -1;
	}
	return (int)written;
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
		/* percent-escape 'ch' as "%XX"; the two hex bytes are guarded
		 * independently, via the available tail, so an escape straddling
		 * the end of buf never overflows. */
		if (written < maxlen) {
			const size_t avail = maxlen - written;
			char hex[2];
			tohex(hex, ch);
			buf[written] = '%';
			if (avail > 1) {
				buf[written + 1] = hex[0];
			}
			if (avail > 2) {
				buf[written + 2] = hex[1];
			}
		}
		written = add_len(written, 3);
	}
	return result_len(buf, maxlen, written);
}

#define S_UNRESERVED "-_.~"
#define S_QUERY_SUBDELIMS "!$'()*,;"
#define S_SUB_DELIMS S_QUERY_SUBDELIMS "&+="
#define S_GEN_DELIMS ":/?#[]@"
#define S_PCHAR S_UNRESERVED S_SUB_DELIMS ":@"
#define S_PATH_CHARS "$&+,/:;=@"
#define S_PATH_SEGMENT_CHARS "$&+:=@"

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

static int
escape_path(char *buf, const size_t maxlen, const char *path, const size_t len)
{
	return escape(buf, maxlen, path, len, S_UNRESERVED S_PATH_CHARS, false);
}

static int escape_path_segment(
	char *buf, const size_t maxlen, const char *segment, const size_t len)
{
	return escape(
		buf, maxlen, segment, len, S_UNRESERVED S_PATH_SEGMENT_CHARS,
		false);
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
	if (n < 0) {
		return -1;
	}
	written = add_len(written, (size_t)n);

	if (password == NULL) {
		return result_len(buf, maxlen, written);
	}

	APPEND_CHAR(':');

	char *p;
	size_t avail;
	subbuf(buf, maxlen, written, &p, &avail);
	n = escape_userinfo(p, avail, password, strlen(password));
	if (n < 0) {
		return -1;
	}
	written = add_len(written, (size_t)n);

	return result_len(buf, maxlen, written);
}

int url_escape_path(char *restrict buf, size_t maxlen, const char *restrict path)
{
	if (buf == NULL) {
		maxlen = 0;
	}
	return escape_path(buf, maxlen, path, strlen(path));
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
		const char *eq = memchr(query, '=', (size_t)(next - query));
		char *p;
		size_t avail;
		int n;
		if (eq != NULL) {
			subbuf(buf, maxlen, written, &p, &avail);
			n = escape_query(p, avail, query, (size_t)(eq - query));
			if (n < 0) {
				return -1;
			}
			written = add_len(written, (size_t)n);
			APPEND_CHAR('=');
			query = eq + 1;
			subbuf(buf, maxlen, written, &p, &avail);
			n = escape_query(
				p, avail, query, (size_t)(next - query));
		} else {
			/* RFC 3986: key without value is a valid query component */
			subbuf(buf, maxlen, written, &p, &avail);
			n = escape_query(
				p, avail, query, (size_t)(next - query));
		}
		if (n < 0) {
			return -1;
		}
		written = add_len(written, (size_t)n);
		if (*next == '\0') {
			break;
		}
		query = next + 1;
		APPEND_CHAR('&');
	}
	return result_len(buf, maxlen, written);
}

int url_escape_path_segment(
	char *restrict buf, size_t maxlen, const char *restrict segment)
{
	if (buf == NULL) {
		maxlen = 0;
	}
	return escape_path_segment(buf, maxlen, segment, strlen(segment));
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
			const int n = escape_hostport(
				p, avail, url->host, strlen(url->host));
			if (n < 0) {
				return -1;
			}
			written = add_len(written, (size_t)n);
		}
		if (url->path != NULL) {
			/* RFC 3986 3.3: with no authority, a path must not
			 * begin with "//", or it would reparse as one. A path
			 * whose first segment is empty therefore gets an empty
			 * authority, which url_parse() reads back as no host. */
			if (url->host == NULL && url->path[0] == '/') {
				APPEND_CHAR('/');
				APPEND_CHAR('/');
			}
			/* the separator url_parse() strips from the path */
			APPEND_CHAR('/');
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
		const int n = escape_fragment(
			p, avail, url->fragment, strlen(url->fragment));
		if (n < 0) {
			return -1;
		}
		written = add_len(written, (size_t)n);
	}

	return result_len(buf, maxlen, written);
}

/* RFC 3986 admits only these bytes unencoded in a URI: the unreserved set,
 * reserved gen-delims and sub-delims, and "%" introducing a percent-encoding.
 * Every other byte is forbidden and makes the whole input an invalid URI. The
 * parsed path and query retain their escaped form; url_parse() decodes the host
 * and fragment in place. Cast through unsigned char so a high byte on a
 * signed-char platform is not misread as an allowed one. */
static bool has_forbidden(const char *s)
{
	static const char allowed[] =
		S_UNRESERVED S_GEN_DELIMS S_SUB_DELIMS "%";
	for (; *s != '\0'; ++s) {
		const unsigned char c = (unsigned char)*s;
		if (!isalnum(c) && strchr(allowed, c) == NULL) {
			return true;
		}
	}
	return false;
}

/* An authority carries ':', '[' and ']' as structure -- the port separator and
 * the IP-literal brackets -- and url_parse() decodes it in place, after which a
 * pct-encoded delimiter could no longer be told from a structural one. Report
 * whether any pct-encoded byte in str is an RFC 3986 gen-delim. A malformed
 * escape is left for unescape() to reject. */
static bool has_encoded_delim(const char *s)
{
	for (; *s != '\0'; ++s) {
		if (s[0] != '%') {
			continue;
		}
		if (s[1] == '%') {
			/* "%%" decodes to a literal '%', not a gen-delim */
			++s;
			continue;
		}
		const int hi = unhex(s[1]);
		if (hi < 0) {
			return false;
		}
		const int lo = unhex(s[2]);
		if (lo < 0) {
			return false;
		}
		const unsigned char ch = (unsigned char)((hi << 4u) | lo);
		if (ch != '\0' && strchr(S_GEN_DELIMS, ch) != NULL) {
			return true;
		}
		s += 2;
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
				/* deliberate leniency, documented at the
				 * @defgroup in url.h: "%%" decodes to a
				 * literal '%' although RFC 3986 requires two
				 * HEXDIG. The escaping direction never emits
				 * it (a '%' is encoded as "%25"). */
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
	if (has_forbidden(raw)) {
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
			/* RFC 3986 3.2/3.2.1: '@' is the sole authority
			 * delimiter and a literal '@' in userinfo must be
			 * pct-encoded, so reject any raw '@' left in the
			 * selected userinfo (i.e. the input held several). */
			if (strchr(raw, '@') != NULL) {
				return false;
			}
			url->userinfo = raw;
			raw = at + 1;
		}
		char *host = raw;
		if (has_encoded_delim(host)) {
			return false;
		}
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
	/* RFC 3986 3.2.1: userinfo is unreserved / pct-encoded / sub-delims /
	 * ':'. A raw '@' is not admitted -- it is the authority delimiter and
	 * must be pct-encoded (%40) when it is data. */
	const char valid_chars[] = S_UNRESERVED ":" S_SUB_DELIMS "%";
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
