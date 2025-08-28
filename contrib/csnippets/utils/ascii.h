/* csnippets (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_ASCII_H
#define UTILS_ASCII_H

#define isascii(c) (((c) & ~0x7f) == 0)

#define isdigit(c) ('0' <= (c) && (c) <= '9')
#define isalpha(c) (('A' <= (c) && (c) <= 'Z') || ('a' <= (c) && (c) <= 'z'))
#define isalnum(c) (isdigit(c) || isalpha(c))
#define isspace(c)                                                             \
	((c) == '\t' || (c) == '\n' || (c) == '\v' || (c) == '\f' ||           \
	 (c) == '\r' || (c) == ' ')
#define iscntrl(c) (isascii(c) && ((c) <= '\x1f' || (c) == '\x7f'))
#define islower(c) ('a' <= (c) && (c) <= 'z')
#define isupper(c) ('A' <= (c) && (c) <= 'Z')
#define isprint(c) ('\x20' <= (c) && (c) <= '\x7e')
#define isgraph(c) ('\x21' <= (c) && (c) <= '\x7e')
#define ispunct(c) (isgraph(c) && !isalnum(c))
#define isxdigit(c)                                                            \
	(isdigit(c) || ('A' <= (c) && (c) <= 'F') || ('a' <= (c) && (c) <= 'f'))
#define isblank(c) ((c) == ' ' || (c) == '\t')

#define tolower(c) ('A' <= (c) && (c) <= 'Z' ? (c) - 'A' + 'a' : (c))
#define toupper(c) ('a' <= (c) && (c) <= 'z' ? (c) - 'a' + 'A' : (c))

static inline char *strlower(char *restrict s)
{
	for (unsigned char *p = (unsigned char *)s; *p; p++) {
		*p = tolower(*p);
	}
	return s;
}

static inline char *strupper(char *restrict s)
{
	for (unsigned char *p = (unsigned char *)s; *p; p++) {
		*p = toupper(*p);
	}
	return s;
}

static inline char *strtrimleftspace(char *restrict s)
{
	const unsigned char *p = (unsigned char *)s;
	while (*p && isspace(*p)) {
		p++;
	}
	return (char *)p;
}

static inline char *strtrimrightspace(char *restrict s)
{
	unsigned char *e;
	for (e = (unsigned char *)s; *e; e++) {
	}
	e--;
	while ((unsigned char *)s < e && isspace(*e)) {
		*e-- = '\0';
	}
	return s;
}

static inline char *strtrimspace(char *restrict s)
{
	return strtrimrightspace(strtrimleftspace(s));
}

#endif /* UTILS_ASCII_H */
