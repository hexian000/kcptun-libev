#ifndef STRBUILDER_H
#define STRBUILDER_H

#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* User should init this struct to zero */
struct strbuilder {
	char *buf;
	size_t len, cap;
};

/**
 * @brief Explicitly reallocate memory of a strbuilder.
 * @details When failed, the strbuilder left unchanged.
 * @param b The strbuilder.
 * @param new_capacity Expected new capacity.
 */
static inline void
strbuilder_reserve(struct strbuilder *restrict b, size_t new_capacity)
{
	if (new_capacity < b->len) {
		new_capacity = b->len;
	}
	if (new_capacity < 16) {
		new_capacity = 16;
	}
	if (new_capacity == b->cap) {
		return;
	}
	char *p = realloc(b->buf, new_capacity);
	if (p == NULL) {
		return;
	}
	b->buf = p;
	b->cap = new_capacity;
}

/**
 * @brief Append one char.
 * @param b The strbuilder.
 * @param ch char to append.
 * @return Number of bytes appended. Can be 0 in case of OOM.
 */
static inline size_t strbuilder_appendch(struct strbuilder *restrict b, char ch)
{
	const size_t len = 1;
	if (b->len + len > b->cap) {
		strbuilder_reserve(b, b->cap * 2);
	}
	if (b->len + len > b->cap) {
		return 0;
	}
	b->buf[b->len++] = ch;
	return len;
}

/**
 * @brief Append a null-terminated string, not including the null-terminator.
 * @param b The strbuilder.
 * @param str String to append.
 * @return Number of bytes appended. Can be 0 in case of OOM.
 */
static inline size_t
strbuilder_append(struct strbuilder *restrict b, const char *str)
{
	const size_t len = strlen(str);
	if (b->len + len > b->cap) {
		strbuilder_reserve(b, b->cap * 2);
	}
	if (b->len + len > b->cap) {
		return 0;
	}
	memmove(b->buf + b->len, str, len);
	b->len += len;
	return len;
}

/**
 * @brief Append a formated string.
 * @param b The strbuilder.
 * @param reserve How much buffer to reserve, passed as maxlen to snprintf.
 * @param fmt passthrough to snprintf.
 * @param ... passthrough to snprintf.
 * @return passthrough from snprintf.
 */
static inline int strbuilder_appendf(
	struct strbuilder *restrict b, size_t reserve, const char *fmt, ...)
{
	if (b->cap - b->len < reserve) {
		strbuilder_reserve(b, b->len + reserve);
	}
	reserve = b->cap - b->len;
	va_list args;
	va_start(args, fmt);
	const int len = vsnprintf(b->buf + b->len, reserve, fmt, args);
	va_end(args);
	if (len > 0) {
		b->len += len;
	}
	return len;
}

/**
 * @brief Append a byte buffer.
 * @param b The strbuilder.
 * @param str Buffer to append.
 * @param len Length of the buffer.
 * @return Number of bytes appended. Can be 0 in case of OOM.
 */
static inline size_t
strbuilder_nappend(struct strbuilder *restrict b, const void *str, size_t len)
{
	if (b->len + len > b->cap) {
		strbuilder_reserve(b, b->cap * 2);
	}
	if (b->len + len > b->cap) {
		return 0;
	}
	memmove(b->buf + b->len, str, len);
	b->len += len;
	return len;
}

/**
 * @brief Free a strbuilder when no longer needed.
 * @param b The strbuilder.
 */
static inline void strbuilder_free(struct strbuilder *restrict b)
{
	free(b->buf);
	*b = (struct strbuilder){ 0 };
}

#endif /* STRBUILDER_H */
