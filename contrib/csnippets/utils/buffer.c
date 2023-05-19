/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "buffer.h"

#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

int buf_appendf(void *buf, const char *format, ...)
{
	struct vbuffer *restrict vbuf = buf;
	char *b = (char *)(vbuf->data + vbuf->len);
	const size_t maxlen = vbuf->cap - vbuf->len;
	if (maxlen == 0) {
		return 0;
	}
	va_list args;
	va_start(args, format);
	const int ret = vsnprintf(b, maxlen, format, args);
	va_end(args);
	if (ret > 0) {
		vbuf->len += MIN((size_t)ret, maxlen - 1);
	}
	return ret;
}

struct vbuffer *vbuf_alloc(struct vbuffer *restrict vbuf, const size_t cap)
{
	if (cap == 0) {
		free(vbuf);
		return NULL;
	}
	size_t len = 0;
	if (vbuf != NULL) {
		if (cap == vbuf->cap) {
			return vbuf;
		}
		len = vbuf->len;
	}
	struct vbuffer *restrict newbuf =
		realloc(vbuf, sizeof(struct vbuffer) + cap);
	if (newbuf == NULL) {
		return vbuf;
	}
	vbuf = newbuf;
	*((size_t *)&vbuf->cap) = cap;
	vbuf->len = MIN(cap, len);
	return vbuf;
}

struct vbuffer *vbuf_reserve(struct vbuffer *vbuf, size_t want)
{
	size_t cap = 0;
	if (vbuf != NULL) {
		cap = vbuf->cap;
	}
	if (cap < want) {
		return vbuf_alloc(vbuf, want);
	}
	return vbuf;
}

static struct vbuffer *vbuf_grow(struct vbuffer *vbuf, const size_t want)
{
	size_t cap = (vbuf != NULL) ? vbuf->cap : 0;
	if (want <= cap) {
		return vbuf;
	}
	const size_t threshold1 = 256;
	const size_t threshold2 = 4096;
	while (cap < want) {
		size_t grow;
		if (cap < threshold1) {
			grow = threshold1;
		} else if (cap < threshold2) {
			grow = cap;
		} else {
			grow = cap / 4 + 3 * threshold2 / 4;
		}
		if (cap >= SIZE_MAX - grow) {
			/* overflow */
			cap = want;
			break;
		}
		cap += grow;
	}
	return vbuf_alloc(vbuf, cap);
}

struct vbuffer *vbuf_append(
	struct vbuffer *restrict vbuf, const unsigned char *data,
	const size_t n)
{
	if (n == 0) {
		return vbuf;
	}
	size_t want = n;
	if (vbuf != NULL) {
		want += vbuf->len;
		vbuf = vbuf_grow(vbuf, want);
	} else {
		vbuf = vbuf_reserve(vbuf, want);
	}
	if (vbuf == NULL) {
		return NULL;
	}
	(void)memcpy(vbuf->data + vbuf->len, data, n);
	vbuf->len += n;
	return vbuf;
}

struct vbuffer *
vbuf_appendf(struct vbuffer *restrict vbuf, const char *format, ...)
{
	char *b = NULL;
	size_t maxlen = 0;
	if (vbuf != NULL) {
		b = (char *)(vbuf->data + vbuf->len);
		maxlen = vbuf->cap - vbuf->len;
	}

	va_list args, args0;
	va_start(args, format);
	va_copy(args0, args);
	int ret = vsnprintf(b, maxlen, format, args0);
	va_end(args0);
	if (ret <= 0) {
		va_end(args);
		return vbuf;
	}
	size_t want = (size_t)ret + (size_t)1;
	if (vbuf != NULL) {
		want += vbuf->len;
		if (want <= vbuf->cap) {
			/* first try success */
			va_end(args);
			vbuf->len += (size_t)ret;
			return vbuf;
		}
		vbuf = vbuf_grow(vbuf, want);
	} else {
		vbuf = vbuf_reserve(vbuf, want);
	}
	if (vbuf == NULL) {
		va_end(args);
		return NULL;
	}
	assert(vbuf->cap == want);
	maxlen = vbuf->cap - vbuf->len;
	b = (char *)(vbuf->data + vbuf->len);
	ret = vsnprintf(b, maxlen, format, args);
	va_end(args);
	if (ret > 0) {
		vbuf->len += (size_t)ret;
	}
	return vbuf;
}
