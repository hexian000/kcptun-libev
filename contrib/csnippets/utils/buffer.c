/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "buffer.h"
#include "math/intlog2.h"

#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

bool buf_appendf(void *buf, const char *format, ...)
{
	struct vbuffer *restrict vbuf = buf;
	char *b = (char *)(vbuf->data + vbuf->len);
	const size_t maxlen = vbuf->cap - vbuf->len;
	if (maxlen == 0) {
		return 0;
	}
	va_list args;
	va_start(args, format);
	const int ret = vsnprintf((char *)b, maxlen, format, args);
	va_end(args);
	const bool ok = ret >= 0 && (size_t)ret < maxlen;
	if (ok) {
		vbuf->len += (size_t)ret;
	}
	return ok;
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
		free(vbuf);
		return NULL;
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

static struct vbuffer *vbuf_grow(struct vbuffer *vbuf, size_t want)
{
	want = MAX(want, 255);
	/* ceil to 2^n-1 */
	const unsigned n = ((size_t)1) << intlog2(want);
	want = (n << 1u) - 1u;
	size_t cap = 0;
	if (vbuf != NULL) {
		cap = vbuf->cap;
	}
	if (cap < want) {
		return vbuf_alloc(vbuf, want);
	}
	return vbuf;
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
	}
	vbuf = vbuf_grow(vbuf, want);
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
	va_list args, args0;
	va_start(args, format);
	va_copy(args0, args);
	const int reserve = vsnprintf(NULL, 0, format, args0);
	va_end(args0);
	if (reserve <= 0) {
		va_end(args);
		return vbuf;
	}
	size_t want = (size_t)reserve + (size_t)1;
	if (vbuf != NULL) {
		want += vbuf->len;
	}
	vbuf = vbuf_grow(vbuf, want);
	if (vbuf == NULL) {
		va_end(args);
		return NULL;
	}
	const size_t maxlen = vbuf->cap - vbuf->len;
	assert(maxlen > 0);
	char *b = (char *)(vbuf->data + vbuf->len);
	const int ret = vsnprintf(b, maxlen, format, args);
	va_end(args);
	if (ret > 0) {
		vbuf->len += MIN((size_t)ret, maxlen - 1);
	}
	return vbuf;
}
