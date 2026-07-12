/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "buffer.h"

#include "meta/minmax.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* vsnprintf may report more chars than fit; len only advances by what was
 * actually written. */
int buf_vappendf(
	struct buffer *restrict buf, const char *restrict format, va_list args)
{
	const size_t maxlen = buf->cap - buf->len;
	if (maxlen == 0) {
		return 0;
	}
	char *restrict s = (char *)(buf->data + buf->len);
	const int ret = vsnprintf(s, maxlen, format, args);
	if (ret > 0) {
		buf->len += MIN((size_t)ret, maxlen - 1);
	}
	return ret;
}

int buf_appendf(struct buffer *restrict buf, const char *restrict format, ...)
{
	va_list args;
	va_start(args, format);
	const int ret = buf_vappendf(buf, format, args);
	va_end(args);
	return ret;
}

/**
 * Growth strategy:
 * - Below 256 bytes: jump to 256.
 * - Below 4096 bytes: double the current capacity.
 * - 4096 and above: grow by cap/4 + 3*4096/4 to moderate fragmentation.
 */
struct vbuffer *vbuf_grow(struct vbuffer *vbuf, const size_t want)
{
	const size_t maxcap = SIZE_MAX - sizeof(struct vbuffer) - 1;
	size_t cap = 0, len = 0;
	if (vbuf != NULL) {
		cap = vbuf->cap;
		len = vbuf->len;
	}
	if (want <= cap || cap >= maxcap || want > maxcap) {
		return vbuf;
	}
	const size_t threshold1 = 256;
	const size_t threshold2 = 4096;
	do {
		size_t grow;
		if (cap < threshold1) {
			grow = threshold1;
		} else if (cap < threshold2) {
			grow = cap;
		} else {
			grow = cap / 4 + 3 * threshold2 / 4;
		}
		if (grow > maxcap || cap >= maxcap - grow) {
			/* overflow */
			cap = want;
			break;
		}
		cap += grow;
	} while (cap < want);

	/* reserve 1 extra byte for null terminator */
	struct vbuffer *newbuf =
		realloc(vbuf, sizeof(struct vbuffer) + cap + 1);
	if (newbuf == NULL) {
		/* retry with minimal required capacity */
		cap = want;
		newbuf = realloc(vbuf, sizeof(struct vbuffer) + cap + 1);
		if (newbuf == NULL) {
			return vbuf;
		}
	}
	newbuf->cap = cap;
	newbuf->len = len; /* initialize the new buffer */
	return newbuf;
}

struct vbuffer *
vbuf_append(struct vbuffer *restrict vbuf, const void *restrict data, size_t n)
{
	if (n == 0) {
		return vbuf;
	}
	if (vbuf->cap == vbuf->len) {
		/* allocation failure occurred, skip */
		return vbuf;
	}
	/* 1 extra byte is reserved for detecting allocation failures */
	if (n < SIZE_MAX - vbuf->len - 1) {
		const size_t want = vbuf->len + n + 1;
		vbuf = vbuf_grow(vbuf, want);
	}
	/* when failed, append as much as possible */
	if (n > vbuf->cap - vbuf->len) {
		n = vbuf->cap - vbuf->len;
	}
	unsigned char *restrict b = vbuf->data + vbuf->len;
	(void)memcpy(b, data, n);
	vbuf->len += n;
	/* null-byte is reserved by vbuf_alloc() */
	b[n] = '\0';
	return vbuf;
}

int vbuf_vappendf(
	struct vbuffer **pvbuf, const char *restrict format, va_list args)
{
	struct vbuffer *restrict vbuf = *pvbuf;
	if (vbuf->cap == vbuf->len) {
		/* allocation failure occurred, skip */
		return -1;
	}

	/* null-byte is reserved by vbuf_alloc() */
	int ret;
	{
		char *restrict s = (char *)(vbuf->data + vbuf->len);
		const size_t maxlen = vbuf->cap - vbuf->len;
		/* args may be needed again below; vsnprintf may only consume
		 * a va_list once, so pass a copy here. */
		va_list args0;
		va_copy(args0, args);
		ret = vsnprintf(s, maxlen + 1, format, args0);
		va_end(args0);
	}
	if (ret <= 0) {
		return ret;
	}
	/* 1 extra byte is reserved for detecting allocation failures */
	const size_t want = vbuf->len + (size_t)ret + 1;
	if (want <= vbuf->cap) {
		/* first try success */
		vbuf->len += (size_t)ret;
		return ret;
	}
	*pvbuf = vbuf_grow(vbuf, want);
	vbuf = *pvbuf;
	/* when failed, append as much as possible */
	{
		char *restrict s = (char *)(vbuf->data + vbuf->len);
		const size_t maxlen = vbuf->cap - vbuf->len;
		(void)vsnprintf(s, maxlen + 1, format, args);
		if ((size_t)ret < maxlen) {
			vbuf->len += (size_t)ret;
		} else {
			vbuf->len = vbuf->cap;
		}
	}
	return ret;
}

int vbuf_appendf(struct vbuffer **pvbuf, const char *restrict format, ...)
{
	va_list args;
	va_start(args, format);
	const int ret = vbuf_vappendf(pvbuf, format, args);
	va_end(args);
	return ret;
}
