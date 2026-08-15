/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "stream.h"

#include "io.h"

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int io_stream_direct_read(
	struct io_stream *restrict s, const void **restrict buf,
	size_t *restrict len)
{
	const io_direct_reader direct_read = s->vftable->direct_read;
	if (direct_read == NULL) {
		/* direct_read is optional; report unsupported instead of
		 * dereferencing a NULL vftable entry */
		*len = 0;
		return ENOTSUP;
	}
	return direct_read(s, buf, len);
}

int io_stream_read(
	struct io_stream *restrict s, void *restrict buf, size_t *restrict len)
{
	{
		const io_reader read = s->vftable->read;
		if (read != NULL) {
			return read(s, buf, len);
		}
	}
	const io_direct_reader direct_read = s->vftable->direct_read;
	if (direct_read == NULL) {
		/* neither read slot is supported; report unsupported instead of
		 * dereferencing a NULL vftable entry */
		*len = 0;
		return ENOTSUP;
	}
	int err = 0;
	size_t nread = 0;
	unsigned char *dst = buf;
	size_t dstsize = *len;
	while (dstsize > 0 && err == 0) {
		const void *src;
		size_t n = dstsize;
		err = direct_read(s, &src, &n);
		if (n == 0) {
			break;
		}
		memcpy(dst, src, n);
		dst += n;
		dstsize -= n;
		nread += n;
	}
	*len = nread;
	return err;
}

int io_stream_write(
	struct io_stream *restrict s, const void *restrict buf,
	size_t *restrict len)
{
	const io_writer write = s->vftable->write;
	if (write == NULL) {
		/* write is optional; report unsupported instead of
		 * dereferencing a NULL vftable entry */
		*len = 0;
		return ENOTSUP;
	}
	return write(s, buf, len);
}

int io_stream_flush(struct io_stream *restrict s)
{
	const io_flusher flush = s->vftable->flush;
	if (flush == NULL) {
		return 0;
	}
	return flush(s);
}

int io_stream_close(struct io_stream *restrict s)
{
	const io_closer close = s->vftable->close;
	if (close == NULL) {
		free(s);
		return 0;
	}
	return close(s);
}

int io_stream_copy(
	struct io_stream *restrict dst, struct io_stream *restrict src,
	void *restrict buf, const size_t bufsize)
{
	if (bufsize == 0) {
		/* Both paths use bufsize as the per-iteration read cap, so a
		 * zero-length buffer reads nothing yet would report a
		 * successful copy of an unconsumed source. Reject it. */
		return EINVAL;
	}

	if (src->vftable->direct_read != NULL) {
		/* The source can hand out its own bytes, so write them from
		 * there. Going through io_stream_read instead would stage them
		 * in buf first -- the very copy direct_read exists to avoid --
		 * and cost one extra zero-length write at EOF. */
		for (;;) {
			const void *span;
			size_t nread = bufsize;
			const int srcerr =
				io_stream_direct_read(src, &span, &nread);
			int dsterr = 0;
			size_t nwritten = nread;
			if (nread > 0) {
				dsterr = io_stream_write(dst, span, &nwritten);
			}
			if (srcerr != 0) {
				return srcerr;
			}
			if (dsterr != 0) {
				return dsterr;
			}
			if (nwritten < nread) {
				/* short write: per io_stream_write's
				 * contract, the caller must treat this
				 * as an error; the sink ran out of
				 * room without naming a cause */
				return ENOSPC;
			}
			if (nread == 0) {
				return 0;
			}
		}
	}

	for (;;) {
		size_t nread = bufsize;
		const int srcerr = io_stream_read(src, buf, &nread);
		size_t nwritten = nread;
		const int dsterr = io_stream_write(dst, buf, &nwritten);
		if (srcerr != 0) {
			return srcerr;
		}
		if (dsterr != 0) {
			return dsterr;
		}
		if (nwritten < nread) {
			/* short write: per io_stream_write's contract, the
			 * caller must treat this as an error; the sink ran out
			 * of room without naming a cause */
			return ENOSPC;
		}
		if (nread < bufsize) {
			/* short read: per io_stream_read's contract, EOF. Reading
			 * again would block a terminal, whose EOF is not sticky,
			 * until the user sent a second one. */
			return 0;
		}
	}
}
