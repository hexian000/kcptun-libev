/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "file.h"

#include "stream.h"
#include "utils/slog.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The stream implementation below is plain ISO C: stdio is not required to set
 * errno on failure, so each call is made with errno cleared and a failure
 * reports what the call left there, or EIO when it left nothing -- never a bare
 * -1, so the code stays in the errno space the fd backend reports in. These are
 * deliberately quiet: when this stream is the slog writer sink, write/flush run
 * under slog's output lock and must not log through slog; the caller may log
 * where that cannot happen. */

/* Read errno exactly once, right after the failing stdio call. */
static int stdio_error(void)
{
	const int err = errno;
	return err != 0 ? err : EIO;
}

static int file_read(void *p, void *buf, size_t *restrict len)
{
	struct io_stream *restrict s = p;
	FILE *f = s->data;
	const size_t want = *len;
	/* clear any indicator the caller's stream carried in, so ferror below
	 * reflects only this fread */
	clearerr(f);
	errno = 0;
	*len = fread(buf, sizeof(unsigned char), want, f);
	/* a short fread is legitimate EOF; only ferror marks a real failure */
	if (ferror(f)) {
		return stdio_error();
	}
	return 0;
}

static int file_write(void *p, const void *buf, size_t *restrict len)
{
	struct io_stream *restrict s = p;
	FILE *f = s->data;
	const size_t want = *len;
	clearerr(f);
	errno = 0;
	*len = fwrite(buf, sizeof(unsigned char), want, f);
	/* a short fwrite is unambiguously an error -- decide from the transfer's
	 * own count rather than the sticky indicator */
	if (*len < want) {
		return stdio_error();
	}
	return 0;
}

static int file_flush(void *p)
{
	struct io_stream *restrict s = p;
	FILE *f = s->data;
	errno = 0;
	if (fflush(f) != 0) {
		return stdio_error();
	}
	return 0;
}

/* Close f unless it is a standard stream: ISO C does not forbid fclose on
 * stdin/stdout/stderr, but using them afterward is undefined behavior and the
 * rest of the program still expects them. Shared by file_close and the
 * constructors' cleanup so the policy cannot drift between them. */
static int file_fclose(FILE *restrict f)
{
	if (f == stdin || f == stdout || f == stderr) {
		return 0;
	}
	errno = 0;
	return fclose(f) != 0 ? stdio_error() : 0;
}

static int file_close(void *p)
{
	struct io_stream *restrict s = p;
	const int ret = file_fclose(s->data);
	free(s);
	return ret;
}

/* The writer's close: a standard output stream is left open, but it is still
 * flushed, so close stays the last point that reports a write error the
 * buffering deferred -- as fclose does for every other file. stdin is excluded:
 * fflush on an input stream is undefined in ISO C. */
static int file_writer_close(void *p)
{
	struct io_stream *restrict s = p;
	FILE *f = s->data;
	if (f == stdout || f == stderr) {
		free(s);
		errno = 0;
		return fflush(f) != 0 ? stdio_error() : 0;
	}
	return file_close(p);
}

struct io_stream *io_filereader(FILE *f)
{
	if (f == NULL) {
		return NULL;
	}
	struct io_stream *restrict s = malloc(sizeof(struct io_stream));
	if (s == NULL) {
		if (file_fclose(f) != 0) {
			LOGE("fclose: failed");
		}
		return NULL;
	}
	static const struct io_stream_vftable vftable = {
		.read = file_read,
		.close = file_close,
	};
	*s = (struct io_stream){ &vftable, f };
	return s;
}

struct io_stream *io_filewriter(FILE *f)
{
	if (f == NULL) {
		return NULL;
	}
	struct io_stream *restrict s = malloc(sizeof(struct io_stream));
	if (s == NULL) {
		if (file_fclose(f) != 0) {
			LOGE("fclose: failed");
		}
		return NULL;
	}
	static const struct io_stream_vftable vftable = {
		.write = file_write,
		.flush = file_flush,
		.close = file_writer_close,
	};
	*s = (struct io_stream){ &vftable, f };
	return s;
}

unsigned char *io_readfile(const char *restrict path, size_t *restrict len)
{
	if (!path || !len) {
		return NULL;
	}
	FILE *fp = fopen(path, "rb");
	if (!fp) {
		/* log like the read and fclose failures below: a bare NULL
		 * conflates a missing file, a permission error and OOM, and
		 * this function reports no errno */
		const int err = errno;
		LOGE_F("fopen \"%s\": (%d) %s", path, err, strerror(err));
		return NULL;
	}
	void *buf = malloc(*len);
	if (!buf) {
		LOGOOM();
		if (fclose(fp) != 0) {
			LOGE("fclose: failed");
		}
		return NULL;
	}
	const size_t nread = fread(buf, 1, *len, fp);
	/* fread returns a short count for both clean EOF and a genuine read
	 * error; ferror() must be checked before fclose() invalidates fp */
	const bool read_error = ferror(fp) != 0;
	if (fclose(fp) != 0) {
		LOGE("fclose: failed");
	}
	if (read_error) {
		LOGE("io_readfile: read error");
		free(buf);
		return NULL;
	}
	if (nread >= *len) {
		/* log like the siblings: a bare NULL cannot tell this case -- the
		 * one a larger capacity would cure -- from the others */
		LOGE_F("io_readfile \"%s\": does not fit in %zu bytes", path,
		       *len);
		free(buf);
		return NULL;
	}
	unsigned char *out = realloc(buf, nread + 1);
	if (!out) {
		out = buf;
	}
	*len = nread;
	out[nread] = '\0';
	return out;
}

bool io_writefile(
	const char *restrict path, const unsigned char *restrict data,
	size_t *restrict len)
{
	if (!len) {
		return false;
	}
	if (!path || !data) {
		*len = 0;
		return false;
	}
	FILE *fp = fopen(path, "wb");
	if (!fp) {
		const int err = errno;
		LOGE_F("fopen \"%s\": (%d) %s", path, err, strerror(err));
		/* nothing was written; report the actual count rather than leaving
		 * *len at the requested value */
		*len = 0;
		return false;
	}
	const size_t nwrite = fwrite(data, 1, *len, fp);
	const bool short_write = nwrite != *len;
	if (short_write) {
		/* a short fwrite (e.g. ENOSPC on a full filesystem) is
		 * unambiguously an error, and every other error site in this
		 * module logs, so log here too rather than returning a bare
		 * false */
		LOGE("fwrite: failed");
	}
	const bool close_failed = fclose(fp) != 0;
	if (close_failed) {
		LOGE("fclose: failed");
	}
	*len = nwrite;
	return !short_write && !close_failed;
}
