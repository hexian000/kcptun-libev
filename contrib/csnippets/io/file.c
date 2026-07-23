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

/* Collect a failed stdio transfer's errno (ferror alone is a sticky boolean
 * that discards it) and clear the indicator. errno is zeroed before each
 * transfer below, so a zero here means stdio failed without setting it,
 * mapped to -1 rather than "Success". Deliberately quiet: when this stream is
 * the slog writer sink, write/flush run under slog's output lock and must not
 * log through slog; the caller may log where that cannot happen. */
static int file_error(FILE *restrict f)
{
	const int err = errno;
	clearerr(f);
	return err != 0 ? err : -1;
}

static int file_read(void *p, void *buf, size_t *restrict len)
{
	struct io_stream *restrict s = p;
	FILE *f = s->data;
	const size_t want = *len;
	/* clear any indicator carried in on this stream (e.g. a logged and
	 * ignored setvbuf failure) and zero errno, so ferror and errno below
	 * reflect only this fread */
	clearerr(f);
	errno = 0;
	*len = fread(buf, sizeof(unsigned char), want, f);
	/* a short fread is legitimate EOF; only ferror marks a real failure */
	if (ferror(f)) {
		const int err = file_error(f);
		if (err > 0) {
			LOGE_F("fread: (%d) %s", err, strerror(err));
		} else {
			LOGE("fread: failed");
		}
		return err;
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
		return file_error(f);
	}
	return 0;
}

static int file_flush(void *p)
{
	struct io_stream *restrict s = p;
	FILE *f = s->data;
	errno = 0;
	if (fflush(f) != 0) {
		return file_error(f);
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
	return fclose(f);
}

static int file_close(void *p)
{
	struct io_stream *restrict s = p;
	const int ret = file_fclose(s->data);
	free(s);
	return ret;
}

struct io_stream *io_filereader(FILE *f)
{
	if (f == NULL) {
		return NULL;
	}
	if (setvbuf(f, NULL, _IONBF, 0) != 0) {
		const int err = errno;
		LOGE_F("setvbuf: (%d) %s", err, strerror(err));
	}
	struct io_stream *restrict s = malloc(sizeof(struct io_stream));
	if (s == NULL) {
		if (file_fclose(f) != 0) {
			const int err = errno;
			LOGE_F("fclose: (%d) %s", err, strerror(err));
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
	if (setvbuf(f, NULL, _IONBF, 0) != 0) {
		const int err = errno;
		LOGE_F("setvbuf: (%d) %s", err, strerror(err));
	}
	struct io_stream *restrict s = malloc(sizeof(struct io_stream));
	if (s == NULL) {
		if (file_fclose(f) != 0) {
			const int err = errno;
			LOGE_F("fclose: (%d) %s", err, strerror(err));
		}
		return NULL;
	}
	static const struct io_stream_vftable vftable = {
		.write = file_write,
		.flush = file_flush,
		.close = file_close,
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
		return NULL;
	}
	void *buf = malloc(*len);
	if (!buf) {
		if (fclose(fp) != 0) {
			const int err = errno;
			LOGE_F("fclose: (%d) %s", err, strerror(err));
		}
		return NULL;
	}
	const size_t nread = fread(buf, 1, *len, fp);
	/* fread returns a short count for both clean EOF and a genuine read
	 * error; ferror() must be checked before fclose() invalidates fp */
	const bool read_error = ferror(fp) != 0;
	if (fclose(fp) != 0) {
		const int err = errno;
		LOGE_F("fclose: (%d) %s", err, strerror(err));
	}
	if (read_error) {
		LOGE("io_readfile: read error");
		free(buf);
		return NULL;
	}
	if (nread >= *len) {
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
	if (!path || !data || !len) {
		return false;
	}
	FILE *fp = fopen(path, "wb");
	if (!fp) {
		return false;
	}
	errno = 0;
	const size_t nwrite = fwrite(data, 1, *len, fp);
	const bool short_write = nwrite != *len;
	if (short_write) {
		/* capture errno now, before fclose can overwrite it; a short
		 * fwrite (e.g. ENOSPC on a full filesystem) is unambiguously an
		 * error, and every other error site in this module logs, so log
		 * here too rather than returning a bare false. errno may be 0 if
		 * stdio failed without setting it. */
		const int err = errno;
		if (err != 0) {
			LOGE_F("fwrite: (%d) %s", err, strerror(err));
		} else {
			LOGE_F("%s", "fwrite: failed");
		}
	}
	const bool close_failed = fclose(fp) != 0;
	if (close_failed) {
		const int err = errno;
		LOGE_F("fclose: (%d) %s", err, strerror(err));
	}
	*len = nwrite;
	return !short_write && !close_failed;
}

const char *
io_readutf8(const unsigned char *restrict data, size_t *restrict len)
{
	if (!data || !len) {
		return NULL;
	}
	if (*len >= 3 && data[0] == 0xEF && data[1] == 0xBB &&
	    data[2] == 0xBF) {
		*len -= 3;
		return (const char *)(data + 3);
	}
	if (*len >= 2 && ((data[0] == 0xFF && data[1] == 0xFE) ||
			  (data[0] == 0xFE && data[1] == 0xFF))) {
		return NULL;
	}
	/* UTF-32BE BOM. The UTF-32LE BOM (FF FE 00 00) is already rejected by
	 * the UTF-16LE check above (its FF FE prefix), so only the BE form
	 * needs a dedicated test here. */
	if (*len >= 4 && data[0] == 0x00 && data[1] == 0x00 &&
	    data[2] == 0xFE && data[3] == 0xFF) {
		return NULL;
	}
	return (const char *)data;
}
