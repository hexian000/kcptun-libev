/* csnippets (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "slog.h"
#include "buffer.h"

#if HAVE_SYSLOG
#include <syslog.h>
#endif

#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#if SLOG_MT_SAFE
#include <stdatomic.h>
#include <threads.h>
#endif

typedef void (*slog_writer_fn)(
	const int level, const char *file, const int line,
	struct slog_extra *extra, const char *format, va_list args);

static const unsigned char slog_level_char[] = {
	'-', 'F', 'E', 'W', 'I', 'I', 'D', 'V', 'V',
};

FILE *slog_output;

#if SLOG_MT_SAFE
mtx_t slog_output_mu;

atomic_int slog_level_ = LOG_LEVEL_VERBOSE;
static _Atomic(slog_writer_fn) slog_writer;
static _Atomic(const char *) slog_fileprefix;

#define THRD_ASSERT(expr)                                                      \
	do {                                                                   \
		const int status = (expr);                                     \
		(void)status;                                                  \
		assert(status == thrd_success);                                \
	} while (0)

#define MTX_LOCK(mu) THRD_ASSERT(mtx_lock(mu))
#define MTX_UNLOCK(mu) THRD_ASSERT(mtx_unlock(mu))

#define ATOMIC_STORE(object, desired)                                          \
	atomic_store_explicit(object, desired, memory_order_relaxed)
#define ATOMIC_LOAD(object) atomic_load_explicit(object, memory_order_relaxed)

static _Thread_local struct {
	BUFFER_HDR;
	unsigned char data[BUFSIZ];
} slog_buffer;

static once_flag slog_init_flag = ONCE_FLAG_INIT;
static void slog_init(void)
{
	THRD_ASSERT(mtx_init(&slog_output_mu, mtx_plain));
	atomic_init(&slog_level_, LOG_LEVEL_SILENCE);
	atomic_init(&slog_writer, NULL);
	atomic_init(&slog_fileprefix, NULL);
}

#define SLOG_INIT() call_once(&slog_init_flag, &slog_init)
#else
int slog_level_ = LOG_LEVEL_SILENCE;
static slog_writer_fn slog_writer = NULL;
static const char *slog_fileprefix = NULL;

#define MTX_LOCK(mu) (void)(0)
#define MTX_UNLOCK(mu) (void)(0)

#define ATOMIC_STORE(object, desired) *(object) = (desired)
#define ATOMIC_LOAD(object) (*(object))

static struct {
	BUFFER_HDR;
	unsigned char data[BUFSIZ];
} slog_buffer;

#define SLOG_INIT() (void)(0)
#endif /* SLOG_MT_SAFE */

#define TIME_LAYOUT "2006-01-02T15:04:05-0700"

#if HAVE_LOCALTIME_R
#define APPEND_TIMESTAMP(buf, timer)                                           \
	do {                                                                   \
		struct tm log_tm;                                              \
		const int ret = strftime(                                      \
			(char *)((buf).data + (buf).len),                      \
			((buf).cap - (buf).len), "%FT%T%z",                    \
			localtime_r((timer), &log_tm));                        \
		assert(ret == sizeof(TIME_LAYOUT) - 1);                        \
		(buf).len += ret;                                              \
	} while (0)
#else
#define APPEND_TIMESTAMP(buf, timer)                                           \
	do {                                                                   \
		const int ret = strftime(                                      \
			(char *)((buf).data + (buf).len),                      \
			((buf).cap - (buf).len), "%FT%T%z",                    \
			localtime((timer)));                                   \
		assert(ret == sizeof(TIME_LAYOUT) - 1);                        \
		(buf).len += ret;                                              \
	} while (0)
#endif /* HAVE_LOCALTIME_R */

static const char *slog_filename(const char *file)
{
	const char *prefix = ATOMIC_LOAD(&slog_fileprefix);
	if (prefix == NULL) {
		return file;
	}
	const char *s = file;
	while (*prefix != '\0') {
		if (*s == '\0' || *s != *prefix) {
			return file;
		}
		prefix++, s++;
	}
	return s;
}

static void slog_write_file(
	const int level, const char *file, const int line,
	struct slog_extra *extra, const char *format, va_list args)
{
	const time_t log_now = time(NULL);
	BUF_INIT(slog_buffer, 2);
	slog_buffer.data[0] = slog_level_char[level];
	slog_buffer.data[1] = ' ';
	APPEND_TIMESTAMP(slog_buffer, &log_now);
	BUF_APPENDF(slog_buffer, " %s:%d ", slog_filename(file), line);
	const int ret = BUF_VAPPENDF(slog_buffer, format, args);
	if (ret < 0) {
		BUF_APPENDSTR(slog_buffer, "(log format error)");
	}
	/* overwritting the null terminator is not an issue */
	BUF_APPENDSTR(slog_buffer, "\n");

	MTX_LOCK(&slog_output_mu);
	(void)fwrite(
		slog_buffer.data, sizeof(slog_buffer.data[0]), slog_buffer.len,
		slog_output);
	if (extra != NULL) {
		extra->func(extra->data, slog_output);
	}
	MTX_UNLOCK(&slog_output_mu);
}

#if HAVE_SYSLOG
static void slog_write_syslog(
	const int level, const char *file, const int line,
	struct slog_extra *extra, const char *format, va_list args)
{
	static const int slog_level_map[] = {
		LOG_ALERT, LOG_CRIT,  LOG_ERR,	 LOG_WARNING, LOG_NOTICE,
		LOG_INFO,  LOG_DEBUG, LOG_DEBUG, LOG_DEBUG,
	};

	file = slog_filename(file);
	BUF_INIT(slog_buffer, 0);
	const int ret = BUF_VAPPENDF(slog_buffer, format, args);
	if (ret < 0) {
		BUF_APPENDSTR(slog_buffer, "(log format error)");
	}

	MTX_LOCK(&slog_output_mu);
	syslog(LOG_USER | slog_level_map[level], "%c %s:%d %.*s",
	       slog_level_char[level], file, line, (int)slog_buffer.len,
	       slog_buffer.data);
	(void)extra;
	MTX_UNLOCK(&slog_output_mu);
}
#endif

void slog_setlevel(const int level)
{
	SLOG_INIT();
	ATOMIC_STORE(&slog_level_, level);
}

void slog_setoutput(const int type, ...)
{
	SLOG_INIT();
	va_list args;
	va_start(args, type);
	switch (type) {
	case SLOG_OUTPUT_DISCARD: {
		ATOMIC_STORE(&slog_writer, NULL);
	} break;
	case SLOG_OUTPUT_FILE: {
		FILE *stream = va_arg(args, FILE *);
		const int status = setvbuf(stream, NULL, _IONBF, 0);
		assert(status == 0);
		(void)status;
		MTX_LOCK(&slog_output_mu);
		slog_output = stream;
		MTX_UNLOCK(&slog_output_mu);
		ATOMIC_STORE(&slog_writer, slog_write_file);
	} break;
	case SLOG_OUTPUT_SYSLOG: {
#if HAVE_SYSLOG
		const char *ident = va_arg(args, const char *);
		openlog(ident, LOG_PID | LOG_NDELAY, LOG_USER);
		ATOMIC_STORE(&slog_writer, slog_write_syslog);
#else
		ATOMIC_STORE(&slog_writer, NULL);
#endif
	} break;
	}
	va_end(args);
}

void slog_setfileprefix(const char *prefix)
{
	SLOG_INIT();
	ATOMIC_STORE(&slog_fileprefix, prefix);
}

void slog_vwrite(
	int level, const char *file, int line, struct slog_extra *extra,
	const char *format, va_list args)
{
	SLOG_INIT();
	const slog_writer_fn write = ATOMIC_LOAD(&slog_writer);
	if (write == NULL) {
		return;
	}
	write(level, file, line, extra, format, args);
}

void slog_write(
	const int level, const char *file, const int line,
	struct slog_extra *extra, const char *format, ...)
{
	SLOG_INIT();
	const slog_writer_fn write = ATOMIC_LOAD(&slog_writer);
	if (write == NULL) {
		return;
	}
	va_list args;
	va_start(args, format);
	write(level, file, line, extra, format, args);
	va_end(args);
}
