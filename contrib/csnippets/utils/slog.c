/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
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

int slog_level = LOG_LEVEL_VERBOSE;
static int slog_output_type = SLOG_OUTPUT_DISCARD;
static FILE *slog_file = NULL;

static const unsigned char slog_level_char[] = {
	'-', 'F', 'E', 'W', 'N', 'I', 'D', 'V',
};

static _Thread_local struct {
	BUFFER_HDR;
	unsigned char data[BUFSIZ];
} slog_buffer;

void slog_setoutput(const int type, ...)
{
	va_list args;
	va_start(args, type);
	switch (type) {
	case SLOG_OUTPUT_DISCARD: {
		slog_file = NULL;
	} break;
	case SLOG_OUTPUT_FILE: {
		FILE *stream = va_arg(args, FILE *);
		assert(stream != NULL);
		(void)setvbuf(stream, NULL, _IONBF, 0);
		slog_file = stream;
	} break;
	case SLOG_OUTPUT_SYSLOG: {
#if HAVE_SYSLOG
		const char *ident = va_arg(args, const char *);
		openlog(ident, LOG_PID | LOG_NDELAY, LOG_USER);
#endif
		slog_file = NULL;
	} break;
	}
	va_end(args);
	slog_output_type = type;
}

#if defined(_MSC_VER)
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

#if HAVE_LOCALTIME_R
#define APPEND_TIMESTAMP(buf, timer)                                           \
	do {                                                                   \
		struct tm log_tm;                                              \
		const int ret = strftime(                                      \
			(char *)((buf).data + (buf).len),                      \
			((buf).cap - (buf).len), "%FT%T%z",                    \
			localtime_r((timer), &log_tm));                        \
		assert(ret > 0);                                               \
		(buf).len += ret;                                              \
	} while (0)
#else
#define APPEND_TIMESTAMP(buf, timer)                                           \
	do {                                                                   \
		const int ret = strftime(                                      \
			(char *)((buf).data + (buf).len),                      \
			((buf).cap - (buf).len), "%FT%T%z",                    \
			localtime((timer)));                                   \
		assert(ret > 0);                                               \
		(buf).len += ret;                                              \
	} while (0)
#endif

static void slog_write_file(
	const int level, const char *path, const int line, const char *format,
	va_list args)
{
	const time_t log_now = time(NULL);
	BUF_INIT(slog_buffer, 2);
	slog_buffer.data[0] = slog_level_char[level];
	slog_buffer.data[1] = ' ';
	APPEND_TIMESTAMP(slog_buffer, &log_now);

	const char *log_filename = strrchr(path, PATH_SEPARATOR);
	if (log_filename && *log_filename) {
		log_filename++;
	} else {
		log_filename = path;
	}
	BUF_APPENDF(slog_buffer, " %s:%d ", log_filename, line);

	const int ret = BUF_VAPPENDF(slog_buffer, format, args);
	if (ret < 0) {
		BUF_APPENDCONST(slog_buffer, "<log format error>");
	}
	/* overwritting the null terminator is not an issue */
	BUF_APPENDCONST(slog_buffer, "\n");

	(void)fwrite(
		slog_buffer.data, sizeof(slog_buffer.data[0]), slog_buffer.len,
		slog_file);
}

#if HAVE_SYSLOG
static void slog_write_syslog(
	const int level, const char *path, const int line, const char *format,
	va_list args)
{
	static const int slog_level_map[] = {
		LOG_ALERT,  LOG_CRIT, LOG_ERR,	 LOG_WARNING,
		LOG_NOTICE, LOG_INFO, LOG_DEBUG, LOG_DEBUG,
	};

	const char *log_filename = strrchr(path, PATH_SEPARATOR);
	if (log_filename && *log_filename) {
		log_filename++;
	} else {
		log_filename = path;
	}

	BUF_INIT(slog_buffer, 0);
	const int ret = BUF_VAPPENDF(slog_buffer, format, args);
	if (ret < 0) {
		BUF_APPENDCONST(slog_buffer, "<log format error>");
	}

	syslog(LOG_USER | slog_level_map[(level)], "%c %s:%d %.*s",
	       slog_level_char[level], log_filename, (line),
	       (int)slog_buffer.len, slog_buffer.data);
}
#endif

void slog_write(
	const int level, const char *path, const int line, const char *format,
	...)
{
	switch (slog_output_type) {
	case SLOG_OUTPUT_DISCARD:
		return;
	case SLOG_OUTPUT_FILE: {
		va_list args;
		va_start(args, format);
		slog_write_file(level, path, line, format, args);
		va_end(args);
	} break;
	case SLOG_OUTPUT_SYSLOG: {
#if HAVE_SYSLOG
		va_list args;
		va_start(args, format);
		slog_write_syslog(level, path, line, format, args);
		va_end(args);
#endif
	} break;
	}
}
