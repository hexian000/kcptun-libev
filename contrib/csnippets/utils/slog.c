/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "slog.h"
#include "buffer.h"

#include <ctype.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int slog_level = LOG_LEVEL_VERBOSE;
FILE *slog_file = NULL;

const unsigned char slog_level_char[] = {
	'-', 'F', 'E', 'W', 'I', 'D', 'V',
};

_Thread_local struct {
	BUFFER_HDR;
	unsigned char data[BUFSIZ];
} slog_buffer;

#if defined(_MSC_VER)
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

#define STRLEN(s) (sizeof(s) - 1)

#if HAVE_SYSLOG
static void slog_write_syslog(
	const int level, const char *path, const int line, const char *format,
	va_list args)
{
	static const int slog_level_map[] = {
		LOG_EMERG, LOG_CRIT,  LOG_ERR,	 LOG_WARNING,
		LOG_INFO,  LOG_DEBUG, LOG_DEBUG,
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

static inline int format_timestamp(char *s, size_t maxsize, const time_t *timer)
{
#if HAVE_LOCALTIME_R
	struct tm t;
	return strftime(s, maxsize, "%FT%T%z", localtime_r(timer, &t));
#else
	return strftime(s, maxsize, "%FT%T%z", localtime(timer));
#endif
}

void slog_write(
	const int level, const char *path, const int line, const char *format,
	...)
{
	FILE *stream = slog_file;
	if (stream == NULL) {
		va_list args;
		va_start(args, format);
		slog_write_syslog(level, path, line, format, args);
		va_end(args);
		return;
	}
	const time_t log_now = time(NULL);
	BUF_INIT(slog_buffer, 2);
	slog_buffer.data[0] = slog_level_char[level];
	slog_buffer.data[1] = ' ';
	slog_buffer.len += format_timestamp(
		(char *)slog_buffer.data + slog_buffer.len,
		slog_buffer.cap - slog_buffer.len, &log_now);

	const char *log_filename = strrchr(path, PATH_SEPARATOR);
	if (log_filename && *log_filename) {
		log_filename++;
	} else {
		log_filename = path;
	}
	BUF_APPENDF(slog_buffer, " %s:%d ", log_filename, line);

	va_list args;
	va_start(args, format);
	const int ret = BUF_VAPPENDF(slog_buffer, format, args);
	va_end(args);
	if (ret < 0) {
		BUF_APPENDCONST(slog_buffer, "<log format error>");
	}
	/* overwritting the null terminator is not an issue */
	BUF_APPENDCONST(slog_buffer, "\n");

	(void)fwrite(
		slog_buffer.data, sizeof(slog_buffer.data[0]), slog_buffer.len,
		stream);
	(void)fflush(stream);
}
