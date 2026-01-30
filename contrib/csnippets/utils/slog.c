/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "slog.h"
#include "buffer.h"

#if HAVE_SYSLOG
#include <syslog.h>
#endif

#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#if SLOG_MT_SAFE
#include <stdatomic.h>
#include <threads.h>
#endif

#define SLOG_BUFSIZE 4096

typedef void (*slog_printer_fn)(
	int level, const char *file, int line, const struct slog_extra *extra,
	const char *format, va_list args);

static const unsigned char slog_level_char[] = {
	'-', 'F', 'E', 'W', 'I', 'I', 'D', 'V', 'V',
};

/* ANSI escape codes */
#define ANSI_ESC "\x1b"
#define ANSI_CSI ANSI_ESC "["
#define ANSI_CSI_N(n) ANSI_CSI #n "m"
#define ANSI_CSI_FG(n, fg) ANSI_CSI #n ";" #fg "m"
#define ANSI_CSI_BG(n, fg, bg) ANSI_CSI #n ";" #fg ";" #bg "m"
#define ANSI_CSI_RESET ANSI_CSI_N(0)

static const char *slog_level_color[] = {
	ANSI_CSI_FG(, 96), ANSI_CSI_BG(, 97, 41), ANSI_CSI_FG(, 91),
	ANSI_CSI_FG(, 93), ANSI_CSI_FG(, 92),	  ANSI_CSI_FG(, 92),
	ANSI_CSI_FG(, 96), ANSI_CSI_FG(, 97),	  ANSI_CSI_FG(, 37),
};

FILE *slog_output;

#if SLOG_MT_SAFE
mtx_t slog_output_mu;

atomic_int slog_level_ = LOG_LEVEL_VERBOSE;
atomic_uint slog_flags_ = 0;
static _Atomic(slog_printer_fn) slog_printer;
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
	atomic_store_explicit(object, desired, memory_order_release)
#define ATOMIC_LOAD(object) atomic_load_explicit(object, memory_order_acquire)

static _Thread_local struct {
	BUFFER_HDR;
	unsigned char data[SLOG_BUFSIZE];
} slog_buffer;

static once_flag slog_init_flag = ONCE_FLAG_INIT;
static void slog_init(void)
{
	THRD_ASSERT(mtx_init(&slog_output_mu, mtx_plain));
	atomic_init(&slog_level_, LOG_LEVEL_SILENCE);
	atomic_init(&slog_flags_, 0);
	atomic_init(&slog_printer, NULL);
	atomic_init(&slog_fileprefix, NULL);
}

#define SLOG_INIT() call_once(&slog_init_flag, &slog_init)
#else
int slog_level_ = LOG_LEVEL_SILENCE;
unsigned int slog_flags_ = 0;
static slog_printer_fn slog_printer = NULL;
static const char *slog_fileprefix = NULL;

#define MTX_LOCK(mu) ((void)(0))
#define MTX_UNLOCK(mu) ((void)(0))

#define ATOMIC_STORE(object, desired) *(object) = (desired)
#define ATOMIC_LOAD(object) (*(object))

static struct {
	BUFFER_HDR;
	unsigned char data[SLOG_BUFSIZE];
} slog_buffer;

#define SLOG_INIT() ((void)(0))
#endif /* SLOG_MT_SAFE */

#if HAVE_GMTIME_R
#define GMTIME(timer) gmtime_r((timer), &(struct tm){ 0 })
#else
#define GMTIME(timer) gmtime((timer))
#endif /* HAVE_GMTIME_R */

#if HAVE_LOCALTIME_R
#define LOCALTIME(timer) localtime_r((timer), &(struct tm){ 0 })
#else
#define LOCALTIME(timer) localtime((timer))
#endif /* HAVE_LOCALTIME_R */

/* a fixed-length layout conforming to both ISO 8601 and RFC 3339 */
static size_t slog_timestamp(
	char *restrict s, const size_t maxsize, const time_t *restrict timer)
{
	const size_t len = sizeof("2006-01-02T15:04:05-07:00") - sizeof("");
	if (maxsize < len) {
		return 0;
	}
	const unsigned int flags = ATOMIC_LOAD(&slog_flags_);
	size_t ftlen;
	if (flags & SLOG_FLAG_UTC) {
		ftlen = strftime(s, maxsize, "%FT%TZ", GMTIME(timer));
		if (ftlen != sizeof("2006-01-02T15:04:05Z") - sizeof("")) {
			return 0;
		}
		return ftlen;
	}
	ftlen = strftime(s, maxsize, "%FT%T%z", LOCALTIME(timer));
	if (ftlen != sizeof("2006-01-02T15:04:05-0700") - sizeof("")) {
		return 0;
	}
	const char *restrict tz = s + ftlen;
	char *restrict e = s + len;
	*--e = *--tz;
	*--e = *--tz;
	*--e = ':';
	return len;
}

#define BUF_APPENDTS(buf, timer)                                               \
	(buf).len += slog_timestamp(                                           \
		(char *)(buf).data + (buf).len, (buf).cap - (buf).len,         \
		(timer))

static const char *slog_filename(const char *restrict file)
{
	const char *restrict prefix = ATOMIC_LOAD(&slog_fileprefix);
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

static void slog_print_terminal(
	const int level, const char *restrict file, const int line,
	const struct slog_extra *restrict extra, const char *restrict format,
	va_list args)
{
	BUF_INIT(slog_buffer, 0);
	BUF_APPENDF(
		slog_buffer, "%s%c ", slog_level_color[level],
		slog_level_char[level]);
	{
		time_t now;
		(void)time(&now);
		BUF_APPENDTS(slog_buffer, &now);
	}
	BUF_APPENDF(slog_buffer, " %s:%d ", slog_filename(file), line);

	const size_t prefixlen = slog_buffer.len;
	va_list args0;
	va_copy(args0, args);
	const int ret = BUF_VAPPENDF(slog_buffer, format, args);
	if (ret < 0) {
		BUF_APPENDSTR(slog_buffer, "(log format error)");
	}
	/* overwritting the null terminator is not an issue */
	BUF_APPENDSTR(slog_buffer, ANSI_CSI_RESET "\n");
	const bool longmsg = (slog_buffer.len >= slog_buffer.cap);

	MTX_LOCK(&slog_output_mu);
	(void)fwrite(
		slog_buffer.data, sizeof(slog_buffer.data[0]),
		longmsg ? prefixlen : slog_buffer.len, slog_output);
	if (longmsg) {
		(void)vfprintf(slog_output, format, args0);
		(void)fputs(ANSI_CSI_RESET "\n", slog_output);
	}
	if (extra != NULL) {
		extra->func(slog_output, extra->data);
	}
	(void)fflush(slog_output);
	MTX_UNLOCK(&slog_output_mu);

	va_end(args0);
}

static void slog_print_file(
	const int level, const char *restrict file, const int line,
	const struct slog_extra *restrict extra, const char *restrict format,
	va_list args)
{
	BUF_INIT(slog_buffer, 2);
	slog_buffer.data[0] = slog_level_char[level];
	slog_buffer.data[1] = ' ';
	{
		time_t now;
		(void)time(&now);
		BUF_APPENDTS(slog_buffer, &now);
	}
	BUF_APPENDF(slog_buffer, " %s:%d ", slog_filename(file), line);

	const size_t prefixlen = slog_buffer.len;
	va_list args0;
	va_copy(args0, args);
	const int ret = BUF_VAPPENDF(slog_buffer, format, args);
	if (ret < 0) {
		BUF_APPENDSTR(slog_buffer, "(log format error)");
	}
	/* overwritting the null terminator is not an issue */
	BUF_APPENDSTR(slog_buffer, "\n");
	const bool longmsg = (slog_buffer.len >= slog_buffer.cap);

	MTX_LOCK(&slog_output_mu);
	(void)fwrite(
		slog_buffer.data, sizeof(slog_buffer.data[0]),
		longmsg ? prefixlen : slog_buffer.len, slog_output);
	if (longmsg) {
		(void)vfprintf(slog_output, format, args0);
		(void)fputc('\n', slog_output);
	}
	if (extra != NULL) {
		extra->func(slog_output, extra->data);
	}
	(void)fflush(slog_output);
	MTX_UNLOCK(&slog_output_mu);

	va_end(args0);
}

#if HAVE_SYSLOG
static void slog_print_syslog(
	const int level, const char *restrict file, const int line,
	const struct slog_extra *restrict extra, const char *restrict format,
	va_list args)
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
	       (const char *)slog_buffer.data);
	(void)extra;
	MTX_UNLOCK(&slog_output_mu);
}
#endif

void slog_setlevel(const int level)
{
	SLOG_INIT();
	ATOMIC_STORE(&slog_level_, level);
}

void slog_setflags(unsigned int flags)
{
	SLOG_INIT();
	ATOMIC_STORE(&slog_flags_, flags);
}

void slog_setoutput(const int type, ...)
{
	SLOG_INIT();
	va_list args;
	va_start(args, type);
	switch (type) {
	case SLOG_OUTPUT_DISCARD: {
		ATOMIC_STORE(&slog_printer, NULL);
	} break;
	case SLOG_OUTPUT_TERMINAL: {
		FILE *stream = va_arg(args, FILE *);
		MTX_LOCK(&slog_output_mu);
		slog_output = stream;
		MTX_UNLOCK(&slog_output_mu);
		ATOMIC_STORE(&slog_printer, slog_print_terminal);
	} break;
	case SLOG_OUTPUT_FILE: {
		FILE *stream = va_arg(args, FILE *);
		MTX_LOCK(&slog_output_mu);
		slog_output = stream;
		MTX_UNLOCK(&slog_output_mu);
		ATOMIC_STORE(&slog_printer, slog_print_file);
	} break;
	case SLOG_OUTPUT_SYSLOG: {
#if HAVE_SYSLOG
		const char *ident = va_arg(args, const char *);
		openlog(ident, LOG_PID | LOG_NDELAY, LOG_USER);
		ATOMIC_STORE(&slog_printer, slog_print_syslog);
#else
		ATOMIC_STORE(&slog_printer, NULL);
#endif
	} break;
	default:;
	}
	va_end(args);
}

void slog_setfileprefix(const char *prefix)
{
	SLOG_INIT();
	ATOMIC_STORE(&slog_fileprefix, prefix);
}

void slog_vprintf(
	const int level, const char *restrict file, const int line,
	const struct slog_extra *restrict extra, const char *restrict format,
	va_list args)
{
	const slog_printer_fn vprintf = ATOMIC_LOAD(&slog_printer);
	if (vprintf == NULL) {
		return;
	}
	vprintf(level, file, line, extra, format, args);
}

void slog_printf(
	const int level, const char *restrict file, const int line,
	const struct slog_extra *restrict extra, const char *restrict format,
	...)
{
	const slog_printer_fn vprintf = ATOMIC_LOAD(&slog_printer);
	if (vprintf == NULL) {
		return;
	}
	va_list args;
	va_start(args, format);
	vprintf(level, file, line, extra, format, args);
	va_end(args);
}
