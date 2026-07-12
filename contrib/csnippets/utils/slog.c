/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "slog.h"

#include "buffer.h"

#if HAVE_SYSLOG
#include <syslog.h>
#endif

#include <assert.h>
#include <stdarg.h>
#if SLOG_MT_SAFE
#include <stdatomic.h>
#include <threads.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

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

static FILE *slog_output;
static slog_writer_fn slog_writer;
static void *slog_writer_ud;
static slog_syslog_fn slog_syslog;
static void *slog_syslog_ident;

#if SLOG_MT_SAFE
static mtx_t slog_output_mu;

atomic_int slog_level_ = LOG_LEVEL_SILENCE;
static atomic_uint slog_flags_ = 0;
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

static thread_local struct {
	BUFFER_HDR;
	unsigned char data[SLOG_BUFSIZE];
} slog_buffer;

/* guards against a sink (e.g. a writer or syslog backend) that logs through
 * slog while it is being invoked, which would otherwise re-enter the printer
 * and deadlock on the non-recursive output mutex */
static thread_local bool slog_in_printer;

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
#else /* !SLOG_MT_SAFE */
int slog_level_ = LOG_LEVEL_SILENCE;
static unsigned int slog_flags_ = 0;
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

/* see the SLOG_MT_SAFE definition above */
static bool slog_in_printer;

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

#define STRLEN(s) (sizeof(s "") - sizeof(""))

#define LAYOUT_C "2006-01-02T15:04:05-0700"
#define LAYOUT_C_UTC "2006-01-02T15:04:05Z"

#define STRFTIME(s, maxlen, timer)                                             \
	(strftime((s), (maxlen), "%FT%T%z", LOCALTIME(timer)) ==               \
	 STRLEN(LAYOUT_C))

#define STRFTIME_UTC(s, maxlen, timer)                                         \
	(strftime((s), (maxlen), "%FT%TZ", GMTIME(timer)) ==                   \
	 STRLEN(LAYOUT_C_UTC))

#define LAYOUT_RFC3339 "2006-01-02T15:04:05-07:00"
#define LAYOUT_RFC3339_UTC "2006-01-02T15:04:05Z"

#define LAYOUT_RFC3339NANO "2006-01-02T15:04:05.999999999-07:00"
#define LAYOUT_RFC3339NANO_UTC "2006-01-02T15:04:05.999999999Z"

static size_t slog_timestamp_nanos(
	char *restrict s, const size_t maxsize, const unsigned int flags,
	const struct timespec *restrict tp)
{
	if (flags & SLOG_FLAG_UTC) {
		if (!STRFTIME_UTC(s, maxsize, &tp->tv_sec)) {
			return 0;
		}
		unsigned char *restrict e =
			(unsigned char *)s + sizeof(LAYOUT_RFC3339NANO_UTC);
		int ns = (int)tp->tv_nsec;
		*--e = '\0';
		*--e = 'Z';
		*--e = '0' + ns % 10, ns /= 10;
		*--e = '0' + ns % 10, ns /= 10;
		*--e = '0' + ns % 10, ns /= 10;
		*--e = '0' + ns % 10, ns /= 10;
		*--e = '0' + ns % 10, ns /= 10;
		*--e = '0' + ns % 10, ns /= 10;
		*--e = '0' + ns % 10, ns /= 10;
		*--e = '0' + ns % 10, ns /= 10;
		*--e = '0' + ns % 10;
		*--e = '.';
		return STRLEN(LAYOUT_RFC3339NANO_UTC);
	}

	if (!STRFTIME(s, maxsize, &tp->tv_sec)) {
		return 0;
	}
	const unsigned char *restrict tz =
		(unsigned char *)s + STRLEN(LAYOUT_C);
	unsigned char *restrict e =
		(unsigned char *)s + sizeof(LAYOUT_RFC3339NANO);
	*--e = '\0';
	*--e = *--tz;
	*--e = *--tz;
	*--e = ':';
	*--e = *--tz;
	*--e = *--tz;
	*--e = *--tz;
	int ns = (int)tp->tv_nsec;
	*--e = '0' + ns % 10, ns /= 10;
	*--e = '0' + ns % 10, ns /= 10;
	*--e = '0' + ns % 10, ns /= 10;
	*--e = '0' + ns % 10, ns /= 10;
	*--e = '0' + ns % 10, ns /= 10;
	*--e = '0' + ns % 10, ns /= 10;
	*--e = '0' + ns % 10, ns /= 10;
	*--e = '0' + ns % 10, ns /= 10;
	*--e = '0' + ns % 10;
	*--e = '.';
	return STRLEN(LAYOUT_RFC3339NANO);
}

/* a fixed-length layout conforming to both ISO 8601 and RFC 3339 */
static size_t
slog_timestamp(char *restrict s, const size_t maxsize, const unsigned int flags)
{
	if (flags & SLOG_FLAG_NANOS) {
		struct timespec ts;
		if (timespec_get(&ts, TIME_UTC) == TIME_UTC) {
			return slog_timestamp_nanos(s, maxsize, flags, &ts);
		}
	}

	time_t now;
	(void)time(&now);
	if (flags & SLOG_FLAG_UTC) {
		if (!STRFTIME_UTC(s, maxsize, &now)) {
			return 0;
		}
		return STRLEN(LAYOUT_RFC3339_UTC);
	}
	if (!STRFTIME(s, maxsize, &now)) {
		return 0;
	}
	const char *restrict tz = s + STRLEN(LAYOUT_C);
	char *restrict e = s + sizeof(LAYOUT_RFC3339);
	*--e = '\0';
	*--e = *--tz;
	*--e = *--tz;
	*--e = ':';
	return STRLEN(LAYOUT_RFC3339);
}

#define BUF_APPENDTS(buf, flags)                                               \
	do {                                                                   \
		((buf).len += slog_timestamp(                                  \
			 (char *)(buf).data + (buf).len,                       \
			 (buf).cap - (buf).len, (flags)));                     \
	} while (0)

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
	const unsigned int flags = ATOMIC_LOAD(&slog_flags_);

	BUF_INIT(slog_buffer, 0);
	BUF_APPENDF(
		slog_buffer, "%s%c ", slog_level_color[level],
		slog_level_char[level]);
	BUF_APPENDTS(slog_buffer, flags);
	BUF_APPENDF(slog_buffer, " %s:%d ", slog_filename(file), line);

	const size_t prefixlen = slog_buffer.len;
	va_list args0;
	va_copy(args0, args);
	const int ret = BUF_VAPPENDF(slog_buffer, format, args);
	/* The message plus its trailer overflow the fixed buffer -- and so must
	 * be re-emitted straight to the stream -- only when the full formatted
	 * length would not fit after the prefix. Deriving this from vsnprintf's
	 * returned length rather than (len >= cap) keeps an exact fit, which
	 * fills the buffer without truncation, on the fast path. */
	const size_t trailer_len = sizeof(ANSI_CSI_RESET "\n") - 1;
	const bool longmsg = (ret >= 0) && ((size_t)ret + trailer_len >
					    slog_buffer.cap - prefixlen);
	if (ret < 0) {
		BUF_APPENDSTR(slog_buffer, "(log format error)");
	}
	/* overwriting the null terminator is not an issue */
	BUF_APPENDSTR(slog_buffer, ANSI_CSI_RESET "\n");

	/* a logger has no lower channel to report its own I/O failures
	 * through, so output errors below are best-effort and unescalated */
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

/* builds the "<L> <timestamp> <file>:<line> " prefix shared by the plain-file
 * and writer sinks into slog_buffer */
static void
slog_build_prefix(const int level, const char *restrict file, const int line)
{
	const unsigned int flags = ATOMIC_LOAD(&slog_flags_);
	BUF_INIT(slog_buffer, 2);
	slog_buffer.data[0] = slog_level_char[level];
	slog_buffer.data[1] = ' ';
	BUF_APPENDTS(slog_buffer, flags);
	BUF_APPENDF(slog_buffer, " %s:%d ", slog_filename(file), line);
}

static void slog_print_file(
	const int level, const char *restrict file, const int line,
	const struct slog_extra *restrict extra, const char *restrict format,
	va_list args)
{
	slog_build_prefix(level, file, line);

	const size_t prefixlen = slog_buffer.len;
	va_list args0;
	va_copy(args0, args);
	const int ret = BUF_VAPPENDF(slog_buffer, format, args);
	/* see slog_print_terminal: detect real truncation from the formatted
	 * length so an exact fit stays on the fast path */
	const size_t trailer_len = sizeof("\n") - 1;
	const bool longmsg = (ret >= 0) && ((size_t)ret + trailer_len >
					    slog_buffer.cap - prefixlen);
	if (ret < 0) {
		BUF_APPENDSTR(slog_buffer, "(log format error)");
	}
	/* overwriting the null terminator is not an issue */
	BUF_APPENDSTR(slog_buffer, "\n");

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

static void slog_print_writer(
	const int level, const char *restrict file, const int line,
	const struct slog_extra *restrict extra, const char *restrict format,
	va_list args)
{
	slog_build_prefix(level, file, line);

	const int ret = BUF_VAPPENDF(slog_buffer, format, args);
	if (ret < 0) {
		BUF_APPENDSTR(slog_buffer, "(log format error)");
	}
	/* overwriting the null terminator is not an issue */
	BUF_APPENDSTR(slog_buffer, "\n");
	/* there is no stream to re-format into, so an overlong line is already
	 * truncated to the buffer capacity by buf_append */
	const size_t len = slog_buffer.len;

	MTX_LOCK(&slog_output_mu);
	if (slog_writer != NULL) {
		slog_writer(slog_writer_ud, slog_buffer.data, len);
	}
	(void)extra;
	MTX_UNLOCK(&slog_output_mu);
}

static void slog_print_syslog(
	const int level, const char *restrict file, const int line,
	const struct slog_extra *restrict extra, const char *restrict format,
	va_list args)
{
	/* RFC 5424 §6.2.1 severities, indexed by slog level; facility USER (1) */
	static const int slog_severity_map[] = {
		1, 2, 3, 4, 5, 6, 7, 7, 7,
	};
	const int priority = (1 << 3) | slog_severity_map[level];

	BUF_INIT(slog_buffer, 0);
	BUF_APPENDF(slog_buffer, "%s:%d ", slog_filename(file), line);
	const int ret = BUF_VAPPENDF(slog_buffer, format, args);
	if (ret < 0) {
		BUF_APPENDSTR(slog_buffer, "(log format error)");
	}

	MTX_LOCK(&slog_output_mu);
	if (slog_syslog != NULL) {
		slog_syslog(
			slog_syslog_ident, priority,
			(const char *)slog_buffer.data, slog_buffer.len);
	}
#if HAVE_SYSLOG
	else {
		syslog(priority, "%.*s", (int)slog_buffer.len,
		       (const char *)slog_buffer.data);
	}
#endif
	(void)extra;
	MTX_UNLOCK(&slog_output_mu);
}

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
	case SLOG_OUTPUT_WRITER: {
		slog_writer_fn fn = va_arg(args, slog_writer_fn);
		void *ud = va_arg(args, void *);
		MTX_LOCK(&slog_output_mu);
		slog_writer = fn;
		slog_writer_ud = ud;
		MTX_UNLOCK(&slog_output_mu);
		ATOMIC_STORE(&slog_printer, slog_print_writer);
	} break;
	case SLOG_OUTPUT_SYSLOG: {
		void *ident = va_arg(args, void *);
		slog_syslog_fn fn = va_arg(args, slog_syslog_fn);
		if (fn != NULL) {
			MTX_LOCK(&slog_output_mu);
			slog_syslog = fn;
			slog_syslog_ident = ident;
			MTX_UNLOCK(&slog_output_mu);
			ATOMIC_STORE(&slog_printer, slog_print_syslog);
			break;
		}
#if HAVE_SYSLOG
		openlog(ident, LOG_PID | LOG_NDELAY, LOG_USER);
		MTX_LOCK(&slog_output_mu);
		slog_syslog = NULL;
		slog_syslog_ident = NULL;
		MTX_UNLOCK(&slog_output_mu);
		ATOMIC_STORE(&slog_printer, slog_print_syslog);
#else /* HAVE_SYSLOG */
		(void)ident;
		ATOMIC_STORE(&slog_printer, NULL);
#endif /* HAVE_SYSLOG */
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

void slog_setflags(const unsigned int flags)
{
	SLOG_INIT();
	ATOMIC_STORE(&slog_flags_, flags);
}

static void slog_dispatch(
	const int level, const char *restrict file, const int line,
	const struct slog_extra *restrict extra, const char *restrict format,
	va_list args)
{
	const slog_printer_fn printer = ATOMIC_LOAD(&slog_printer);
	/* drop messages emitted by a sink from within its own invocation;
	 * re-entering the printer here would deadlock on slog_output_mu */
	if (printer == NULL || slog_in_printer) {
		return;
	}
	slog_in_printer = true;
	printer(level, file, line, extra, format, args);
	slog_in_printer = false;
}

void slog_vprintf(
	const int level, const char *restrict file, const int line,
	const struct slog_extra *restrict extra, const char *restrict format,
	va_list args)
{
	slog_dispatch(level, file, line, extra, format, args);
}

void slog_printf(
	const int level, const char *restrict file, const int line,
	const struct slog_extra *restrict extra, const char *restrict format,
	...)
{
	va_list args;
	va_start(args, format);
	slog_dispatch(level, file, line, extra, format, args);
	va_end(args);
}
