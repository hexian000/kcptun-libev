/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "slog.h"

#include "buffer.h"
#include "io/stream.h"

#if HAVE_SYSLOG
#include <syslog.h>
#endif

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#if SLOG_MT_SAFE
#include <stdatomic.h>
#include <threads.h>
#endif
#include <stddef.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define SLOG_BUFSIZE 4096
/* slog_panicf() formats one line onto the caller's stack; sized to hold a
 * prefix plus a typical crash message without spilling the altstack budget */
#define SLOG_PANIC_BUFSIZE 1024

/* one formatted line, built on the logging thread's stack per call */
struct slog_linebuf {
	BUFFER_HDR;
	unsigned char data[SLOG_BUFSIZE];
};

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

static const char *const slog_level_color[] = {
	ANSI_CSI_FG(, 96), ANSI_CSI_BG(, 97, 41), ANSI_CSI_FG(, 91),
	ANSI_CSI_FG(, 93), ANSI_CSI_FG(, 92),	  ANSI_CSI_FG(, 92),
	ANSI_CSI_FG(, 96), ANSI_CSI_FG(, 97),	  ANSI_CSI_FG(, 37),
};

static FILE *slog_output;
static struct io_stream *slog_stream;
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
		/* the fixed-offset writes below reach s[sizeof(layout)-1], which
		 * strftime's own length check does not cover, so guard maxsize
		 * for the full layout too */
		if (maxsize < sizeof(LAYOUT_RFC3339NANO_UTC) ||
		    !STRFTIME_UTC(s, maxsize, &tp->tv_sec)) {
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

	if (maxsize < sizeof(LAYOUT_RFC3339NANO) ||
	    !STRFTIME(s, maxsize, &tp->tv_sec)) {
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
	if (maxsize < sizeof(LAYOUT_RFC3339) || !STRFTIME(s, maxsize, &now)) {
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

/* write the whole buffer, retrying short writes and EINTR. Like the printers'
 * stdio calls, output errors are best-effort and unescalated -- a logger has no
 * lower channel to report its own I/O failures through. Async-signal-safe. */
static void slog_write_all(const int fd, const void *restrict data, size_t n)
{
	const unsigned char *restrict p = data;
	while (n > 0) {
		const ssize_t nw = write(fd, p, n);
		if (nw < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		if (nw == 0) {
			break;
		}
		p += (size_t)nw;
		n -= (size_t)nw;
	}
}

/* stream view of the terminal sink's FILE, so struct slog_extra callbacks
 * (which take a stream) can write to it */
static int slog_term_write(void *p, const void *buf, size_t *restrict len)
{
	struct io_stream *restrict s = p;
	FILE *restrict f = s->data;
	const size_t want = *len;
	*len = fwrite(buf, sizeof(unsigned char), want, f);
	if (*len < want) {
		return -1;
	}
	return 0;
}

static const struct io_stream_vftable slog_term_vftable = {
	.write = slog_term_write,
};

static void slog_print_terminal(
	const int level, const char *restrict file, const int line,
	const struct slog_extra *restrict extra, const char *restrict format,
	va_list args)
{
	const unsigned int flags = ATOMIC_LOAD(&slog_flags_);

	struct slog_linebuf buf;
	BUF_INIT(buf, 0);
	BUF_APPENDF(
		buf, "%s%c ", slog_level_color[level], slog_level_char[level]);
	BUF_APPENDTS(buf, flags);
	BUF_APPENDF(buf, " %s:%d ", slog_filename(file), line);

	/* Reserve the trailer before formatting the message, so the color reset
	 * and newline always fit even when an overlong message truncates (a
	 * chopped-off reset would leave the terminal colored); the engine
	 * truncates at whatever cap it sees without splitting a UTF-8 sequence. */
	const size_t cap = buf.cap;
	const size_t trailer_len = STRLEN(ANSI_CSI_RESET "\n");
	buf.cap = cap - buf.len > trailer_len ? cap - trailer_len : buf.len;
	const int ret = BUF_VAPPENDF(buf, format, args);
	if (ret < 0) {
		BUF_APPENDSTR(buf, "(log format error)");
	}
	buf.cap = cap;
	/* overwriting the null terminator is not an issue */
	BUF_APPENDSTR(buf, ANSI_CSI_RESET "\n");

	/* a logger has no lower channel to report its own I/O failures
	 * through, so output errors below are best-effort and unescalated */
	MTX_LOCK(&slog_output_mu);
	(void)fwrite(buf.data, sizeof(buf.data[0]), buf.len, slog_output);
	if (extra != NULL) {
		struct io_stream term = { &slog_term_vftable, slog_output };
		extra->func(&term, extra->data);
	}
	(void)fflush(slog_output);
	MTX_UNLOCK(&slog_output_mu);
}

/* builds the "<L> <timestamp> <file>:<line> " prefix of the writer sink */
static void slog_build_prefix(
	struct slog_linebuf *restrict buf, const int level,
	const char *restrict file, const int line)
{
	const unsigned int flags = ATOMIC_LOAD(&slog_flags_);
	BUF_INIT(*buf, 2);
	buf->data[0] = slog_level_char[level];
	buf->data[1] = ' ';
	BUF_APPENDTS(*buf, flags);
	BUF_APPENDF(*buf, " %s:%d ", slog_filename(file), line);
}

static void slog_print_writer(
	const int level, const char *restrict file, const int line,
	const struct slog_extra *restrict extra, const char *restrict format,
	va_list args)
{
	struct slog_linebuf buf;
	slog_build_prefix(&buf, level, file, line);

	const int ret = BUF_VAPPENDF(buf, format, args);
	if (ret < 0) {
		BUF_APPENDSTR(buf, "(log format error)");
	}
	/* overwriting the null terminator is not an issue */
	BUF_APPENDSTR(buf, "\n");
	/* a generic stream cannot be re-formatted into, so an overlong line is
	 * already truncated to the buffer capacity by buf_append */
	size_t len = buf.len;

	MTX_LOCK(&slog_output_mu);
	/* re-check under the lock: a concurrent slog_setoutput may have cleared
	 * the stream after this printer was selected */
	if (slog_stream != NULL) {
		(void)io_stream_write(slog_stream, buf.data, &len);
		if (extra != NULL) {
			extra->func(slog_stream, extra->data);
		}
		(void)io_stream_flush(slog_stream);
	}
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

	struct slog_linebuf buf;
	BUF_INIT(buf, 0);
	BUF_APPENDF(buf, "%s:%d ", slog_filename(file), line);
	const int ret = BUF_VAPPENDF(buf, format, args);
	if (ret < 0) {
		BUF_APPENDSTR(buf, "(log format error)");
	}

	MTX_LOCK(&slog_output_mu);
	if (slog_syslog != NULL) {
		slog_syslog(
			slog_syslog_ident, priority, (const char *)buf.data,
			buf.len);
	}
#if HAVE_SYSLOG
	else {
		syslog(priority, "%.*s", (int)buf.len, (const char *)buf.data);
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
	case SLOG_OUTPUT_WRITER: {
		struct io_stream *stream = va_arg(args, struct io_stream *);
		MTX_LOCK(&slog_output_mu);
		slog_stream = stream;
		MTX_UNLOCK(&slog_output_mu);
		ATOMIC_STORE(
			&slog_printer,
			stream != NULL ? slog_print_writer : NULL);
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
	/* the printers index level-keyed tables (slog_level_char, slog_level_color
	 * and slog_severity_map, 9 entries each) with `level` directly; it is a
	 * public int parameter, so guard its valid range here before it can drive
	 * an out-of-bounds read */
	assert(level >= LOG_LEVEL_SILENCE && level <= LOG_LEVEL_VERYVERBOSE);
	const slog_printer_fn printer = ATOMIC_LOAD(&slog_printer);
	if (printer == NULL) {
		return;
	}
	printer(level, file, line, extra, format, args);
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

/* --- async-signal-safe panic logging -------------------------------------- *
 * slog_panicf() formats via the buffer helpers' utf8 engine (allocation-free,
 * locale-independent, async-signal-safe), builds one line onto the caller's
 * stack -- no thread_local, no output mutex (a crash may have interrupted a
 * thread already holding it) -- and emits it to stderr with a single write(2).
 */

void slog_panicf(
	const int level, const char *restrict file, const int line,
	const char *restrict format, ...)
{
	assert(level >= LOG_LEVEL_SILENCE && level <= LOG_LEVEL_VERYVERBOSE);
	struct {
		BUFFER_HDR;
		unsigned char data[SLOG_PANIC_BUFSIZE];
	} buf;
	BUF_INIT(buf, 0);
	/* own prefix, not slog_build_prefix(): no timestamp, as
	 * strftime()/localtime() are not async-signal-safe */
	BUF_APPENDF(
		buf, "%c %s:%d ", slog_level_char[level], slog_filename(file),
		line);
	/* reserve the last byte so the trailing newline always fits */
	const size_t cap = buf.cap;
	buf.cap = cap - buf.len > 1 ? cap - 1 : buf.len;
	va_list args;
	va_start(args, format);
	(void)BUF_VAPPENDF(buf, format, args);
	va_end(args);
	buf.cap = cap;
	BUF_APPENDSTR(buf, "\n");
	slog_write_all(STDERR_FILENO, buf.data, buf.len);
}
