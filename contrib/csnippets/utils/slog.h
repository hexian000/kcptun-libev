/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_SLOG_H
#define UTILS_SLOG_H

#include <errno.h>
#include <stdarg.h>
#if SLOG_MT_SAFE
#include <stdatomic.h>
#endif
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct io_stream;

enum {
	LOG_LEVEL_SILENCE,
	LOG_LEVEL_FATAL,
	LOG_LEVEL_ERROR,
	LOG_LEVEL_WARNING,
	LOG_LEVEL_NOTICE,
	LOG_LEVEL_INFO,
	LOG_LEVEL_DEBUG,
	LOG_LEVEL_VERBOSE,
	LOG_LEVEL_VERYVERBOSE,
};
#if SLOG_MT_SAFE
extern atomic_int slog_level_;
#else
extern int slog_level_;
#endif
void slog_setlevel(int level);

/* Receives each fully formatted log line -- including its trailing newline --
 * and the ud registered with SLOG_OUTPUT_WRITER. Runs under slog's output lock;
 * logging through slog from within it is undefined behavior (see struct
 * slog_extra). */
typedef void (*slog_writer_fn)(void *ud, const unsigned char *buf, size_t len);

/* A drop-in replacement for the C library syslog(3). It receives the ident
 * registered with SLOG_OUTPUT_SYSLOG, the priority (facility | severity), and
 * the formatted message body. The ident may point into a caller structure so
 * that fn can recover its context from it. Runs under slog's output lock;
 * logging through slog from within it is undefined behavior (see struct
 * slog_extra). */
typedef void (*slog_syslog_fn)(
	const char *ident, int priority, const char *msg, size_t len);

enum {
	SLOG_OUTPUT_DISCARD,
	SLOG_OUTPUT_TERMINAL,
	SLOG_OUTPUT_STREAM,
	SLOG_OUTPUT_WRITER,
	SLOG_OUTPUT_SYSLOG,
};

/**
 * @brief Set the log output sink.
 * @param type One of the SLOG_OUTPUT_* constants, followed by the matching
 * variadic arguments:
 * - SLOG_OUTPUT_DISCARD: drop all messages. No extra arguments.
 * - SLOG_OUTPUT_TERMINAL, struct io_stream *stream: write each formatted line
 *   to stream (io/stream.h) with ANSI colors, then flush. The stream is
 *   borrowed like SLOG_OUTPUT_STREAM below. An overlong line is truncated to
 *   the internal buffer size, its color reset and newline always emitted.
 * - SLOG_OUTPUT_STREAM, struct io_stream *stream: write each formatted line to
 *   stream (io/stream.h) without ANSI colors, then flush. The stream is
 *   borrowed, never closed, and must stay valid until the sink is replaced;
 *   NULL discards all messages. An overlong line is truncated to the internal
 *   buffer size. The stream's write/flush run under slog's output lock and
 *   must not log through slog (see struct slog_extra).
 * - SLOG_OUTPUT_WRITER, slog_writer_fn fn, void *ud: deliver each formatted
 *   line to fn(ud, buf, len), without ANSI colors. fn is borrowed and must stay
 *   valid until the sink is replaced; NULL discards all messages. An overlong
 *   line is truncated to the internal buffer size. Like the syslog sink, the
 *   writer sink ignores struct slog_extra.
 * - SLOG_OUTPUT_SYSLOG, void *ident, slog_syslog_fn fn: send messages via fn,
 *   or the system syslog() when fn is NULL. ident is the syslog identity and is
 *   passed back to fn as its first argument.
 * @details The previous sink, if any, is replaced.
 */
void slog_setoutput(int type, ...);

/**
 * @brief Set a path prefix stripped from the __FILE__ shown in each line.
 * @param prefix Borrowed, not copied: the pointer is stored and dereferenced
 * by every subsequent log call, including the async-signal-safe panic path,
 * so it must stay valid until it is replaced or cleared with NULL. A string
 * literal or other static storage is the intended use; a stack or temporary
 * buffer is a use-after-scope.
 */
void slog_setfileprefix(const char *prefix);

enum {
	SLOG_FLAG_UTC = 0x0001,
	SLOG_FLAG_NANOS = 0x0002,
};
void slog_setflags(unsigned int flags);

/**
 * @brief Extra content written after the message, via func(s, data).
 * @details Honored by the terminal and stream sinks; the writer and syslog
 * sinks ignore it. func -- like the syslog callback and the stream's
 * write/flush -- runs while slog holds its internal, non-recursive output lock;
 * calling any slog logging function from inside such a callback is undefined
 * behavior (deadlock, or unbounded recursion without SLOG_MT_SAFE).
 */
struct slog_extra {
	void (*func)(struct io_stream *s, void *data);
	void *data;
};
/** @brief Log a message with a va_list of arguments. extra may be NULL. */
void slog_vprintf(
	int level, const char *file, int line, const struct slog_extra *extra,
	const char *format, va_list args);
/** @brief Log a message with variadic arguments. extra may be NULL. */
void slog_printf(
	int level, const char *file, int line, const struct slog_extra *extra,
	const char *format, ...);

/**
 * @brief Async-signal-safe emergency log line, for use from a crash signal
 * handler.
 * @details Writes "<L> <file>:<line> <message>\n" to stderr with a single
 * write(2): no locking, no buffered stdio, no allocation, and no timestamp
 * (strftime()/localtime() are not async-signal-safe). Formats full printf-style
 * via u8vsnprintf (strings/string.h), with its documented divergences; an
 * overlong line is truncated to a fixed internal buffer, the newline always
 * emitted. Unlike the LOG* macros it does not test the log level; the caller
 * decides whether to emit.
 */
void slog_panicf(int level, const char *file, int line, const char *format, ...);

/* LOG_F: Internal macro to log a message unconditionally. This is not a part of supported API. */
#define LOG_F(level, format, ...)                                              \
	slog_printf(                                                           \
		(LOG_LEVEL_##level), __FILE__, __LINE__, NULL, (format),       \
		__VA_ARGS__)

#if SLOG_MT_SAFE
#define LOGLEVEL(level)                                                        \
	((LOG_LEVEL_##level) <=                                                \
	 atomic_load_explicit(&slog_level_, memory_order_acquire))
#else
#define LOGLEVEL(level) ((LOG_LEVEL_##level) <= slog_level_)
#endif

/* Temporary: Temporary logs are printed regardless of log level. */
#define LOGT_F(format, ...)                                                    \
	do {                                                                   \
		LOG_F(SILENCE, format, __VA_ARGS__);                           \
	} while (0)
#define LOGT(message) LOGT_F("%s", message)

/* Fatal: Serious problems that are likely to cause the program to exit. */
#define LOGF_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(FATAL)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(FATAL, format, __VA_ARGS__);                             \
	} while (0)
#define LOGF(message) LOGF_F("%s", message)

/* Error: Issues that shouldn't be ignored. */
#define LOGE_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(ERROR)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(ERROR, format, __VA_ARGS__);                             \
	} while (0)
#define LOGE(message) LOGE_F("%s", message)

/* Warning: Issues that may be ignored. */
#define LOGW_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(WARNING)) {                                      \
			break;                                                 \
		}                                                              \
		LOG_F(WARNING, format, __VA_ARGS__);                           \
	} while (0)
#define LOGW(message) LOGW_F("%s", message)

/* Notice: Important status changes. The prefix is 'I'. */
#define LOGN_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(NOTICE)) {                                       \
			break;                                                 \
		}                                                              \
		LOG_F(NOTICE, format, __VA_ARGS__);                            \
	} while (0)
#define LOGN(message) LOGN_F("%s", message)

/* Info: Normal work reports. */
#define LOGI_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(INFO)) {                                         \
			break;                                                 \
		}                                                              \
		LOG_F(INFO, format, __VA_ARGS__);                              \
	} while (0)
#define LOGI(message) LOGI_F("%s", message)

/* Debug: Extra information for debugging. */
#define LOGD_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(DEBUG)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(DEBUG, format, __VA_ARGS__);                             \
	} while (0)
#define LOGD(message) LOGD_F("%s", message)

/* Verbose: Details for inspecting specific issues. */
#define LOGV_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(VERBOSE)) {                                      \
			break;                                                 \
		}                                                              \
		LOG_F(VERBOSE, format, __VA_ARGS__);                           \
	} while (0)
#define LOGV(message) LOGV_F("%s", message)

/* VeryVerbose: More details that may significantly impact performance. The prefix is 'V'. */
#define LOGVV_F(format, ...)                                                   \
	do {                                                                   \
		if (!LOGLEVEL(VERYVERBOSE)) {                                  \
			break;                                                 \
		}                                                              \
		LOG_F(VERYVERBOSE, format, __VA_ARGS__);                       \
	} while (0)
#define LOGVV(message) LOGVV_F("%s", message)

/* Convenience macro for logging errors with errno */
#define LOG_PERROR(msg)                                                        \
	do {                                                                   \
		const int err = errno;                                         \
		LOGE_F(msg ": (%d) %s", err, strerror(err));                   \
	} while (0)

/* Check critical allocation failure */
#define FAILOOM()                                                              \
	do {                                                                   \
		LOGF("out of memory");                                         \
		_Exit(EXIT_FAILURE); /* no core dump */                        \
	} while (0)
#define CHECKOOM(ptr)                                                          \
	do {                                                                   \
		if ((ptr) == NULL) {                                           \
			FAILOOM();                                             \
		}                                                              \
	} while (0)
#define LOGOOM() LOGE("out of memory")

#endif /* UTILS_SLOG_H */
