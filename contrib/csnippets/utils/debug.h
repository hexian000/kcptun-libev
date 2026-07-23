/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_DEBUG_H
#define UTILS_DEBUG_H

#include "slog.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

struct slog_extra_txt {
	const char *data;
	size_t len;
	/** Column at which to wrap; a value < 4 selects the default of 80. */
	size_t hardwrap;
};
void slog_extra_txt(struct io_stream *restrict s, void *restrict data);

struct slog_extra_bin {
	const void *data;
	size_t len;
	/** Bytes per row; a value of 0 selects the default of 16. */
	size_t binwrap;
};
void slog_extra_bin(struct io_stream *restrict s, void *restrict data);

struct slog_extra_stack {
	size_t len;
	void *pc[];
};
void slog_extra_stack(struct io_stream *restrict s, void *restrict data);

int debug_backtrace(void **restrict frames, int skip, int len);

/**
 * @brief Warm up the backtrace machinery for async-signal-safe use.
 * @details Forces the lazy unwinder/allocator and symbol/DWARF initialization
 * by capturing and symbolizing the current stack once, so a later
 * debug_backtrace() or debug_backtrace_fd() -- e.g. from a crash signal handler
 * -- performs no first-use allocation or file parsing. Call once, from ordinary
 * (non-signal) context, before installing crash handlers; idempotent, and safe
 * (but not required) to call again after dlopen() to warm newly mapped objects.
 * @return true if a usable backtrace is available, false otherwise.
 */
bool debug_backtrace_init(void);

typedef void (*debug_backtrace_symbols_cb)(void *ctx, const char *line);
int debug_backtrace_symbols(
	debug_backtrace_symbols_cb cb, void *ctx, void **restrict frames,
	int len);

/**
 * @brief Write a symbolized stack trace straight to a file descriptor.
 * @details Async-signal-safe after debug_backtrace_init(): emits each frame
 * with write(2) and no buffered stdio. The glibc backend uses
 * backtrace_symbols_fd() (documented malloc-free, unlike backtrace_symbols());
 * the libbacktrace and libunwind backends symbolize from their own mmap-based
 * arenas rather than the C heap. A build with no async-signal-safe symbolizer
 * falls back to raw frame addresses. Intended for crash handlers; pass
 * STDERR_FILENO to target the same destination as slog_panicf(). A no-op when
 * fd < 0 or len <= 0.
 */
void debug_backtrace_fd(int fd, void **restrict frames, int len);

int debug_strframes(
	char *restrict buf, size_t maxlen, void **restrict frames, int len,
	const char *restrict indent);

#define DEBUG_STACK_MAXDEPTH 256

#define LOG_STACK_F(level, skip, format, ...)                                  \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		struct {                                                       \
			size_t len;                                            \
			void *pc[DEBUG_STACK_MAXDEPTH];                        \
		} frames;                                                      \
		frames.len = (size_t)debug_backtrace(                          \
			frames.pc, (skip), DEBUG_STACK_MAXDEPTH);              \
		struct slog_extra extra = {                                    \
			.func = slog_extra_stack,                              \
			.data = &frames,                                       \
		};                                                             \
		slog_printf(                                                   \
			(LOG_LEVEL_##level), __FILE__, __LINE__, &extra,       \
			(format), __VA_ARGS__);                                \
	} while (0)
#define LOG_STACK(level, skip, msg)                                            \
	LOG_STACK_F(                                                           \
		level, skip, "%s", (msg) != NULL ? (msg) : "stack traceback:")

#define LOG_TXT_F(level, txt, txtsize, wrap, format, ...)                      \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		struct slog_extra_txt extradata = {                            \
			.data = (txt),                                         \
			.len = (txtsize),                                      \
			.hardwrap = (wrap),                                    \
		};                                                             \
		struct slog_extra extra = {                                    \
			.func = slog_extra_txt,                                \
			.data = &extradata,                                    \
		};                                                             \
		slog_printf(                                                   \
			(LOG_LEVEL_##level), __FILE__, __LINE__, &extra,       \
			(format), __VA_ARGS__);                                \
	} while (0)
#define LOG_TXT(level, txt, txtsize, msg)                                      \
	LOG_TXT_F(level, txt, txtsize, 0, "%s", msg)

#define LOG_BIN_F(level, bin, binsize, wrap, format, ...)                      \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		struct slog_extra_bin extradata = {                            \
			.data = (bin),                                         \
			.len = (binsize),                                      \
			.binwrap = (wrap),                                     \
		};                                                             \
		struct slog_extra extra = {                                    \
			.func = slog_extra_bin,                                \
			.data = &extradata,                                    \
		};                                                             \
		slog_printf(                                                   \
			(LOG_LEVEL_##level), __FILE__, __LINE__, &extra,       \
			(format), __VA_ARGS__);                                \
	} while (0)
#define LOG_BIN(level, bin, binsize, msg)                                      \
	LOG_BIN_F(level, bin, binsize, 0, "%s", msg)

/* FAIL*: log a fatal message and abort the program */
#define FAILMSGF(format, ...)                                                  \
	do {                                                                   \
		LOG_STACK_F(FATAL, 0, format, __VA_ARGS__);                    \
		abort();                                                       \
	} while (0)
#define FAILMSG(msg) FAILMSGF("%s", msg)
#define FAIL() FAILMSG("program encountered an unexpected state (bug?)")

/* CHECK*: check a runtime condition or FAIL.
 * Use assert() for our own bugs or conditions that don't always crash;
 * use CHECK() when bad external behavior will definitely cause failure. */
#define CHECKMSGF(cond, format, ...)                                           \
	do {                                                                   \
		if (!(cond)) {                                                 \
			FAILMSGF(format, __VA_ARGS__);                         \
		}                                                              \
	} while (0)
#define CHECKMSG(cond, msg) CHECKMSGF(cond, "%s", msg)
#ifdef NDEBUG
#define CHECK(cond)                                                            \
	do {                                                                   \
		if (!(cond)) {                                                 \
			FAIL();                                                \
		}                                                              \
	} while (0)
#else /* NDEBUG */
#define CHECK(cond) CHECKMSGF(cond, "runtime check failed: `%s'", #cond)
#endif /* NDEBUG */

/* ASSERT: an alternative to assert() */
#ifdef NDEBUG
#define ASSERT(cond) ((void)(0))
#else
#define ASSERT(cond) CHECKMSGF(cond, "assertion failed: `%s'", #cond)
#endif

#endif /* UTILS_DEBUG_H */
