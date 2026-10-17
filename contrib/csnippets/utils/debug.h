/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_DEBUG_H
#define UTILS_DEBUG_H

#include "slog.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

struct slog_extra_txt {
	/** UTF-8 text, read as UTF-8 whatever the locale; rendering stops at a NUL
	 * or an ill-formed sequence and reports how many bytes it left out. */
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

/**
 * @brief Stack trace payload for struct slog_extra.
 * @details pc carries no storage of its own. Back it with an object of this
 * type spanning at least sizeof(struct slog_extra_stack) + len * sizeof(void *)
 * bytes -- either malloc'd at that size, or a union of this struct with a byte
 * array of it.
 */
struct slog_extra_stack {
	size_t len;
	void *pc[];
};
void slog_extra_stack(struct io_stream *restrict s, void *restrict data);

/**
 * @brief Capture the calling thread's stack as an array of program counters.
 * @details Stores at most len frames, innermost first, after dropping the skip
 * innermost caller frames (a negative skip drops none); debug_backtrace()'s own
 * frame is never stored. Every stored entry is a program counter the unwinder
 * reported for a frame, never the marker it yields past the outermost one. An
 * entry may still be 0: a trace ending at a signal frame that interrupted
 * execution at address 0 -- control transferred through a null function pointer
 * -- reports that 0 as the faulting address, and it is kept rather than
 * filtered, since it is exactly what such a crash report has to show.
 * The glibc execinfo backend captures through a bounded window of the
 * max(len, DEBUG_STACK_MAXDEPTH + 32) innermost frames, which also holds
 * debug_backtrace()'s own frame and the skipped ones, so a request with
 * skip + len + 1 above that bound yields fewer than len frames even from a
 * deeper stack.
 * @return The number of frames stored; 0 if nothing was captured, e.g. no
 * backtrace backend is available or skip exceeded the stack depth.
 */
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

/**
 * @brief Receives one symbolized stack-trace line.
 * @param ctx The ctx passed to debug_backtrace_symbols().
 * @param line A NUL-terminated line with no trailing newline, valid only for
 * the duration of the call.
 */
typedef void (*debug_backtrace_symbols_cb)(void *ctx, const char *line);

/**
 * @brief Symbolize captured frames, handing each line to a callback.
 * @details Lines are numbered consecutively from "#1", innermost first. The
 * libbacktrace backend emits one line per inlined function at a program
 * counter, so a frame may yield several lines; the other backends emit exactly
 * one line per frame. A frame that cannot be symbolized still yields a line
 * carrying its raw address. A no-op when len <= 0, in which case frames may be
 * NULL. Not async-signal-safe in general -- the glibc backend allocates through
 * backtrace_symbols() -- so a signal handler should use debug_backtrace_fd().
 * @param cb Called once per line, synchronously; must not be NULL.
 * @param ctx Passed through to cb unchanged.
 * @param frames Program counters, e.g. from debug_backtrace().
 * @param len Number of entries in frames.
 * @return The number of lines passed to cb, which may exceed len; 0 when
 * len <= 0.
 */
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

/**
 * @brief Format a symbolized stack trace into a string buffer.
 * @details Each line debug_backtrace_symbols() produces is written as indent,
 * the line, then '\n'. Follows snprintf(3) semantics: the output is truncated
 * to fit maxlen, and buf is always NUL-terminated when it is non-NULL and
 * maxlen > 0. A NULL buf is a pure measuring call for any maxlen: nothing is
 * written. A no-op producing "" when len <= 0, in which case frames may be
 * NULL. Not async-signal-safe (see debug_backtrace_symbols()).
 * @param[out] buf Output buffer, or NULL to measure only.
 * @param maxlen Size of buf in bytes, including the NUL terminator.
 * @param frames Program counters, e.g. from debug_backtrace().
 * @param len Number of entries in frames.
 * @param indent Prefix for every line; NULL is treated as "".
 * @return The length of the full, untruncated output excluding the NUL
 * terminator; a value >= maxlen indicates truncation. Returns -1 when the
 * full length exceeds INT_MAX; the output remains NUL-terminated as above.
 */
int debug_strframes(
	char *restrict buf, size_t maxlen, void **restrict frames, int len,
	const char *restrict indent);

#define DEBUG_STACK_MAXDEPTH 256

/* The statement macros below expand their arguments inside their own scope, so
 * their locals are uglified with a trailing underscore to keep a caller's
 * `frames`, `extra` or `extradata` from binding to the macro's instead.
 * LOG_STACK_F's union gives the flexible array member real storage, so the
 * object slog_extra_stack() reads carries the declared type it accesses. */
#define LOG_STACK_F(level, skip, format, ...)                                  \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		union {                                                        \
			struct slog_extra_stack stack;                         \
			unsigned char                                          \
				space[DEBUG_STACK_MAXDEPTH * sizeof(void *) +  \
				      sizeof(struct slog_extra_stack)];        \
		} frames_;                                                     \
		frames_.stack.len = (size_t)debug_backtrace(                   \
			frames_.stack.pc, (skip), DEBUG_STACK_MAXDEPTH);       \
		struct slog_extra extra_ = {                                   \
			.func = slog_extra_stack,                              \
			.data = &frames_.stack,                                \
		};                                                             \
		slog_printf(                                                   \
			(LOG_LEVEL_##level), __FILE__, __LINE__, &extra_,      \
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
		struct slog_extra_txt extradata_ = {                           \
			.data = (txt),                                         \
			.len = (txtsize),                                      \
			.hardwrap = (wrap),                                    \
		};                                                             \
		struct slog_extra extra_ = {                                   \
			.func = slog_extra_txt,                                \
			.data = &extradata_,                                   \
		};                                                             \
		slog_printf(                                                   \
			(LOG_LEVEL_##level), __FILE__, __LINE__, &extra_,      \
			(format), __VA_ARGS__);                                \
	} while (0)
#define LOG_TXT(level, txt, txtsize, msg)                                      \
	LOG_TXT_F(level, txt, txtsize, 0, "%s", msg)

#define LOG_BIN_F(level, bin, binsize, wrap, format, ...)                      \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		struct slog_extra_bin extradata_ = {                           \
			.data = (bin),                                         \
			.len = (binsize),                                      \
			.binwrap = (wrap),                                     \
		};                                                             \
		struct slog_extra extra_ = {                                   \
			.func = slog_extra_bin,                                \
			.data = &extradata_,                                   \
		};                                                             \
		slog_printf(                                                   \
			(LOG_LEVEL_##level), __FILE__, __LINE__, &extra_,      \
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
 * Use ASSERT() or assert() for our own bugs or conditions that don't
 * always crash;
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

/* ASSERT: an internal invariant with a fatal log and stack trace on failure.
 * Use only where logging and its dependencies are safe to call. NDEBUG disables
 * predicate evaluation; CHECK above remains active in every build. */
#ifdef NDEBUG
#define ASSERT(cond) ((void)(0))
#else
#define ASSERT(cond) CHECKMSGF(cond, "assertion failed: `%s'", #cond)
#endif

#endif /* UTILS_DEBUG_H */
