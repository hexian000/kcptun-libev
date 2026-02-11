/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_DEBUG_H
#define UTILS_DEBUG_H

#include "slog.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

struct slog_extra_txt {
	const char *data;
	size_t len;
	size_t hardwrap;
};
void slog_extra_txt(FILE *f, void *data);

struct slog_extra_bin {
	const void *data;
	size_t len;
	size_t binwrap;
};
void slog_extra_bin(FILE *f, void *data);

struct slog_extra_stack {
	size_t len;
	void *pc[];
};
void slog_extra_stack(FILE *f, void *data);

int debug_backtrace(void **frames, int skip, int len);

#define STACK_MAXDEPTH 256

#define LOG_STACK_F(level, skip, format, ...)                                  \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		struct {                                                       \
			size_t len;                                            \
			void *pc[STACK_MAXDEPTH];                              \
		} frames;                                                      \
		frames.len =                                                   \
			debug_backtrace(frames.pc, (skip), STACK_MAXDEPTH);    \
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

/* CHECK*: check runtime condition or FAIL
 *   Suggestions:
 *   - Use assert() when the condition indicates our bug
 *   - Use assert() when the condition does not always cause failure (crash)
 *   - When the unexpected behavior of external component will definitely cause
 *     failure, use CHECK()
 */
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
#else
#define CHECK(cond) CHECKMSGF(cond, "runtime check failed: `%s'", #cond)
#endif

/* ASSERT: an alternative to assert() */
#ifdef NDEBUG
#define ASSERT(cond) ((void)(0))
#else
#define ASSERT(cond) CHECKMSGF(cond, "assertion failed: `%s'", #cond)
#endif

#endif /* UTILS_DEBUG_H */
