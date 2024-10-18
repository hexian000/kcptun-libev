/* csnippets (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_DEBUG_H
#define UTILS_DEBUG_H

#include "slog.h"
#include "utils/buffer.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/* NOTICE: debugging utils may not be efficient */

struct slog_extra_txt {
	const char *data;
	size_t len;
};
void slog_extra_txt(void *data, FILE *f);

struct slog_extra_bin {
	const void *data;
	size_t len;
};
void slog_extra_bin(void *data, FILE *f);

void slog_stacktrace(struct buffer *buf, int skip);
void slog_extra_buf(void *data, FILE *f);

#define LOG_STACK_F(level, calldepth, format, ...)                             \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		struct {                                                       \
			BUFFER_HDR;                                            \
			unsigned char data[BUFSIZ];                            \
		} buf;                                                         \
		BUF_INIT(buf, 0);                                              \
		slog_stacktrace((struct buffer *)&buf, (calldepth));           \
		struct slog_extra extra = {                                    \
			.func = slog_extra_buf,                                \
			.data = &buf,                                          \
		};                                                             \
		slog_write(                                                    \
			(LOG_LEVEL_##level), __FILE__, __LINE__, &extra,       \
			(format), __VA_ARGS__);                                \
	} while (0)
#define LOG_STACK(level, calldepth, msg)                                       \
	LOG_STACK_F(level, calldepth, "%s", msg)

#define LOG_TXT_F(level, txt, txtsize, format, ...)                            \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		struct slog_extra_txt extradata = {                            \
			.data = (txt),                                         \
			.len = (txtsize),                                      \
		};                                                             \
		struct slog_extra extra = {                                    \
			.func = slog_extra_txt,                                \
			.data = &extradata,                                    \
		};                                                             \
		slog_write(                                                    \
			(LOG_LEVEL_##level), __FILE__, __LINE__, &extra,       \
			(format), __VA_ARGS__);                                \
	} while (0)
#define LOG_TXT(level, txt, txtsize, msg)                                      \
	LOG_TXT_F(level, txt, txtsize, "%s", msg)

#define LOG_BIN_F(level, bin, binsize, format, ...)                            \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		struct slog_extra_bin extradata = {                            \
			.data = (bin),                                         \
			.len = (binsize),                                      \
		};                                                             \
		struct slog_extra extra = {                                    \
			.func = slog_extra_bin,                                \
			.data = &extradata,                                    \
		};                                                             \
		slog_write(                                                    \
			(LOG_LEVEL_##level), __FILE__, __LINE__, &extra,       \
			(format), __VA_ARGS__);                                \
	} while (0)
#define LOG_BIN(level, bin, binsize, msg)                                      \
	LOG_BIN_F(level, bin, binsize, "%s", msg)

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
#define CHECK(cond) CHECKMSGF(cond, "runtime check failed: `%s'", #cond)

/* ASSERT: an alternative to assert() */
#ifdef NDEBUG
#define ASSERT(cond) ((void)(0))
#else
#define ASSERT(cond) CHECKMSGF(cond, "assertion failed: `%s'", #cond)
#endif

/* check critical allocation failure */
#define FAILOOM()                                                              \
	do {                                                                   \
		LOGF("out of memory");                                         \
		exit(EXIT_FAILURE);                                            \
	} while (0)
#define CHECKOOM(ptr)                                                          \
	do {                                                                   \
		if ((ptr) == NULL) {                                           \
			FAILOOM();                                             \
		}                                                              \
	} while (0)
#define LOGOOM() LOGE("out of memory")

#endif /* UTILS_DEBUG_H */
