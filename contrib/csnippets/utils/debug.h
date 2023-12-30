/* csnippets (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_DEBUG_H
#define UTILS_DEBUG_H

#include "slog.h"

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

/* NOTICE: debugging utils may not be efficient */

void print_txt(FILE *f, const char *indent, const void *data, size_t n);
void print_bin(FILE *f, const char *indent, const void *data, size_t n);
void print_stacktrace(FILE *f, const char *indent, int skip);

#define LOG_STACK_F(level, skip, format, ...)                                  \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(level, format, __VA_ARGS__);                             \
		FILE *log_fp = slog_file;                                      \
		if (log_fp != NULL) {                                          \
			print_stacktrace(log_fp, "  ", (skip));                \
		}                                                              \
	} while (0)
#define LOG_STACK(level, skip, msg) LOG_STACK_F(level, skip, "%s", msg)

#define LOG_TXT_F(level, txt, txtsize, format, ...)                            \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(level, format, __VA_ARGS__);                             \
		FILE *log_fp = slog_file;                                      \
		if (log_fp != NULL) {                                          \
			print_txt(log_fp, "  ", (txt), (txtsize));             \
		}                                                              \
	} while (0)
#define LOG_TXT(level, txt, txtsize, msg)                                      \
	LOG_TXT_F(level, txt, txtsize, "%s", msg)

#define LOG_BIN_F(level, bin, binsize, format, ...)                            \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(level, format, __VA_ARGS__);                             \
		FILE *log_fp = slog_file;                                      \
		if (log_fp != NULL) {                                          \
			print_bin(log_fp, "  ", (bin), (binsize));             \
		}                                                              \
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

/* CHECK*: check runtime condition or FAIL */
#define CHECKMSGF(cond, format, ...)                                           \
	do {                                                                   \
		if (!(cond)) {                                                 \
			FAILMSGF(format, __VA_ARGS__);                         \
		}                                                              \
	} while (0)
#define CHECKMSG(cond, msg) CHECKMSGF(cond, "%s", msg)
#define CHECK(cond) CHECKMSG(cond, "runtime check failed")

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
