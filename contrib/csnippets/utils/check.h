/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_CHECK_H
#define UTILS_CHECK_H

#include "slog.h"

#include <stdlib.h>

/* FAIL*: log a fatal message and abort the program */
#define FAILMSGF(format, ...)                                                  \
	do {                                                                   \
		LOGF_F(format, __VA_ARGS__);                                   \
		abort();                                                       \
	} while (0)
#define FAILMSG(msg) FAILMSGF("%s", msg)
#define FAIL() FAILMSG("program entered an unexpected state (bug?)")

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

#endif /* UTILS_CHECK_H */
