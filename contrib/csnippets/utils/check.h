/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef CHECK_H
#define CHECK_H

#include "slog.h"

#include <stdlib.h>

#define CHECKMSGF(cond, format, ...)                                           \
	do {                                                                   \
		if (!(cond)) {                                                 \
			LOGF_F(format, __VA_ARGS__);                           \
			abort();                                               \
		}                                                              \
	} while (0)
#define CHECKMSG(cond, msg) CHECKMSGF(cond, "%s", msg)
#define CHECK(cond) CHECKMSGF(cond, "runtime check failed: %s", #cond)

#define FAILMSGF(format, ...) CHECKMSGF(0, format, __VA_ARGS__)
#define FAILMSG(msg) CHECKMSG(0, msg)
#define FAIL() CHECKMSG(0, "program entered an unexpected state (bug?)")

#define LOGOOM() LOGE("out of memory")
#define CHECKOOM(ptr) CHECKMSG((ptr) != NULL, "out of memory")
#define FAILOOM() FAILMSG("out of memory")

#endif /* CHECK_H */
