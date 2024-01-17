/* kcptun-libev (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef EVENT_IMPL_H
#define EVENT_IMPL_H

#include "utils/slog.h"

#include <ev.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#define CHECK_EV_ERROR(revents, accept)                                        \
	do {                                                                   \
		if (((revents)&EV_ERROR) != 0) {                               \
			const int err = errno;                                 \
			LOGE_F("error event: [errno=%d] %s", err,              \
			       strerror(err));                                 \
			return;                                                \
		}                                                              \
		assert(((revents) & (accept)) == (revents));                   \
	} while (0)

#define LOG_RATELIMITED_F(level, now, rate, format, ...)                       \
	RATELIMIT(now, rate, LOG_F(level, format, __VA_ARGS__));

#define LOG_RATELIMITED(level, now, rate, message)                             \
	LOG_RATELIMITED_F(level, now, rate, "%s", message)

struct server;
struct session;

bool kcp_cansend(struct session *ss);
bool kcp_canrecv(struct session *ss);

#endif /* EVENT_IMPL_H */
