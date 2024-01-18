/* kcptun-libev (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef EVENT_IMPL_H
#define EVENT_IMPL_H

#include "util.h"

#include "utils/slog.h"

#include <ev.h>

#include <stdbool.h>

#define LOG_RATELIMITED_F(level, now, rate, format, ...)                       \
	RATELIMIT(now, rate, LOG_F(level, format, __VA_ARGS__));

#define LOG_RATELIMITED(level, now, rate, message)                             \
	LOG_RATELIMITED_F(level, now, rate, "%s", message)

struct server;
struct session;

bool kcp_cansend(struct session *ss);
bool kcp_canrecv(struct session *ss);

#endif /* EVENT_IMPL_H */
