/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef EVENT_IMPL_H
#define EVENT_IMPL_H

#include <ev.h>
#include <errno.h>

#include <string.h>

#define CHECK_EV_ERROR(revents)                                                \
	do {                                                                   \
		if ((unsigned)(revents) & (unsigned)EV_ERROR) {                \
			const int err = errno;                                 \
			LOGE_F("got error event: %s", strerror(err));          \
			return;                                                \
		}                                                              \
	} while (0)

/* these errors do not fail the connection */
#define IS_TEMPORARY_ERROR(err)                                                \
	((err) == EAGAIN || (err) == EWOULDBLOCK || (err) == EINTR ||          \
	 (err) == ENOMEM)

#define LOG_RATELIMITEDF(level, loop, rate, format, ...)                       \
	do {                                                                   \
		if (LOGLEVEL(level)) {                                         \
			const ev_tstamp now = ev_now(loop);                    \
			static ev_tstamp last_log = TSTAMP_NIL;                \
			if (last_log == TSTAMP_NIL ||                          \
			    now - last_log > (rate)) {                         \
				LOG_WRITE(                                     \
					level, __FILE__, __LINE__, format,     \
					__VA_ARGS__);                          \
				last_log = now;                                \
			}                                                      \
		}                                                              \
	} while (0)

#define LOG_RATELIMITED(level, loop, rate, message)                            \
	LOG_RATELIMITEDF(level, loop, rate, "%s", message)

struct server;

void kcp_notify_update(struct server *s);

#endif /* EVENT_IMPL_H */
