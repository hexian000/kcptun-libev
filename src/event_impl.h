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
			LOGE_F("error event: [errno=%d] %s", err,              \
			       strerror(err));                                 \
			return;                                                \
		}                                                              \
	} while (0)

/* Check if the error is generally "transient":
 *   In accept()/send()/recv()/sendmsg()/recvmsg()/sendmmsg()/recvmmsg(),
 * transient errors should not cause the socket to fail. The operation should
 * be retried later if the corresponding event is still available.
 */
#define IS_TRANSIENT_ERROR(err)                                                \
	((err) == EINTR || (err) == EAGAIN || (err) == EWOULDBLOCK ||          \
	 (err) == ENOBUFS || (err) == ENOMEM)

#define LOG_RATELIMITEDF(level, now, rate, format, ...)                        \
	do {                                                                   \
		if (LOGLEVEL(level)) {                                         \
			RATELIMIT(                                             \
				now, rate, LOG_F(level, format, __VA_ARGS__)); \
		}                                                              \
	} while (0)

#define LOG_RATELIMITED(level, now, rate, message)                             \
	LOG_RATELIMITEDF(level, now, rate, "%s", message)

struct server;

#endif /* EVENT_IMPL_H */
