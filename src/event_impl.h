
#ifndef EVENT_IMPL_H
#define EVENT_IMPL_H

#include <ev.h>

#define CHECK_EV_ERROR(revents)                                                \
	do {                                                                   \
		if ((unsigned)(revents) & (unsigned)EV_ERROR) {                \
			LOGE_PERROR("got error event");                        \
			return;                                                \
		}                                                              \
	} while (0)

#define LOG_RATELIMITEDF(level, loop, rate, format, ...)                       \
	do {                                                                   \
		const ev_tstamp now = ev_now(loop);                            \
		static ev_tstamp last_log = TSTAMP_NIL;                        \
		if (last_log == TSTAMP_NIL || now - last_log > (rate)) {       \
			LOG_INTERNAL(                                          \
				level, __FILE__, __LINE__, format,             \
				__VA_ARGS__);                                  \
			last_log = now;                                        \
		}                                                              \
	} while (0)

#define LOG_RATELIMITED(level, loop, rate, message)                            \
	LOG_RATELIMITEDF(level, loop, rate, "%s", message)

#endif /* EVENT_IMPL_H */
