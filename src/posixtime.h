#ifndef POSIXTIME_H
#define POSIXTIME_H

#include <time.h>
#if HAVE_GETTIMEOFDAY
#include <sys/time.h>
#endif

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Get current realtime timestamp.
 * @return Timestamp in nanoseconds.
 */
static inline int64_t clock_realtime()
{
#if HAVE_CLOCK_GETTIME
	struct timespec t;
	(void)clock_gettime(CLOCK_REALTIME, &t);
	return (int64_t)(t.tv_sec) * INT64_C(1000000000) + (int64_t)(t.tv_nsec);
#elif HAVE_GETTIMEOFDAY
	/* use obsoleted api for compatibility */
	struct timeval t;
	(void)gettimeofday(&t, NULL);
	return (int64_t)(t.tv_sec) * INT64_C(1000000000) +
	       (int64_t)(t.tv_usec) * INT64_C(1000000);
#else
	return (int64_t)time(NULL) * INT64_C(1000000000);
#endif
}

/**
 * @brief Get current monotonic timestamp.
 * @return Timestamp in nanoseconds.
 */
static inline int64_t clock_monotonic()
{
#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)
	struct timespec t;
	(void)clock_gettime(CLOCK_MONOTONIC, &t);
	return (int64_t)(t.tv_sec) * INT64_C(1000000000) + (int64_t)(t.tv_nsec);
#else
	return (int64_t)clock() *
	       (INT64_C(1000000000) / (int64_t)CLOCKS_PER_SEC);
#endif
}

#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)
#define clock_nanos() clock_monotonic()
#else
#define clock_nanos() clock_realtime()
#endif

#endif /* POSIXTIME_H */
