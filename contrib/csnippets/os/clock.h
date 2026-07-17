/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef OS_CLOCK_H
#define OS_CLOCK_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/**
 * @brief Get current Unix timestamp. (Unix epoch)
 * @param[out] tp The timestamp, if successful.
 * @return true if successful.
 */
static inline bool clock_unix(struct timespec *restrict tp)
{
#if HAVE_CLOCK_GETTIME && defined(CLOCK_REALTIME)
	if (clock_gettime(CLOCK_REALTIME, tp) == 0) {
		return true;
	}
#elif HAVE_TIMESPEC_GET && defined(TIME_UTC)
	return timespec_get(tp, TIME_UTC) == TIME_UTC;
#endif
	(void)tp;
	return false;
}

/**
 * @brief Get current monotonic timestamp.
 * @param[out] tp The timestamp, if successful.
 * @return true if successful.
 */
static inline bool clock_monotonic(struct timespec *restrict tp)
{
#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)
	if (clock_gettime(CLOCK_MONOTONIC, tp) == 0) {
		return true;
	}
#elif HAVE_TIMESPEC_GET && defined(TIME_UTC)
	/* ISO C11 fallback: TIME_UTC is wall-clock, not guaranteed monotonic (it
	 * may jump on clock adjustment), but it is the only standard option where
	 * clock_gettime is unavailable. */
	return timespec_get(tp, TIME_UTC) == TIME_UTC;
#endif
	(void)tp;
	return false;
}

/**
 * @brief Get current thread CPU time.
 * @param tp Pointer to timespec structure to store the time.
 * @return true if successful, false otherwise.
 */
static inline bool clock_thread(struct timespec *restrict tp)
{
#if HAVE_CLOCK_GETTIME && defined(CLOCK_THREAD_CPUTIME_ID)
	if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, tp) == 0) {
		return true;
	}
#endif
	(void)tp;
	return false;
}

/**
 * @brief Get current process CPU time.
 * @param tp Pointer to timespec structure to store the time.
 * @return true if successful, false otherwise.
 */
static inline bool clock_process(struct timespec *restrict tp)
{
#if HAVE_CLOCK_GETTIME && defined(CLOCK_PROCESS_CPUTIME_ID)
	if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, tp) == 0) {
		return true;
	}
#endif
	(void)tp;
	return false;
}

/**
 * @brief Get current boot time.
 * @param tp Pointer to timespec structure to store the time.
 * @return true if successful, false otherwise.
 */
static inline bool clock_boot(struct timespec *restrict tp)
{
#if HAVE_CLOCK_GETTIME && defined(CLOCK_BOOTTIME)
	if (clock_gettime(CLOCK_BOOTTIME, tp) == 0) {
		return true;
	}
#endif
	(void)tp;
	return false;
}

/**
 * @brief Convert timespec to nanoseconds.
 * @details The argument is expanded twice (tv_sec and tv_nsec), so it must be
 * free of side effects.
 */
#define TIMESPEC_NANO(ts)                                                      \
	((int_fast64_t)(ts).tv_sec * INT64_C(1000000000) +                     \
	 (int_fast64_t)(ts).tv_nsec)

/**
 * @brief Calculate the difference between two timespecs in nanoseconds.
 * @details Subtracts the tv_sec and tv_nsec fields before scaling, which is
 * well-defined whenever both the scaled second-difference and the final result
 * fit an int_fast64_t. Each argument is expanded twice (tv_sec and tv_nsec), so
 * it must be free of side effects.
 */
#define TIMESPEC_DIFF(ts0, ts1)                                                \
	(((int_fast64_t)(ts0).tv_sec - (int_fast64_t)(ts1).tv_sec) *           \
		 INT64_C(1000000000) +                                         \
	 ((int_fast64_t)(ts0).tv_nsec - (int_fast64_t)(ts1).tv_nsec))

/**
 * @brief Get current Unix timestamp.
 * @return Timestamp in nanoseconds, or -1 on failure. Note the sentinel is
 * in-band: -1 is also a representable timestamp (1ns before the epoch).
 */
static inline int_fast64_t clock_unix_ns(void)
{
	struct timespec ts;
	if (!clock_unix(&ts)) {
		return -1;
	}
	return TIMESPEC_NANO(ts);
}

/**
 * @brief Get current monotonic timestamp.
 * @return Timestamp in nanoseconds, or -1 on failure.
 */
static inline int_fast64_t clock_monotonic_ns(void)
{
	struct timespec ts;
	if (!clock_monotonic(&ts)) {
		return -1;
	}
	return TIMESPEC_NANO(ts);
}

#endif /* OS_CLOCK_H */
