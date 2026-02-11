/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef OS_CLOCK_H
#define OS_CLOCK_H

#include <time.h>

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Get current realtime timestamp.
 * @return Timestamp in nanoseconds. (Unix epoch)
 */
static inline bool clock_realtime(struct timespec *restrict tp)
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
 * @return Timestamp in nanoseconds.
 */
static inline bool clock_monotonic(struct timespec *restrict tp)
{
#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)
	if (clock_gettime(CLOCK_MONOTONIC, tp) == 0) {
		return true;
	}
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
 * @brief Convert timespec to seconds.
 * @param tp Pointer to timespec structure.
 * @return Time in seconds as double.
 */
static inline double timespec2second(const struct timespec *tp)
{
	return (double)tp->tv_sec + (double)tp->tv_nsec * 1e-9;
}

/**
 * @brief Convert timespec to nanoseconds.
 * @param tp Pointer to timespec structure.
 * @return Time in nanoseconds as int_least64_t.
 */
static inline int_least64_t timespec2nano(const struct timespec *tp)
{
	return (int_least64_t)tp->tv_sec * UINT64_C(1000000000) +
	       (int_least64_t)tp->tv_nsec;
}

/**
 * @brief Get current monotonic timestamp.
 * @return Timestamp in seconds.
 */
static inline double clock_monotonic_seconds(void)
{
	struct timespec ts;
	if (!clock_monotonic(&ts)) {
		return -1;
	}
	return timespec2second(&ts);
}

/**
 * @brief Get current monotonic timestamp.
 * @return Timestamp in nanoseconds.
 */
static inline int_least64_t clock_monotonic_ns(void)
{
	struct timespec ts;
	if (!clock_monotonic(&ts)) {
		return -1;
	}
	return timespec2nano(&ts);
}

#endif /* OS_CLOCK_H */
