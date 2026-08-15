/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef OS_CLOCK_H
#define OS_CLOCK_H

#ifdef _WIN32
#include <Windows.h>

#include <stdatomic.h>

#endif
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
 * @param[out] tp The timestamp, if successful.
 * @return true if successful.
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
 * @param[out] tp The timestamp, if successful.
 * @return true if successful.
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
 * @param[out] tp The timestamp, if successful.
 * @return true if successful.
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

#ifdef _WIN32

/* Windows has no clock_gettime, and timespec_get(TIME_UTC) is neither
 * monotonic nor fine-grained there, so the nanosecond helpers read the native
 * counters instead. Neither can fail: the -1 sentinel below is never
 * returned on this platform. */

/**
 * @brief Get current Unix timestamp.
 * @return Timestamp in nanoseconds. Never fails on Windows.
 */
static inline int_fast64_t clock_unix_ns(void)
{
	FILETIME Time;
	GetSystemTimePreciseAsFileTime(&Time);
	/* FILETIME counts 100 ns intervals since 1601-01-01; shift to the Unix
	 * epoch (1970-01-01) before converting to nanoseconds. The offset is
	 * 11644473600 seconds expressed in 100 ns units. */
	const int_fast64_t ft = ((int_fast64_t)(Time.dwHighDateTime) << 32u) +
				(int_fast64_t)(Time.dwLowDateTime);
	return (ft - INT64_C(116444736000000000)) * INT64_C(100);
}

/**
 * @brief Get current monotonic timestamp.
 * @return Timestamp in nanoseconds. Never fails on Windows.
 */
static inline int_fast64_t clock_monotonic_ns(void)
{
	/* The QPC frequency is fixed at boot, so query it once: this is the
	 * timestamp source under measure.h's benchmark loops. The cache is
	 * atomic because callers may be concurrent; relaxed suffices, as it
	 * carries no other state and every writer stores the same boot-fixed
	 * value, so racing first callers merely query twice. Both BOOL returns
	 * are dropped because neither call can fail on Windows XP or later --
	 * QueryPerformanceFrequency returns FALSE only where no high-resolution
	 * counter exists, which no supported version reports. */
	static atomic_int_fast64_t freq_cache;
	int_fast64_t freq =
		atomic_load_explicit(&freq_cache, memory_order_relaxed);
	if (freq == 0) {
		LARGE_INTEGER Frequency;
		(void)QueryPerformanceFrequency(&Frequency);
		freq = (int_fast64_t)Frequency.QuadPart;
		atomic_store_explicit(&freq_cache, freq, memory_order_relaxed);
	}
	LARGE_INTEGER Counter;
	(void)QueryPerformanceCounter(&Counter);
	const int_fast64_t ticks = (int_fast64_t)Counter.QuadPart;
	/* Split into whole seconds plus the sub-second remainder so the
	 * intermediate product never overflows: ticks * 1e9 overflows int64
	 * after roughly 15 minutes of uptime at a 10 MHz QPC frequency. */
	return (ticks / freq) * INT64_C(1000000000) +
	       (ticks % freq) * INT64_C(1000000000) / freq;
}

#else /* _WIN32 */

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

#endif /* _WIN32 */

#endif /* OS_CLOCK_H */
