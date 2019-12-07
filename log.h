#ifndef LOG_H
#define LOG_H

#include "config.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(HAVE_SYS_TIME_H)
#include <sys/time.h>
#endif

typedef enum {
	LOG_LEVEL_SILENCE,
	LOG_LEVEL_FATAL,
	LOG_LEVEL_ERROR,
	LOG_LEVEL_WARNING,
	LOG_LEVEL_INFO,
	LOG_LEVEL_DEBUG,
	LOG_LEVEL_VERBOSE
} log_level_t;
extern log_level_t log_level;
extern const char log_level_char[];

static inline int log_timestamp(char *buf, size_t size)
{
	time_t now;
	long msec;
#if defined(HAVE_CLOCK_GETTIME)
	{
		struct timespec t;
		clock_gettime(CLOCK_REALTIME, &t);
		now = t.tv_sec;
		msec = t.tv_nsec / 1000000L;
	}
#elif defined(HAVE_GETTIMEOFDAY)
	{
		struct timeval t;
		gettimeofday(&t, NULL);
		now = t.tv_sec;
		msec = t.tv_usec / 1000L;
	}
#else
	now = time(NULL);
	msec = 0;
#endif
	struct tm lt;
#if defined(HAVE_LOCALTIME_R)
	localtime_r(&now, &lt);
#else
	lt = *localtime(&now);
#endif
	char timestr[32];
	strftime(timestr, sizeof(timestr), "%FT%T.%%03ld%z", &lt);
	return snprintf(buf, size, timestr, msec);
}

#define LOG(level, file, line, format, ...)                                    \
	do {                                                                   \
		if (log_level >= level) {                                      \
			char buf[32];                                          \
			log_timestamp(buf, sizeof(buf));                       \
			fprintf(stdout, "%c %s %s:%d " format "\n",            \
				log_level_char[level], buf, file, line,        \
				__VA_ARGS__);                                  \
			fflush(stdout);                                        \
		}                                                              \
	} while (0)

/* What a Terrible Failure: Log a fatal error message and exit immediately. */
#define LOGF_WTF(format, ...)                                                  \
	do {                                                                   \
		LOG(LOG_LEVEL_FATAL, __FILE__, __LINE__, format, __VA_ARGS__); \
		exit(EXIT_FAILURE); /* exit due to fatal error */              \
	} while (0)
#define LOG_WTF(info) LOGF_WTF("%s", info)

/* Error: Log an error message. */
#define LOGF_E(format, ...)                                                    \
	LOG(LOG_LEVEL_ERROR, __FILE__, __LINE__, format, __VA_ARGS__)
#define LOG_E(info) LOGF_E("%s", info)

/* Warning: Log a warning message. */
#define LOGF_W(format, ...)                                                    \
	LOG(LOG_LEVEL_WARNING, __FILE__, __LINE__, format, __VA_ARGS__)
#define LOG_W(info) LOGF_W("%s", info)

/* Info: Log an info message. */
#define LOGF_I(format, ...)                                                    \
	LOG(LOG_LEVEL_INFO, __FILE__, __LINE__, format, __VA_ARGS__)
#define LOG_I(info) LOGF_I("%s", info)

/* Debug: Log a debug message. */
#define LOGF_D(format, ...)                                                    \
	LOG(LOG_LEVEL_DEBUG, __FILE__, __LINE__, format, __VA_ARGS__)
#define LOG_D(info) LOGF_D("%s", info)

/* Verbose: Log a verbose message. */
#define LOGF_V(format, ...)                                                    \
	LOG(LOG_LEVEL_VERBOSE, __FILE__, __LINE__, format, __VA_ARGS__)
#define LOG_V(info) LOGF_V("%s", info)

/* perror: Log an error message with last system error message. */
#define LOG_PERROR(info)                                                       \
	LOG(LOG_LEVEL_ERROR, __FILE__, __LINE__, "%s: [%d] %s", info, errno,   \
	    strerror(errno))

#endif /* LOG_H */
