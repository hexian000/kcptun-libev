#ifndef SLOG_H
#define SLOG_H

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>

enum { LOG_LEVEL_VERBOSE,
       LOG_LEVEL_DEBUG,
       LOG_LEVEL_INFO,
       LOG_LEVEL_WARNING,
       LOG_LEVEL_ERROR,
       LOG_LEVEL_FATAL,
       LOG_LEVEL_SILENCE,
};
extern const char slog_level_char[];
extern int slog_level;
extern FILE *slog_file;

#if defined(_MSC_VER)
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

#define LOGLEVEL(x) ((x) >= slog_level)

#define LOG_INTERNAL(level, path, line, format, ...)                           \
	do {                                                                   \
		if (LOGLEVEL(level)) {                                         \
			FILE *log_fp = slog_file ? slog_file : stdout;         \
			const time_t log_now = time(NULL);                     \
			char log_timestamp[32];                                \
			const int timestamp_len = strftime(                    \
				log_timestamp, sizeof(log_timestamp),          \
				"%FT%T%z", localtime(&log_now));               \
			const char *log_filename =                             \
				strrchr((path), PATH_SEPARATOR);               \
			if (log_filename && *log_filename) {                   \
				log_filename++;                                \
			} else {                                               \
				log_filename = (path);                         \
			}                                                      \
			(void)fprintf(                                         \
				log_fp, "%c %*s %s:%d " format "\n",           \
				slog_level_char[(level)], timestamp_len,       \
				log_timestamp, log_filename, (line),           \
				__VA_ARGS__);                                  \
			(void)fflush(log_fp);                                  \
		}                                                              \
	} while (0)

/* Fatal: Log an fatal message. */
#define LOGF_F(format, ...)                                                    \
	LOG_INTERNAL(LOG_LEVEL_FATAL, __FILE__, __LINE__, format, __VA_ARGS__)
#define LOGF(message) LOGF_F("%s", message)

/* Error: Log an error message. */
#define LOGE_F(format, ...)                                                    \
	LOG_INTERNAL(LOG_LEVEL_ERROR, __FILE__, __LINE__, format, __VA_ARGS__)
#define LOGE(message) LOGE_F("%s", message)

/* Warning: Log a warning message. */
#define LOGW_F(format, ...)                                                    \
	LOG_INTERNAL(LOG_LEVEL_WARNING, __FILE__, __LINE__, format, __VA_ARGS__)
#define LOGW(message) LOGW_F("%s", message)

/* Info: Log an info message. */
#define LOGI_F(format, ...)                                                    \
	LOG_INTERNAL(LOG_LEVEL_INFO, __FILE__, __LINE__, format, __VA_ARGS__)
#define LOGI(message) LOGI_F("%s", message)

/* Debug: Log a debug message. */
#define LOGD_F(format, ...)                                                    \
	LOG_INTERNAL(LOG_LEVEL_DEBUG, __FILE__, __LINE__, format, __VA_ARGS__)
#define LOGD(message) LOGD_F("%s", message)

/* Verbose: Log a verbose message. */
#define LOGV_F(format, ...)                                                    \
	LOG_INTERNAL(LOG_LEVEL_VERBOSE, __FILE__, __LINE__, format, __VA_ARGS__)
#define LOGV(message) LOGV_F("%s", message)

/* perror: Log an error message with last system error message. */
#define LOGW_PERROR(message)                                                   \
	LOG_INTERNAL(                                                          \
		LOG_LEVEL_WARNING, __FILE__, __LINE__, "%s: [%d] %s", message, \
		errno, strerror(errno))

#define LOGE_PERROR(message)                                                   \
	LOG_INTERNAL(                                                          \
		LOG_LEVEL_ERROR, __FILE__, __LINE__, "%s: [%d] %s", message,   \
		errno, strerror(errno))

#endif /* SLOG_H */
