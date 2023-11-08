/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_SLOG_H
#define UTILS_SLOG_H

#include <stdio.h>
#if HAVE_SYSLOG
#include <syslog.h>
#endif

enum {
	LOG_LEVEL_SILENCE,
	LOG_LEVEL_FATAL,
	LOG_LEVEL_ERROR,
	LOG_LEVEL_WARNING,
	LOG_LEVEL_INFO,
	LOG_LEVEL_DEBUG,
	LOG_LEVEL_VERBOSE,
};

#define LOG_LEVEL_SILENCE_STR "-"
#define LOG_LEVEL_FATAL_STR "F"
#define LOG_LEVEL_ERROR_STR "E"
#define LOG_LEVEL_WARNING_STR "W"
#define LOG_LEVEL_INFO_STR "I"
#define LOG_LEVEL_DEBUG_STR "D"
#define LOG_LEVEL_VERBOSE_STR "V"

extern int slog_level;
extern FILE *slog_file;

void slog_write(int level, const char *path, int line, const char *format, ...);

#define LOG_WRITE(level, path, line, format, ...)                              \
	slog_write((level), (path), (line), (format), __VA_ARGS__)

/* LOG: Log a message unconditionally. */
#define LOG_F(level, format, ...)                                              \
	LOG_WRITE(level, __FILE__, __LINE__, format, __VA_ARGS__);
#define LOG(level, message) LOG_F(level, "%s", message)

#define LOGLEVEL(x) ((x) <= slog_level)

/* LOGF: Log a fatal message. */
#define LOGF_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(LOG_LEVEL_FATAL)) {                              \
			break;                                                 \
		}                                                              \
		LOG_WRITE(                                                     \
			LOG_LEVEL_FATAL, __FILE__, __LINE__, format,           \
			__VA_ARGS__);                                          \
	} while (0)
#define LOGF(message) LOGF_F("%s", message)

/* Error: Log an error message. */
#define LOGE_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(LOG_LEVEL_ERROR)) {                              \
			break;                                                 \
		}                                                              \
		LOG_WRITE(                                                     \
			LOG_LEVEL_ERROR, __FILE__, __LINE__, format,           \
			__VA_ARGS__);                                          \
	} while (0)
#define LOGE(message) LOGE_F("%s", message)

/* Warning: Log a warning message. */
#define LOGW_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(LOG_LEVEL_WARNING)) {                            \
			break;                                                 \
		}                                                              \
		LOG_WRITE(                                                     \
			LOG_LEVEL_WARNING, __FILE__, __LINE__, format,         \
			__VA_ARGS__);                                          \
	} while (0)
#define LOGW(message) LOGW_F("%s", message)

/* Info: Log an info message. */
#define LOGI_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(LOG_LEVEL_INFO)) {                               \
			break;                                                 \
		}                                                              \
		LOG_WRITE(                                                     \
			LOG_LEVEL_INFO, __FILE__, __LINE__, format,            \
			__VA_ARGS__);                                          \
	} while (0)
#define LOGI(message) LOGI_F("%s", message)

/* Debug: Log a debug message. */
#define LOGD_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(LOG_LEVEL_DEBUG)) {                              \
			break;                                                 \
		}                                                              \
		LOG_WRITE(                                                     \
			LOG_LEVEL_DEBUG, __FILE__, __LINE__, format,           \
			__VA_ARGS__);                                          \
	} while (0)
#define LOGD(message) LOGD_F("%s", message)

/* Verbose: Log a verbose message. */
#define LOGV_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(LOG_LEVEL_VERBOSE)) {                            \
			break;                                                 \
		}                                                              \
		LOG_WRITE(                                                     \
			LOG_LEVEL_VERBOSE, __FILE__, __LINE__, format,         \
			__VA_ARGS__);                                          \
	} while (0)
#define LOGV(message) LOGV_F("%s", message)

#endif /* UTILS_SLOG_H */
