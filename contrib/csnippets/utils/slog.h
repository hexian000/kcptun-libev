/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_SLOG_H
#define UTILS_SLOG_H

#include <stdarg.h>
#include <stdio.h>

#if SLOG_MT_SAFE
#include <stdatomic.h>
#endif

enum {
	LOG_LEVEL_SILENCE,
	LOG_LEVEL_FATAL,
	LOG_LEVEL_ERROR,
	LOG_LEVEL_WARNING,
	LOG_LEVEL_NOTICE,
	LOG_LEVEL_INFO,
	LOG_LEVEL_DEBUG,
	LOG_LEVEL_VERBOSE,
	LOG_LEVEL_VERYVERBOSE,
};
#if SLOG_MT_SAFE
extern atomic_int slog_level_;
#else
extern int slog_level_;
#endif
void slog_setlevel(int level);

enum {
	SLOG_OUTPUT_DISCARD,
	SLOG_OUTPUT_TERMINAL,
	SLOG_OUTPUT_FILE,
	SLOG_OUTPUT_SYSLOG,
};
void slog_setoutput(int type, ...);

void slog_setfileprefix(const char *prefix);

struct slog_extra {
	void (*func)(FILE *f, void *data);
	void *data;
};
void slog_vprintf(
	int level, const char *file, int line, const struct slog_extra *extra,
	const char *format, va_list args);
void slog_printf(
	int level, const char *file, int line, const struct slog_extra *extra,
	const char *format, ...);

/* LOG_F: Internal macro to log a message unconditionally. This is not a part of supported API. */
#define LOG_F(level, format, ...)                                              \
	slog_printf(                                                           \
		(LOG_LEVEL_##level), __FILE__, __LINE__, NULL, (format),       \
		__VA_ARGS__)

#if SLOG_MT_SAFE
#define LOGLEVEL(level)                                                        \
	((LOG_LEVEL_##level) <=                                                \
	 atomic_load_explicit(&slog_level_, memory_order_acquire))
#else
#define LOGLEVEL(level) ((LOG_LEVEL_##level) <= slog_level_)
#endif

/* Temporary: Temporary logs are printed in any debug build regardless of log level. */
#ifndef NDEBUG
#define LOGT_F(format, ...)                                                    \
	do {                                                                   \
		LOG_F(SILENCE, format, __VA_ARGS__);                           \
	} while (0)
#else
#define LOGT_F(format, ...)                                                    \
	do {                                                                   \
	} while (0)
#endif
#define LOGT(message) LOGT_F("%s", message)

/* Fatal: Serious problems that are likely to cause the program to exit. */
#define LOGF_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(FATAL)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(FATAL, format, __VA_ARGS__);                             \
	} while (0)
#define LOGF(message) LOGF_F("%s", message)

/* Error: Issues that shouldn't be ignored. */
#define LOGE_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(ERROR)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(ERROR, format, __VA_ARGS__);                             \
	} while (0)
#define LOGE(message) LOGE_F("%s", message)

/* Warning: Issues that may be ignored. */
#define LOGW_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(WARNING)) {                                      \
			break;                                                 \
		}                                                              \
		LOG_F(WARNING, format, __VA_ARGS__);                           \
	} while (0)
#define LOGW(message) LOGW_F("%s", message)

/* Notice: Important status changes. The prefix is 'I'. */
#define LOGN_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(NOTICE)) {                                       \
			break;                                                 \
		}                                                              \
		LOG_F(NOTICE, format, __VA_ARGS__);                            \
	} while (0)
#define LOGN(message) LOGN_F("%s", message)

/* Info: Normal work reports. */
#define LOGI_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(INFO)) {                                         \
			break;                                                 \
		}                                                              \
		LOG_F(INFO, format, __VA_ARGS__);                              \
	} while (0)
#define LOGI(message) LOGI_F("%s", message)

/* Debug: Extra information for debugging. */
#define LOGD_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(DEBUG)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(DEBUG, format, __VA_ARGS__);                             \
	} while (0)
#define LOGD(message) LOGD_F("%s", message)

/* Verbose: Details for inspecting specific issues. */
#define LOGV_F(format, ...)                                                    \
	do {                                                                   \
		if (!LOGLEVEL(VERBOSE)) {                                      \
			break;                                                 \
		}                                                              \
		LOG_F(VERBOSE, format, __VA_ARGS__);                           \
	} while (0)
#define LOGV(message) LOGV_F("%s", message)

/* VeryVerbose: More details that may significantly impact performance. The prefix is 'V'. */
#define LOGVV_F(format, ...)                                                   \
	do {                                                                   \
		if (!LOGLEVEL(VERYVERBOSE)) {                                  \
			break;                                                 \
		}                                                              \
		LOG_F(VERYVERBOSE, format, __VA_ARGS__);                       \
	} while (0)
#define LOGVV(message) LOGVV_F("%s", message)

/* Convenience macro for logging errors with errno */
#define LOG_PERROR(what)                                                       \
	do {                                                                   \
		const int err = errno;                                         \
		LOGE_F("%s: [%d] %s", what, err, strerror(errno));             \
	} while (0)

#endif /* UTILS_SLOG_H */
