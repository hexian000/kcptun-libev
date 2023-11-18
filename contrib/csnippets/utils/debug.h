/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_DEBUG_H
#define UTILS_DEBUG_H

#include "buffer.h"
#include "slog.h"

#include <stddef.h>
#include <stdlib.h>

struct buffer;
struct vbuffer;

struct vbuffer *
print_txt(struct vbuffer *vbuf, const char *indent, const void *data, size_t n);
struct vbuffer *
print_bin(struct vbuffer *vbuf, const char *indent, const void *data, size_t n);

#if WITH_LIBUNWIND
void print_stack(struct buffer *buf, const char *indent);

#define LOG_STACK_F(level, format, ...)                                        \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		struct {                                                       \
			BUFFER_HDR;                                            \
			unsigned char data[4096];                              \
		} buf;                                                         \
		BUF_INIT(buf, 0);                                              \
		print_stack((struct buffer *)&buf, "  ");                      \
		if (buf.len > 0 && buf.data[buf.len - 1] == '\n') {            \
			buf.len--;                                             \
		}                                                              \
		LOG_F(level, format "\n%.*s", __VA_ARGS__, (int)buf.len,       \
		      buf.data);                                               \
	} while (0)
#define LOG_STACK(level, msg) LOG_STACK_F(level, "%s", msg)
#else
#define LOG_STACK_F(level, format, ...)                                        \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(level, format, __VA_ARGS__);                             \
	} while (0)
#define LOG_STACK(level, msg) LOG_STACK_F(level, "%s", msg)
#endif

#define LOG_TXT_F(level, txt, txtsize, format, ...)                            \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		struct vbuffer *vbuf =                                         \
			print_txt(NULL, "  ", (txt), (txtsize));               \
		if (vbuf->len > 0 && vbuf->data[vbuf->len - 1] == '\n') {      \
			vbuf->len--;                                           \
		}                                                              \
		LOG_F(level, format "\n%.*s", __VA_ARGS__, (int)vbuf->len,     \
		      vbuf->data);                                             \
		VBUF_FREE(vbuf);                                               \
	} while (0)
#define LOG_TXT(level, txt, txtsize, msg)                                      \
	LOG_TXT_F(level, txt, txtsize, "%s", msg)

#define LOG_BIN_F(level, bin, binsize, format, ...)                            \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		struct vbuffer *vbuf =                                         \
			print_bin(NULL, "  ", (bin), (binsize));               \
		if (vbuf->len > 0 && vbuf->data[vbuf->len - 1] == '\n') {      \
			vbuf->len--;                                           \
		}                                                              \
		LOG_F(level, format "\n%.*s", __VA_ARGS__, (int)vbuf->len,     \
		      vbuf->data);                                             \
		VBUF_FREE(vbuf);                                               \
	} while (0)
#define LOG_BIN(level, bin, binsize, msg)                                      \
	LOG_BIN_F(level, bin, binsize, "%s", msg)

/* FAIL*: log a fatal message and abort the program */
#define FAILMSGF(format, ...)                                                  \
	do {                                                                   \
		LOG_STACK_F(FATAL, format, __VA_ARGS__);                       \
		abort();                                                       \
	} while (0)
#define FAILMSG(msg) FAILMSGF("%s", msg)
#define FAIL() FAILMSG("program entered an unexpected state (bug?)")

/* CHECK*: check runtime condition or FAIL */
#define CHECKMSGF(cond, format, ...)                                           \
	do {                                                                   \
		if (!(cond)) {                                                 \
			FAILMSGF(format, __VA_ARGS__);                         \
		}                                                              \
	} while (0)
#define CHECKMSG(cond, msg) CHECKMSGF(cond, "%s", msg)
#define CHECK(cond) CHECKMSG(cond, "runtime check failed")

/* check critical allocation failure */
#define FAILOOM()                                                              \
	do {                                                                   \
		LOG_STACK(FATAL, "out of memory");                             \
		exit(EXIT_FAILURE);                                            \
	} while (0)
#define CHECKOOM(ptr)                                                          \
	do {                                                                   \
		if ((ptr) == NULL) {                                           \
			FAILOOM();                                             \
		}                                                              \
	} while (0)
#define LOGOOM() LOGE("out of memory")

#endif /* UTILS_DEBUG_H */
