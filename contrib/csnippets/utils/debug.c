/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "debug.h"

#include "utils/ascii.h"
#include "utils/buffer.h"

#if WITH_LIBBACKTRACE
#include <backtrace.h>
#elif WITH_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#elif HAVE_BACKTRACE
#include <execinfo.h>
#endif

#include <assert.h>
#include <inttypes.h>
#if SLOG_MT_SAFE
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

#define TAB_SPACE "    "
#define TAB_WIDTH (sizeof(TAB_SPACE) - 1)

#define INDENT "  "

void slog_extra_txt(FILE *restrict f, void *restrict data)
{
	const struct slog_extra_txt *extra = data;
	size_t n = extra->len;
	const size_t hardwrap = extra->hardwrap < 4 ? 80 : extra->hardwrap;
	const char *restrict s = extra->data;
	struct {
		BUFFER_HDR;
		unsigned char data[256];
	} buf;
	BUF_INIT(buf, 0);
	bool newline = true;
	bool cr = false;
	size_t line = 0, column = 0;
	/* thread one conversion state across the whole decode so a
	 * state-dependent multibyte encoding is not mis-decoded */
	mbstate_t mbs = { 0 };
	while (n > 0) {
		wchar_t wc;
		const size_t clen = mbrtowc(&wc, s, n, &mbs);
		if (clen == 0 || clen == (size_t)-1 || clen == (size_t)-2) {
			break;
		}
		s += clen, n -= clen;
		if (cr && wc == L'\n') {
			/* skip CRLF */
			cr = false;
			continue;
		}
		cr = (wc == L'\r');
		if (newline) {
			BUF_APPENDF(buf, INDENT "%4zu ", ++line);
			newline = false;
		}
		size_t width;
		switch (wc) {
		case L'\r':
		case L'\n':
			/* soft wrap */
			BUF_APPENDSTR(buf, "\n");
			(void)fwrite(buf.data, sizeof(buf.data[0]), buf.len, f);
			buf.len = 0;
			column = 0;
			newline = true;
			continue;
		case L'\t':
			width = TAB_WIDTH - column % TAB_WIDTH;
			break;
		default:
			if (!iswprint(wc)) {
				wc = L'?';
			}
#if HAVE_WCWIDTH
			{
				/* wcwidth() can return -1 for a code point some
				 * libc implementations consider undefined-width
				 * even when iswprint() is true; casting that to
				 * size_t would silently corrupt the running
				 * column counter used for wrap decisions. */
				const int w = wcwidth(wc);
				width = (w < 0) ? 1 : (size_t)w;
			}
#else
			width = 1;
#endif /* HAVE_WCWIDTH */
		}
		if (column + width > hardwrap) {
			/* hard wrap */
			BUF_APPENDSTR(buf, " +\n" INDENT "     ");
			(void)fwrite(buf.data, sizeof(buf.data[0]), buf.len, f);
			buf.len = 0;
			column = 0;
			if (wc == L'\t') {
				/* recalculate tab width */
				width = TAB_WIDTH;
			}
		}
		if (wc == L'\t') {
			BUF_APPEND(buf, TAB_SPACE, width);
			column += width;
		} else {
			BUF_APPENDF(buf, "%lc", wc);
			column += width;
		}
		if (buf.cap - buf.len < 16) {
			(void)fwrite(buf.data, sizeof(buf.data[0]), buf.len, f);
			buf.len = 0;
		}
	}
	if (column > 0) {
		BUF_APPENDSTR(buf, "\n");
	}
	if (buf.len > 0) {
		(void)fwrite(buf.data, sizeof(buf.data[0]), buf.len, f);
		buf.len = 0;
	}
	if (n > 0) {
		/* omit bytes after the null terminator or undecodable code point */
		(void)fprintf(f, INDENT " ... (omitting %zu bytes)\n", n);
	}
}

void slog_extra_bin(FILE *restrict f, void *restrict data)
{
	const struct slog_extra_bin *extra = data;
	size_t n = extra->len;
	struct {
		BUFFER_HDR;
		unsigned char data[256];
	} buf;
	BUF_INIT(buf, 0);
	const size_t binwrap = extra->binwrap < 1 ? 16 : extra->binwrap;
	const unsigned char *restrict b = extra->data;
	/* The fixed buffer only coalesces output to reduce write calls; flush it
	 * whenever the next token might not fit, so a large binwrap does not
	 * silently truncate a row. fwrite concatenates, so splitting a row across
	 * writes yields byte-identical output. */
#define BIN_FLUSH_IF(need)                                                     \
	do {                                                                   \
		if (buf.cap - buf.len < (size_t)(need)) {                      \
			(void)fwrite(                                          \
				buf.data, sizeof(buf.data[0]), buf.len, f);    \
			buf.len = 0;                                           \
		}                                                              \
	} while (0)
	for (size_t i = 0; i < n; i += binwrap) {
		/* INDENT + "0x" + up to two hex digits per pointer byte + ": " */
		BIN_FLUSH_IF(sizeof(INDENT) + 2 + 2 * sizeof(void *) + 2);
		BUF_APPENDF(buf, INDENT "%p: ", (void *)(b + i));
		for (size_t j = 0; j < binwrap; j++) {
			/* "%02hhX " is 3 chars, +1 for buf_appendf's in-place NUL */
			BIN_FLUSH_IF(4);
			if ((i + j) < n) {
				BUF_APPENDF(buf, "%02hhX ", b[i + j]);
			} else {
				BUF_APPENDSTR(buf, "   ");
			}
		}
		BIN_FLUSH_IF(1);
		BUF_APPENDSTR(buf, " ");
		for (size_t j = 0; j < binwrap; j++) {
			unsigned char ch = ' ';
			if ((i + j) < n) {
				ch = b[i + j];
				if (!isascii(ch) || !isprint(ch)) {
					ch = '.';
				}
			}
			BIN_FLUSH_IF(1);
			BUF_APPEND(buf, &ch, 1);
		}
		BIN_FLUSH_IF(1);
		BUF_APPENDSTR(buf, "\n");
		(void)fwrite(buf.data, sizeof(buf.data[0]), buf.len, f);
		buf.len = 0;
	}
#undef BIN_FLUSH_IF
}

static void fprint_line(void *data, const char *line)
{
	FILE *const f = data;
	(void)fprintf(f, INDENT "%s\n", line);
}

void slog_extra_stack(FILE *restrict f, void *restrict data)
{
	struct slog_extra_stack *restrict extra = data;
	(void)debug_backtrace_symbols(
		fprint_line, f, extra->pc, (int)extra->len);
}

#if WITH_LIBBACKTRACE

struct bt_context {
	struct backtrace_state *state;
	void **frames;
	size_t i, n;
};

static int backtrace_cb(void *data, const uintptr_t pc)
{
	struct bt_context *restrict ctx = data;
	if (ctx->i < ctx->n) {
		ctx->frames[ctx->i++] = (void *)pc;
		return 0;
	}
	return 1;
}

static struct backtrace_state *bt_state(void)
{
#if SLOG_MT_SAFE
	/* shared across threads (not thread_local) and created with
	 * threaded=1: crashhandler_install()'s probe (signal.c) must warm up
	 * a state every thread can reuse, since backtrace_create_state() is
	 * not async-signal-safe and a crash can land on any thread */
	static _Atomic(struct backtrace_state *) state = NULL;
	struct backtrace_state *cur =
		atomic_load_explicit(&state, memory_order_acquire);
	if (cur != NULL) {
		return cur;
	}
	cur = backtrace_create_state(NULL, 1, NULL, NULL);
	struct backtrace_state *expected = NULL;
	if (!atomic_compare_exchange_strong_explicit(
		    &state, &expected, cur, memory_order_release,
		    memory_order_acquire)) {
		/* another thread published first; backtrace_create_state()
		 * has no free function, so the redundant state is leaked */
		return expected;
	}
	return cur;
#else
	static struct backtrace_state *state = NULL;
	if (state != NULL) {
		return state;
	}
	state = backtrace_create_state(NULL, 0, NULL, NULL);
	return state;
#endif /* SLOG_MT_SAFE */
}
#endif /* WITH_LIBBACKTRACE */

int debug_backtrace(void **restrict frames, int skip, const int len)
{
	assert(frames != NULL && len > 0);
	skip++;
#if WITH_LIBBACKTRACE
	struct bt_context ctx = {
		.state = bt_state(),
		.frames = frames,
		.i = 0,
		.n = (size_t)len,
	};
	if (ctx.state == NULL) {
		return 0;
	}
	(void)backtrace_simple(ctx.state, skip, backtrace_cb, NULL, &ctx);
	return (int)ctx.i;
#elif WITH_LIBUNWIND /* WITH_LIBBACKTRACE */
	int n = unw_backtrace(frames, len);
	int w = 0;
	for (int i = skip; i < n; i++) {
		frames[w++] = frames[i];
	}
	return w;
#elif HAVE_BACKTRACE /* WITH_LIBBACKTRACE */
	int n = backtrace(frames, len);
	int w = 0;
	for (int i = skip; i < n; i++) {
		frames[w++] = frames[i];
	}
	return w;
#else /* WITH_LIBBACKTRACE */
	(void)frames;
	(void)skip;
	(void)len;
	return 0;
#endif /* WITH_LIBBACKTRACE */
}

#if WITH_LIBBACKTRACE

struct print_context {
	struct backtrace_state *state;
	debug_backtrace_symbols_cb cb;
	void *arg;
	uintptr_t pc;
	int index;
};

static void error_cb(void *data, const char *msg, const int errnum)
{
	struct print_context *restrict ctx = data;
	(void)msg;
	(void)errnum;
	char line[256];
	(void)snprintf(
		line, sizeof(line), "#%-3d 0x%jx <unknown>", ctx->index,
		(uintmax_t)ctx->pc);
	ctx->cb(ctx->arg, line);
	ctx->index++;
}

static void syminfo_cb(
	void *data, const uintptr_t pc, const char *symname,
	const uintptr_t symval, const uintptr_t symsize)
{
	struct print_context *restrict ctx = data;
	(void)symsize;
	if (symname == NULL) {
		error_cb(data, NULL, -1);
		return;
	}
	char line[256];
	(void)snprintf(
		line, sizeof(line), "#%-3d 0x%jx %s+0x%jx", ctx->index,
		(uintmax_t)pc, symname, (uintmax_t)(pc - symval));
	ctx->cb(ctx->arg, line);
	ctx->index++;
}

static int pcinfo_cb(
	void *data, const uintptr_t pc, const char *filename, const int lineno,
	const char *function)
{
	struct print_context *restrict ctx = data;
	if (function != NULL && filename != NULL) {
		char line[256];
		(void)snprintf(
			line, sizeof(line), "#%-3d 0x%jx in %s (%s:%d)",
			ctx->index, (uintmax_t)pc, function, filename, lineno);
		ctx->cb(ctx->arg, line);
		ctx->index++;
		return 0;
	}
	/* no inline info: fall back to the symbol table, which emits (and
	 * counts) exactly one line via syminfo_cb or error_cb */
	(void)backtrace_syminfo(ctx->state, pc, syminfo_cb, error_cb, data);
	return 0;
}
#endif /* WITH_LIBBACKTRACE */

static int nosym_lines(
	const debug_backtrace_symbols_cb cb, void *restrict ctx,
	void **restrict frames, const int len)
{
	char line[256];
	for (int i = 0; i < len; i++) {
		(void)snprintf(
			line, sizeof(line), "#%-3d %p", i + 1, frames[i]);
		cb(ctx, line);
	}
	return len;
}

int debug_backtrace_symbols(
	const debug_backtrace_symbols_cb cb, void *ctx, void **restrict frames,
	const int len)
{
	assert(cb != NULL);
	if (len <= 0) {
		/* frames may be NULL here (e.g. a 0-frame debug_backtrace()
		 * capture); backends below assume a non-NULL, non-empty
		 * array, so nothing past this point may run in that case. */
		return 0;
	}
#if WITH_LIBBACKTRACE
	struct print_context pctx = {
		.state = bt_state(),
		.cb = cb,
		.arg = ctx,
		.index = 1,
	};
	if (pctx.state == NULL) {
		return nosym_lines(cb, ctx, frames, len);
	}
	for (int i = 0; i < len; i++) {
		pctx.pc = (uintptr_t)frames[i];
		/* backtrace_pcinfo invokes pcinfo_cb once per inlined function at
		 * this PC (or error_cb once); each emitted line advances
		 * pctx.index itself, so a PC spanning several inline levels numbers
		 * its lines consecutively rather than sharing one number. */
		(void)backtrace_pcinfo(
			pctx.state, pctx.pc, pcinfo_cb, error_cb, &pctx);
	}
	/* return the number of lines emitted (index started at 1), keeping the
	 * "cb calls == return value" contract the other backends uphold even when
	 * inlining made the line count exceed the physical frame count */
	return pctx.index - 1;
#elif WITH_LIBUNWIND /* WITH_LIBBACKTRACE */
	unw_context_t uc;
	if (unw_getcontext(&uc) != 0) {
		return nosym_lines(cb, ctx, frames, len);
	}
	unw_cursor_t cursor;
	if (unw_init_local(&cursor, &uc) != 0) {
		return nosym_lines(cb, ctx, frames, len);
	}
	char line[256];
	for (int i = 0; i < len; i++) {
		void *pc = frames[i];
		(void)unw_set_reg(&cursor, UNW_REG_IP, (unw_word_t)pc);
		unw_word_t offset;
		char sym[256];
		if (unw_get_proc_name(&cursor, sym, sizeof(sym), &offset)) {
			(void)snprintf(
				line, sizeof(line), "#%-3d 0x%jx <unknown>",
				i + 1, (uintmax_t)pc);
		} else {
			(void)snprintf(
				line, sizeof(line), "#%-3d 0x%jx %s+0x%jx",
				i + 1, (uintmax_t)pc, sym, (uintmax_t)offset);
		}
		cb(ctx, line);
	}
	return len;
#elif HAVE_BACKTRACE && HAVE_BACKTRACE_SYMBOLS /* WITH_LIBBACKTRACE */
	char **syms = backtrace_symbols(frames, len);
	if (syms == NULL) {
		return nosym_lines(cb, ctx, frames, len);
	}
	char line[256];
	for (int i = 0; i < len; i++) {
		(void)snprintf(line, sizeof(line), "#%-3d %s", i + 1, syms[i]);
		cb(ctx, line);
	}
	free((void *)syms);
	return len;
#else /* WITH_LIBBACKTRACE */
	return nosym_lines(cb, ctx, frames, len);
#endif /* WITH_LIBBACKTRACE */
}

struct strframes_ctx {
	char *buf;
	size_t maxlen;
	size_t written;
	const char *indent;
};

static void strframes_append(
	struct strframes_ctx *restrict ctx, const char *restrict s,
	const size_t n)
{
	if (ctx->buf != NULL && ctx->written < ctx->maxlen) {
		const size_t avail = ctx->maxlen - ctx->written;
		const size_t copy_n = n < avail ? n : avail;
		memcpy(ctx->buf + ctx->written, s, copy_n);
	}
	ctx->written += n;
}

static void strframes_cb(void *data, const char *line)
{
	struct strframes_ctx *restrict ctx = data;
	strframes_append(ctx, ctx->indent, strlen(ctx->indent));
	strframes_append(ctx, line, strlen(line));
	strframes_append(ctx, "\n", 1);
}

int debug_strframes(
	char *restrict buf, const size_t maxlen, void **restrict frames,
	const int len, const char *restrict indent)
{
	struct strframes_ctx ctx = {
		.buf = buf,
		.maxlen = maxlen,
		.written = 0,
		.indent = indent != NULL ? indent : "",
	};
	(void)debug_backtrace_symbols(strframes_cb, &ctx, frames, len);
	if (maxlen > 0) {
		buf[ctx.written < maxlen ? ctx.written : maxlen - 1] = '\0';
	}
	return (int)ctx.written;
}
