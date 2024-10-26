/* csnippets (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "debug.h"
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
#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include <wctype.h>

#define HARD_WRAP 110
#define TAB_SPACE "    "
#define TAB_WIDTH (sizeof(TAB_SPACE) - 1)

#define INDENT "  "

void slog_extra_txt(FILE *f, void *data)
{
	const struct slog_extra_txt *restrict extra = data;
	size_t n = extra->len;
	const char *s = extra->data;
	struct {
		BUFFER_HDR;
		unsigned char data[256];
	} buf;
	BUF_INIT(buf, 0);
	mbstate_t state = { 0 };
	bool lineno = true;
	size_t line = 0, column = 0;
	while (n > 0) {
		if (lineno) {
			BUF_APPENDF(buf, INDENT "%4zu ", ++line);
			lineno = false;
		}
		wchar_t wc;
		const int clen = mbrtowc(&wc, s, n, &state);
		if (clen == 0) {
			break;
		}
		s += clen, n -= clen;
		int width;
		switch (wc) {
		case L'\n':
			/* soft wrap */
			BUF_APPENDSTR(buf, "\n");
			(void)fwrite(buf.data, sizeof(buf.data[0]), buf.len, f);
			buf.len = 0;
			column = 0;
			lineno = true;
			continue;
		case L'\t':
			width = TAB_WIDTH - column % TAB_WIDTH;
			break;
		default:
			if (!iswprint(wc)) {
				wc = L'?';
			}
#if HAVE_WCWIDTH
			width = wcwidth(wc);
#else
			width = 1;
#endif
		}
		if (column + width > HARD_WRAP) {
			/* hard wrap */
			BUF_APPENDSTR(buf, " +\n" INDENT "     ");
			(void)fwrite(buf.data, sizeof(buf.data[0]), buf.len, f);
			buf.len = 0;
			column = 0;
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
	(void)fwrite(buf.data, sizeof(buf.data[0]), buf.len, f);
}

void slog_extra_bin(FILE *f, void *data)
{
	const struct slog_extra_bin *restrict extra = data;
	size_t n = extra->len;
	struct {
		BUFFER_HDR;
		unsigned char data[256];
	} buf;
	BUF_INIT(buf, 0);
	const size_t wrap = 16;
	const unsigned char *restrict b = extra->data;
	for (size_t i = 0; i < n; i += wrap) {
		BUF_APPENDF(buf, INDENT "%p: ", (void *)(b + i));
		for (size_t j = 0; j < wrap; j++) {
			if ((i + j) < n) {
				BUF_APPENDF(buf, "%02" PRIX8 " ", b[i + j]);
			} else {
				BUF_APPENDSTR(buf, "   ");
			}
		}
		BUF_APPENDSTR(buf, " ");
		for (size_t j = 0; j < wrap; j++) {
			unsigned char ch = ' ';
			if ((i + j) < n) {
				ch = b[i + j];
				if (((ch) & ~0x7f) || !isprint(ch)) {
					ch = '.';
				}
			}
			buf.data[buf.len++] = ch;
		}
		BUF_APPENDSTR(buf, "\n");
		(void)fwrite(buf.data, sizeof(buf.data[0]), buf.len, f);
		buf.len = 0;
	}
}

#if WITH_LIBBACKTRACE

struct print_context {
	struct slog_extra_stack *data;
	struct backtrace_state *state;
	FILE *f;
	uintptr_t pc;
	int index;
};

static void error_cb(void *data, const char *msg, const int errnum)
{
	struct print_context *restrict ctx = data;
	(void)msg;
	(void)errnum;
	(void)fprintf(
		ctx->f, INDENT "#%-3d 0x%jx <unknown>\n", ctx->index,
		(uintmax_t)ctx->pc);
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
	(void)fprintf(
		ctx->f, INDENT "#%-3d 0x%jx %s+0x%jx\n", ctx->index,
		(uintmax_t)pc, symname, (uintmax_t)(pc - symval));
}

static int pcinfo_cb(
	void *data, const uintptr_t pc, const char *filename, const int lineno,
	const char *function)
{
	struct print_context *restrict ctx = data;
	if (function != NULL && filename != NULL) {
		(void)fprintf(
			ctx->f, INDENT "#%-3d 0x%jx in %s (%s:%d)\n",
			ctx->index, (uintmax_t)pc, function, filename, lineno);
		return 0;
	}
	backtrace_syminfo(ctx->state, pc, syminfo_cb, error_cb, data);
	return 0;
}

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
	static _Thread_local struct backtrace_state *state = NULL;
#else
	static struct backtrace_state *state = NULL;
#endif

	if (state != NULL) {
		return state;
	}
	state = backtrace_create_state(NULL, 0, NULL, NULL);
	return state;
}
#endif

int debug_backtrace(void **frames, int skip, const int len)
{
	assert(frames != NULL && len > 0);
	skip++;
#if WITH_LIBBACKTRACE
	struct bt_context ctx = {
		.state = bt_state(),
		.frames = frames,
		.i = 0,
		.n = len,
	};
	if (ctx.state == NULL) {
		return 0;
	}
	(void)backtrace_simple(ctx.state, skip, backtrace_cb, NULL, &ctx);
	return ctx.i;
#elif WITH_LIBUNWIND
	int n = unw_backtrace(frames, len);
	int w = 0;
	for (int i = skip; i < n; i++) {
		frames[w++] = frames[i];
	}
	return w;
#elif HAVE_BACKTRACE
	int n = backtrace(frames, len);
	int w = 0;
	for (int i = skip; i < n; i++) {
		frames[w++] = frames[i];
	}
	return w;
#else
	(void)frames;
	(void)skip;
	(void)len;
	return 0;
#endif
}

static void
slog_extra_stack_default(FILE *f, struct slog_extra_stack *restrict extra)
{
	int index = 1;
	for (size_t i = 0; i < extra->len; i++) {
		(void)fprintf(f, INDENT "#%-3d %p\n", index, extra->pc[i]);
		index++;
	}
}

void slog_extra_stack(FILE *f, void *data)
{
	struct slog_extra_stack *restrict extra = data;
#if WITH_LIBBACKTRACE
	struct print_context ctx = {
		.data = extra,
		.state = bt_state(),
		.f = f,
		.index = 1,
	};
	if (ctx.state == NULL) {
		slog_extra_stack_default(f, extra);
		return;
	}
	for (size_t i = 0; i < extra->len; i++) {
		ctx.pc = (uintptr_t)extra->pc[i];
		(void)backtrace_pcinfo(
			ctx.state, ctx.pc, pcinfo_cb, error_cb, &ctx);
		ctx.index++;
	}
#elif WITH_LIBUNWIND
	unw_context_t uc;
	if (unw_getcontext(&uc) != 0) {
		slog_extra_stack_default(f, extra);
		return;
	}
	unw_cursor_t cursor;
	if (unw_init_local(&cursor, &uc) != 0) {
		slog_extra_stack_default(f, extra);
		return;
	}
	int index = 1;
	for (size_t i = 0; i < extra->len; i++) {
		void *pc = extra->pc[i];
		unw_set_reg(&cursor, UNW_REG_IP, (unw_word_t)pc);
		unw_word_t offset;
		char sym[256];
		if (unw_get_proc_name(&cursor, sym, sizeof(sym), &offset)) {
			(void)fprintf(
				f, INDENT "#%-3d 0x%jx <unknown>\n", index,
				(uintmax_t)pc);
		} else {
			(void)fprintf(
				f, INDENT "#%-3d 0x%jx %s+0x%jx\n", index,
				(uintmax_t)pc, sym, (uintmax_t)offset);
		}
		index++;
	}
#elif HAVE_BACKTRACE && HAVE_BACKTRACE_SYMBOLS
	char **syms = backtrace_symbols(extra->pc, extra->len);
	if (syms == NULL) {
		slog_extra_stack_default(f, extra);
		return;
	}
	int index = 1;
	for (size_t i = 0; i < extra->len; i++) {
		(void)fprintf(f, INDENT "#%-3d %s\n", index++, syms[i]);
	}
	free(syms);
#else
	slog_extra_stack_default(f, extra);
#endif
}
