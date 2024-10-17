/* csnippets (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "debug.h"
#include "utils/buffer.h"

#if WITH_LIBBACKTRACE
#include <backtrace.h>
#elif WITH_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#elif HAVE_BACKTRACE_SYMBOLS
#include <execinfo.h>
#endif

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <wchar.h>
#include <wctype.h>

#define HARD_WRAP 110
#define TAB_SPACE "    "
#define TAB_WIDTH (sizeof(TAB_SPACE) - 1)

#define INDENT "  "

void slog_extra_txt(void *data, FILE *f)
{
	const struct slog_extra_txt *restrict extradata = data;
	size_t n = extradata->len;
	const char *s = extradata->data;
	struct {
		BUFFER_HDR;
		unsigned char data[256];
	} buf;
	BUF_INIT(buf, 0);
	bool lineno = true;
	size_t line = 0, column = 0;
	while (*s != '\0') {
		if (lineno) {
			BUF_APPENDF(buf, INDENT "%4zu ", ++line);
			lineno = false;
		}
		wchar_t wc;
		int clen = mbtowc(&wc, s, n);
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

void slog_extra_bin(void *data, FILE *f)
{
	const struct slog_extra_bin *restrict extradata = data;
	size_t n = extradata->len;
	struct {
		BUFFER_HDR;
		unsigned char data[256];
	} buf;
	BUF_INIT(buf, 0);
	const size_t wrap = 16;
	const unsigned char *restrict b = extradata->data;
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

struct bt_error {
	const char *msg;
	int num;
};

struct bt_pcinfo {
	struct bt_error err;
	const char *filename;
	int lineno;
	const char *function;
};

struct bt_syminfo {
	struct bt_error err;
	const char *symname;
	uintptr_t symval;
	uintptr_t symsize;
};

struct bt_context {
	struct backtrace_state *state;
	struct buffer *buf;
	int index;
};

static void error_cb(void *data, const char *msg, const int errnum)
{
	struct bt_error *restrict err = data;
	err->msg = msg;
	err->num = errnum;
}

static void syminfo_cb(
	void *data, const uintptr_t pc, const char *symname,
	const uintptr_t symval, const uintptr_t symsize)
{
	(void)pc;
	struct bt_syminfo *restrict syminfo = data;
	syminfo->symname = symname;
	syminfo->symval = symval;
	syminfo->symsize = symsize;
}

static int pcinfo_cb(
	void *data, const uintptr_t pc, const char *filename, const int lineno,
	const char *function)
{
	(void)pc;
	struct bt_pcinfo *restrict pcinfo = data;
	pcinfo->filename = filename;
	pcinfo->lineno = lineno;
	pcinfo->function = function;
	return 0;
}

static int backtrace_cb(void *data, const uintptr_t pc)
{
	struct bt_context *restrict ctx = data;
	struct bt_pcinfo pcinfo = { 0 };
	backtrace_pcinfo(ctx->state, pc, pcinfo_cb, error_cb, &pcinfo);
	struct bt_syminfo syminfo = { 0 };
	backtrace_syminfo(ctx->state, pc, syminfo_cb, error_cb, &syminfo);

	if (syminfo.symname != NULL && pcinfo.filename != NULL) {
		BUF_APPENDF(
			*ctx->buf,
			INDENT "#%-3d 0x%jx: %s+0x%jx in %s (%s:%d)\n",
			ctx->index, (uintmax_t)pc, syminfo.symname,
			(uintmax_t)(pc - syminfo.symval),
			pcinfo.function ? pcinfo.function : "???",
			slog_filename(pcinfo.filename), pcinfo.lineno);
	} else if (syminfo.symname != NULL) {
		BUF_APPENDF(
			*ctx->buf, INDENT "#%-3d 0x%jx: %s+0x%jx\n", ctx->index,
			(uintmax_t)pc, syminfo.symname,
			(uintmax_t)(pc - syminfo.symval));
	} else if (syminfo.err.msg != NULL) {
		BUF_APPENDF(
			*ctx->buf, INDENT "#%-3d 0x%jx: (%d) %s\n", ctx->index,
			(uintmax_t)pc, syminfo.err.num, syminfo.err.msg);
	} else if (pcinfo.err.msg != NULL) {
		BUF_APPENDF(
			*ctx->buf, INDENT "#%-3d 0x%jx: (%d) %s\n", ctx->index,
			(uintmax_t)pc, pcinfo.err.num, pcinfo.err.msg);
	} else {
		BUF_APPENDF(
			*ctx->buf, INDENT "#%-3d 0x%jx: <unknown>\n",
			ctx->index, (uintmax_t)pc);
	}
	ctx->index++;
	return 0;
}

static void print_error_cb(void *data, const char *msg, int errnum)
{
	struct bt_context *restrict ctx = data;
	BUF_APPENDF(
		*ctx->buf, INDENT "backtrace error: (%d) %s\n", errnum, msg);
}
#endif

void slog_traceback(struct buffer *buf, int skip)
{
#if WITH_LIBBACKTRACE
	skip++;
#if SLOG_MT_SAFE
	static _Thread_local struct backtrace_state *state = NULL;
#else
	static struct backtrace_state *state = NULL;
#endif
	if (state == NULL) {
		state = backtrace_create_state(NULL, 0, print_error_cb, NULL);
		if (state == NULL) {
			return;
		}
	}
	struct bt_context ctx = {
		.state = state,
		.buf = buf,
		.index = 1,
	};
	backtrace_simple(state, skip, backtrace_cb, print_error_cb, &ctx);
#elif WITH_LIBUNWIND
	unw_context_t uc;
	if (unw_getcontext(&uc) != 0) {
		return;
	}
	unw_cursor_t cursor;
	if (unw_init_local(&cursor, &uc) != 0) {
		return;
	}
	int index = 1;
	for (int i = 0; unw_step(&cursor) > 0; i++) {
		if (i < skip) {
			continue;
		}
		unw_word_t pc;
		if (unw_get_reg(&cursor, UNW_REG_IP, &pc)) {
			break;
		}
		char sym[256];
		unw_word_t offset;
		if (unw_get_proc_name(&cursor, sym, sizeof(sym), &offset)) {
			BUF_APPENDF(
				*buf, INDENT "#%-3d 0x%jx: <unknown>\n", index,
				(uintmax_t)pc);
		} else {
			BUF_APPENDF(
				*buf, INDENT "#%-3d 0x%jx: %s+0x%jx\n", index,
				(uintmax_t)pc, sym, (uintmax_t)offset);
		}
		index++;
	}
#elif HAVE_BACKTRACE_SYMBOLS
	skip += 2;
	void *bt[256];
	const int n = backtrace(bt, sizeof(bt));
	char **syms = backtrace_symbols(bt, n);
	if (syms == NULL) {
		int index = 1;
		for (int i = skip; i < n; i++) {
			BUF_APPENDF(*buf, INDENT "#%-3d %p\n", index, bt[i]);
			index++;
		}
		return;
	}
	int index = 1;
	for (int i = skip; i < n; i++) {
		BUF_APPENDF(*buf, INDENT "#%-3d %s\n", index, syms[i]);
		index++;
	}
	free(syms);
#else
	(void)buf;
	(void)skip;
#endif
}

void slog_extra_buf(void *data, FILE *f)
{
	const struct buffer *restrict buf = data;
	(void)fwrite(buf->data, sizeof(buf->data[0]), buf->len, f);
}
