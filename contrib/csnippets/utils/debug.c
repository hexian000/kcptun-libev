/* csnippets (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "debug.h"

#if WITH_LIBBACKTRACE
#include <backtrace.h>
#elif WITH_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#elif HAVE_BACKTRACE_SYMBOLS
#include <execinfo.h>
#endif

#include <ctype.h>
#include <stddef.h>
#include <inttypes.h>

void print_txt(FILE *f, const char *indent, const void *data, size_t n)
{
	const unsigned char *restrict s = data;
	size_t line = 1, wrap = 0;
	for (size_t i = 0; s[i] != '\0' && i < n; i++) {
		if (wrap == 0) {
			fprintf(f, "%s%4zu ", indent, line);
		}
		unsigned char ch = s[i];
		if (ch == '\n') {
			/* soft wrap */
			fputc('\n', f);
			line++;
			wrap = 0;
			continue;
		}
		if (wrap >= 70) {
			/* hard wrap */
			fprintf(f, " +\n%s     ", indent);
			wrap = 0;
		}
		if (!(isprint(ch) || isspace(ch))) {
			ch = '?';
		}
		fputc(ch, f);
		wrap++;
	}
	if (wrap > 0) {
		fputc('\n', f);
	}
	fflush(f);
}

void print_bin(FILE *f, const char *indent, const void *data, size_t n)
{
	const size_t wrap = 16;
	const unsigned char *restrict b = data;
	for (size_t i = 0; i < n; i += wrap) {
		fprintf(f, "%s%p: ", indent, (void *)(b + i));
		for (size_t j = 0; j < wrap; j++) {
			if ((i + j) < n) {
				fprintf(f, "%02" PRIX8 " ", b[i + j]);
			} else {
				fputs("   ", f);
			}
		}
		fputc(' ', f);
		for (size_t j = 0; j < wrap; j++) {
			unsigned char ch = ' ';
			if ((i + j) < n) {
				ch = b[i + j];
				if (!isprint(ch)) {
					ch = '.';
				}
			}
			fputc(ch, f);
		}
		fputc('\n', f);
	}
	fflush(f);
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
	FILE *f;
	const char *indent;
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
		fprintf(ctx->f, "%s#%-3d 0x%jx: %s+0x%jx in %s (%s:%d)\n",
			ctx->indent, ctx->index, (uintmax_t)pc, syminfo.symname,
			(uintmax_t)(pc - syminfo.symval),
			pcinfo.function ? pcinfo.function : "???",
			pcinfo.filename, pcinfo.lineno);
	} else if (syminfo.symname != NULL) {
		fprintf(ctx->f, "%s#%-3d 0x%jx: %s+0x%jx\n", ctx->indent,
			ctx->index, (uintmax_t)pc, syminfo.symname,
			(uintmax_t)(pc - syminfo.symval));
	} else if (syminfo.err.msg != NULL) {
		fprintf(ctx->f, "%s#%-3d 0x%jx: (%d) %s\n", ctx->indent,
			ctx->index, (uintmax_t)pc, syminfo.err.num,
			syminfo.err.msg);
	} else if (pcinfo.err.msg != NULL) {
		fprintf(ctx->f, "%s#%-3d 0x%jx: (%d) %s\n", ctx->indent,
			ctx->index, (uintmax_t)pc, pcinfo.err.num,
			pcinfo.err.msg);
	} else {
		fprintf(ctx->f, "%s#%-3d 0x%jx: <unknown>\n", ctx->indent,
			ctx->index, (uintmax_t)pc);
	}
	fflush(ctx->f);
	ctx->index++;
	return 0;
}

static void print_error_cb(void *data, const char *msg, int errnum)
{
	struct bt_context *restrict ctx = data;
	fprintf(ctx->f, "%sbacktrace error: (%d) %s\n", ctx->indent, errnum,
		msg);
	fflush(ctx->f);
}
#endif

void print_stacktrace(FILE *f, const char *indent, int skip)
{
	skip++;
#if WITH_LIBBACKTRACE
	static _Thread_local struct backtrace_state *state = NULL;
	struct bt_context ctx = {
		.state = state,
		.f = f,
		.indent = indent,
		.index = 1,
	};
	if (ctx.state == NULL) {
		ctx.state =
			backtrace_create_state(NULL, 0, print_error_cb, &ctx);
		if (ctx.state == NULL) {
			return;
		}
		state = ctx.state;
	}
	backtrace_simple(ctx.state, skip, backtrace_cb, print_error_cb, &ctx);
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
			fprintf(f, "%s#%-3d 0x%jx: <unknown>\n", indent, index,
				(uintmax_t)pc);
		} else {
			fprintf(f, "%s#%-3d 0x%jx: %s+0x%jx\n", indent, index,
				(uintmax_t)pc, sym, (uintmax_t)offset);
		}
		index++;
	}
#elif HAVE_BACKTRACE_SYMBOLS
	void *bt[256];
	const int n = backtrace(bt, sizeof(bt));
	char **syms = backtrace_symbols(bt, n);
	if (syms == NULL) {
		int index = 1;
		for (int i = skip; i < n; i++) {
			fprintf(f, "%s#%-3d %p\n", indent, index, bt[i]);
			index++;
		}
		return;
	}
	int index = 1;
	for (int i = skip; i < n; i++) {
		fprintf(f, "%s#%-3d %s\n", indent, index, syms[i]);
		index++;
	}
	free(syms);
#else
	(void)indent;
	(void)skip;
#endif
	fflush(f);
}
