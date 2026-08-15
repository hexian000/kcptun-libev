/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "debug.h"

#include "buffer.h"
#include "ctype_ascii.h"
#include "io/stream.h"
#include "strings/string.h"
#include "strings/utf8.h"

#if WITH_LIBBACKTRACE
#include <backtrace.h>
#elif WITH_LIBUNWIND
/* only the local unwinder is used below; without this, libunwind's unw_*
 * names resolve to the remote-capable entry points that live in the
 * arch-specific libunwind-<arch>, not in the libunwind we link */
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#elif HAVE_BACKTRACE
#include <execinfo.h>
#endif /* WITH_LIBBACKTRACE */

/* debug_backtrace_fd() writes each frame itself with write(2) on the
 * libbacktrace/libunwind and raw-address paths; the glibc path delegates to
 * backtrace_symbols_fd() and touches neither write() nor errno. Gate the
 * matching includes and the writer helper on that so no config carries an
 * unused header or function. */
#if WITH_LIBBACKTRACE || WITH_LIBUNWIND ||                                     \
	!(HAVE_BACKTRACE && HAVE_BACKTRACE_SYMBOLS_FD)
#define DEBUG_FD_RAW_WRITE 1
#else
#define DEBUG_FD_RAW_WRITE 0
#endif

#include <assert.h>
#include <limits.h>
#if DEBUG_FD_RAW_WRITE
#include <errno.h>
#endif
/* bt_state() is the only user of stdatomic, and it exists only with
 * libbacktrace, so an MT-safe build without it needs no atomics here. */
#if WITH_LIBBACKTRACE && SLOG_MT_SAFE
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <uchar.h>
#if DEBUG_FD_RAW_WRITE
#include <unistd.h>
#endif
#include <wchar.h>

#define TAB_SPACE "    "
#define TAB_WIDTH (sizeof(TAB_SPACE) - 1)

#define INDENT "  "

#if !WITH_LIBBACKTRACE && !WITH_LIBUNWIND && HAVE_BACKTRACE
/* slots of debug_backtrace()'s local capture window on the execinfo backend: a
 * full DEBUG_STACK_MAXDEPTH capture plus room for the skipped frames; debug.h
 * states this size in debug_backtrace()'s contract */
#define DEBUG_BACKTRACE_WINDOW (DEBUG_STACK_MAXDEPTH + 32)
#endif

/* best-effort write to the log sink: like slog's own printers, an extra
 * renderer has no channel to report its I/O failures through */
static void
put(struct io_stream *restrict s, const void *restrict data, size_t len)
{
	(void)io_stream_write(s, data, &len);
}

/* The text renderer reads its input as UTF-8 whatever the locale, as the rest
 * of the library does. Printability is decided here rather than by iswprint(),
 * whose "C" locale classes reject every non-ASCII codepoint: a control
 * character (C0, DEL, C1), a line or paragraph separator, or a noncharacter
 * would disturb the rendered layout or is not meant for interchange, so it is
 * shown as '?'; every other codepoint is copied through. */
static bool is_printable(const char32_t cp)
{
	if (cp < 0x20 || (cp >= 0x7F && cp <= 0x9F)) {
		return false;
	}
	if (cp == 0x2028 || cp == 0x2029) {
		return false;
	}
	if ((cp >= 0xFDD0 && cp <= 0xFDEF) || (cp & 0xFFFE) == 0xFFFE) {
		return false;
	}
	return true;
}

/* Column width of a printable codepoint. wcwidth() is the only width table
 * available without ICU, and it answers by the current locale: outside a
 * Unicode locale it knows no non-ASCII codepoint and returns -1, which is
 * taken as one column, so wide characters only wrap late rather than being
 * lost. Even a Unicode locale may report -1 for a codepoint it knows; casting
 * that to size_t would corrupt the running column counter used for wrap
 * decisions. */
static size_t display_width(const char32_t cp)
{
#if HAVE_WCWIDTH
	if (cp <= (char32_t)WCHAR_MAX) {
		const int w = wcwidth((wchar_t)cp);
		return (w < 0) ? 1 : (size_t)w;
	}
#else
	(void)cp;
#endif /* HAVE_WCWIDTH */
	return 1;
}

void slog_extra_txt(struct io_stream *restrict s, void *restrict data)
{
	const struct slog_extra_txt *extra = data;
	size_t n = extra->len;
	const size_t hardwrap = extra->hardwrap < 4 ? 80 : extra->hardwrap;
	const char *restrict text = extra->data;
	struct {
		BUFFER_HDR;
		unsigned char data[256];
	} buf;
	BUF_INIT(buf, 0);
	bool newline = true;
	bool cr = false;
	size_t line = 0, column = 0;
	while (n > 0) {
		char32_t cp;
		const int clen = utf8_decode(&cp, text, n);
		if (clen <= 0 || cp == 0) {
			break;
		}
		const char *unit = text;
		size_t unitlen = (size_t)clen;
		text += clen, n -= (size_t)clen;
		if (cr && cp == U'\n') {
			/* skip CRLF */
			cr = false;
			continue;
		}
		cr = (cp == U'\r');
		if (newline) {
			BUF_APPENDF(buf, INDENT "%4zu ", ++line);
			newline = false;
		}
		size_t width;
		switch (cp) {
		case U'\r':
		case U'\n':
			/* soft wrap */
			BUF_APPENDSTR(buf, "\n");
			put(s, buf.data, buf.len);
			buf.len = 0;
			column = 0;
			newline = true;
			continue;
		case U'\t':
			width = TAB_WIDTH - column % TAB_WIDTH;
			break;
		default:
			if (is_printable(cp)) {
				width = display_width(cp);
			} else {
				unit = "?", unitlen = 1;
				width = 1;
			}
		}
		if (column + width > hardwrap) {
			/* hard wrap */
			BUF_APPENDSTR(buf, " +\n" INDENT "     ");
			put(s, buf.data, buf.len);
			buf.len = 0;
			column = 0;
			if (cp == U'\t') {
				/* recalculate tab width */
				width = TAB_WIDTH;
			}
		}
		if (cp == U'\t') {
			BUF_APPEND(buf, TAB_SPACE, width);
		} else {
			/* a well-formed sequence is copied through verbatim */
			BUF_APPEND(buf, unit, unitlen);
		}
		column += width;
		if (buf.cap - buf.len < 16) {
			put(s, buf.data, buf.len);
			buf.len = 0;
		}
	}
	if (!newline) {
		BUF_APPENDSTR(buf, "\n");
	}
	if (buf.len > 0) {
		put(s, buf.data, buf.len);
		buf.len = 0;
	}
	if (n > 0) {
		/* omit bytes from the null terminator or ill-formed sequence on */
		BUF_APPENDF(buf, INDENT " ... (omitting %zu bytes)\n", n);
		put(s, buf.data, buf.len);
	}
}

void slog_extra_bin(struct io_stream *restrict s, void *restrict data)
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
	 * silently truncate a row. Writes concatenate, so splitting a row across
	 * them yields byte-identical output. */
#define BIN_FLUSH_IF(need)                                                     \
	do {                                                                   \
		if (buf.cap - buf.len < (size_t)(need)) {                      \
			put(s, buf.data, buf.len);                             \
			buf.len = 0;                                           \
		}                                                              \
	} while (0)
	for (size_t i = 0; i < n;) {
		/* i < n, so remaining never underflows; the row spans
		 * min(binwrap, remaining) real bytes, and every j < rowlen keeps
		 * i + j within [i, n), so no index can wrap past SIZE_MAX */
		const size_t remaining = n - i;
		const size_t rowlen = remaining < binwrap ? remaining : binwrap;
		/* INDENT + "0x" + up to two hex digits per pointer byte + ": " */
		BIN_FLUSH_IF(sizeof(INDENT) + 2 + 2 * sizeof(void *) + 2);
		BUF_APPENDF(buf, INDENT "%p: ", (void *)(b + i));
		for (size_t j = 0; j < binwrap; j++) {
			/* "%02hhX " is 3 chars, +1 for buf_appendf's in-place NUL */
			BIN_FLUSH_IF(4);
			if (j < rowlen) {
				BUF_APPENDF(buf, "%02hhX ", b[i + j]);
			} else {
				BUF_APPENDSTR(buf, "   ");
			}
		}
		BIN_FLUSH_IF(1);
		BUF_APPENDSTR(buf, " ");
		for (size_t j = 0; j < binwrap; j++) {
			unsigned char ch = ' ';
			if (j < rowlen) {
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
		put(s, buf.data, buf.len);
		buf.len = 0;
		/* advance by the proven byte count (>= 1), so i rises to exactly n
		 * and the loop always terminates */
		i += rowlen;
	}
#undef BIN_FLUSH_IF
}

static void put_line(void *data, const char *line)
{
	struct io_stream *restrict s = data;
	put(s, INDENT, sizeof(INDENT) - 1);
	put(s, line, strlen(line));
	put(s, "\n", 1);
}

void slog_extra_stack(struct io_stream *restrict s, void *restrict data)
{
	struct slog_extra_stack *restrict extra = data;
	(void)debug_backtrace_symbols(put_line, s, extra->pc, (int)extra->len);
}

#if WITH_LIBBACKTRACE

struct bt_context {
	struct backtrace_state *state;
	void **frames;
	size_t i, n;
};

#if defined(DEBUG_TEST) && SLOG_MT_SAFE
static atomic_int g_backtrace_create_state_calls;
#endif

static int backtrace_cb(void *data, const uintptr_t pc)
{
	/* backtrace_simple() promises nothing but "pc is the program counter",
	 * so the end of the stack has to be recognized from the value itself:
	 * _Unwind_Backtrace() runs its trace function once more past the
	 * outermost frame, with a return address of 0, and libbacktrace's
	 * simple_unwind() forwards that after its "the ip is not before the
	 * instruction" fixup (`if (!ip_before_insn) --pc;`) has wrapped it to
	 * UINTPTR_MAX. No instruction can live at that address, so it is the
	 * unwinder's terminator rather than a frame; returning non-zero also
	 * stops backtrace_simple() there.
	 *
	 * That fixup is conditional, so UINTPTR_MAX is not the only value the
	 * last call can carry: libgcc sets ip_before_insn from
	 * _Unwind_IsSignalFrame(), skipping the decrement for a signal frame,
	 * whose pc is the interrupted instruction rather than a return address.
	 * The trace can therefore end with pc == 0, but only when that
	 * interrupted instruction sits at address 0 -- control was transferred
	 * through a null function pointer -- which is the faulting address the
	 * crash handler exists to report rather than a terminator. Such a 0 is
	 * stored like any other frame; see debug_backtrace() in debug.h. */
	if (pc == UINTPTR_MAX) {
		return 1;
	}
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
	static_assert(
		ATOMIC_POINTER_LOCK_FREE == 2,
		"the cached state is read by debug_backtrace() from a crash "
		"handler, where ISO C11 7.14.1.1p5 admits an atomic access "
		"only if it is lock-free");
	struct backtrace_state *cur =
		atomic_load_explicit(&state, memory_order_acquire);
	if (cur != NULL) {
		return cur;
	}
#if defined(DEBUG_TEST)
	(void)atomic_fetch_add_explicit(
		&g_backtrace_create_state_calls, 1, memory_order_relaxed);
#endif
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

#if defined(DEBUG_TEST) && WITH_LIBBACKTRACE && SLOG_MT_SAFE
/* Test instrumentation, compiled only into debug_test's own build of this file.
 * Not static so debug_test.c can read the counter from its separate translation
 * unit; kept out of debug.h so test hooks stay off the public header, and
 * debug_test.c declares it by hand. */
int debug_test_backtrace_create_state_calls(void)
{
	return atomic_load_explicit(
		&g_backtrace_create_state_calls, memory_order_relaxed);
}
#endif

int debug_backtrace(void **restrict frames, int skip, const int len)
{
	assert(frames != NULL && len > 0);
	/* skip counts caller frames to drop; clamp a negative request and add
	 * this function's own frame without signed-overflowing the count */
	if (skip < 0) {
		skip = 0;
	}
	if (skip < INT_MAX) {
		skip++;
	}
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
	/* backtrace_simple() adds one to skip internally (skip + 1, to drop its
	 * own frame), so a skip of INT_MAX overflows that signed count and, once
	 * negative, skips nothing at all. Cap the argument at INT_MAX - 1: an
	 * unreachably deep skip still drops every captured frame. */
	(void)backtrace_simple(
		ctx.state, skip < INT_MAX ? skip : INT_MAX - 1, backtrace_cb,
		NULL, &ctx);
	return (int)ctx.i;
#elif WITH_LIBUNWIND /* WITH_LIBBACKTRACE */
	unw_context_t uc;
	if (unw_getcontext(&uc) != 0) {
		return 0;
	}
	unw_cursor_t cursor;
	if (unw_init_local(&cursor, &uc) != 0) {
		return 0;
	}
	/* depth 0 is debug_backtrace's own frame (matching unw_backtrace's
	 * frame 0), so the caller's incremented skip carries over unchanged */
	int w = 0;
	int depth = 0;
	do {
		if (depth >= skip) {
			unw_word_t ip;
			if (unw_get_reg(&cursor, UNW_REG_IP, &ip) != 0) {
				break;
			}
			frames[w++] = (void *)(uintptr_t)ip;
			if (w >= len) {
				break;
			}
		}
		depth++;
	} while (unw_step(&cursor) > 0);
	return w;
#elif HAVE_BACKTRACE /* WITH_LIBBACKTRACE */
	/* backtrace() takes no skip: it fills its buffer from this very frame
	 * outward, so the skipped frames need slots of their own on top of the
	 * len frames kept. Capture into whichever is larger, a local window or
	 * the caller's array, then move the kept range to the front. The window
	 * is fixed-size (this runs from crash handlers: no VLA, no malloc), so a
	 * capture needing more than that many slots loses its outermost frames;
	 * see debug_backtrace() in debug.h. */
	void *window[DEBUG_BACKTRACE_WINDOW];
	void **buf = window;
	int cap = DEBUG_BACKTRACE_WINDOW;
	if (len > cap) {
		buf = frames;
		cap = len;
	}
	/* cap >= len, so cap - len cannot overflow and bounds skip + len */
	const int n = backtrace(buf, skip < cap - len ? skip + len : cap);
	int w = 0;
	/* w never passes i, so the forward copy is safe when buf is frames */
	for (int i = skip; i < n; i++) {
		frames[w++] = buf[i];
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
	(void)u8snprintf(
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
	(void)u8snprintf(
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
		(void)u8snprintf(
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
		(void)u8snprintf(
			line, sizeof(line), "#%-3d %p", i + 1, frames[i]);
		cb(ctx, line);
	}
	return len;
}

static void
debug_backtrace_warmup_cb(void *restrict ctx, const char *restrict line)
{
	(void)ctx;
	(void)line;
}

bool debug_backtrace_init(void)
{
	void *frames[DEBUG_STACK_MAXDEPTH];
	const int n = debug_backtrace(frames, 0, DEBUG_STACK_MAXDEPTH);
	if (n <= 0) {
		return false;
	}
	/* warm the symbolization path too (symbol table / DWARF parse and the
	 * backend's caches): debug_backtrace() alone only warms the unwinder, so
	 * a first debug_backtrace_fd() would still allocate/parse otherwise */
	(void)debug_backtrace_symbols(
		debug_backtrace_warmup_cb, NULL, frames, n);
	return true;
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
			(void)u8snprintf(
				line, sizeof(line), "#%-3d 0x%jx <unknown>",
				i + 1, (uintmax_t)pc);
		} else {
			(void)u8snprintf(
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
		(void)u8snprintf(
			line, sizeof(line), "#%-3d %s", i + 1, syms[i]);
		cb(ctx, line);
	}
	free((void *)syms);
	return len;
#else /* WITH_LIBBACKTRACE */
	return nosym_lines(cb, ctx, frames, len);
#endif /* WITH_LIBBACKTRACE */
}

/* --- async-signal-safe fd backtrace --------------------------------------- */

/* debug_fd_write() serves the libbacktrace/libunwind and raw-address paths; the
 * glibc path writes through backtrace_symbols_fd() and does not need it */
#if DEBUG_FD_RAW_WRITE
/* write the whole buffer, retrying short writes and EINTR; best-effort during a
 * crash (a stack tracer has no channel to report its own I/O failure through) */
static void debug_fd_write(const int fd, const void *restrict data, size_t n)
{
	const unsigned char *restrict p = data;
	while (n > 0) {
		const ssize_t nw = write(fd, p, n);
		if (nw < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		if (nw == 0) {
			break;
		}
		p += (size_t)nw;
		n -= (size_t)nw;
	}
}
#endif /* DEBUG_FD_RAW_WRITE */

#if WITH_LIBBACKTRACE || WITH_LIBUNWIND
/* line sink for debug_backtrace_symbols(): route each formatted frame to the fd
 * captured in ctx. Reuses the libbacktrace/libunwind symbolizers, which draw
 * from their own mmap arenas (not the C heap), so this stays deadlock-free from
 * a signal handler once debug_backtrace_init() has warmed them. */
static void debug_fd_line_cb(void *restrict ctx, const char *restrict line)
{
	const int fd = *(const int *)ctx;
	debug_fd_write(fd, line, strlen(line));
	debug_fd_write(fd, "\n", 1);
}
#elif !(HAVE_BACKTRACE && HAVE_BACKTRACE_SYMBOLS_FD)
/* raw-address fallback: this build has no async-signal-safe symbolizer */
static void debug_fd_nosym(const int fd, void **restrict frames, const int len)
{
	for (int i = 0; i < len; i++) {
		/* '#', the widest int index, ' ', "0x" and two hex digits per
		 * pointer byte, '\n', NUL */
		char line[1 + 11 + 1 + 2 + 2 * sizeof(void *) + 1 + 1];
		const int r = u8snprintf(
			line, sizeof(line), "#%-3d %p\n", i + 1, frames[i]);
		if (r <= 0) {
			continue;
		}
		size_t w = (size_t)r;
		if (w >= sizeof(line)) {
			/* unreachable with the sizing above; should it ever
			 * truncate, send what was kept but never the NUL, and
			 * still end the line so it cannot merge with the next */
			w = sizeof(line) - 1;
			line[w - 1] = '\n';
		}
		debug_fd_write(fd, line, w);
	}
}
#endif

void debug_backtrace_fd(const int fd, void **restrict frames, const int len)
{
	if (fd < 0 || len <= 0) {
		return;
	}
#if WITH_LIBBACKTRACE || WITH_LIBUNWIND
	int fdarg = fd;
	(void)debug_backtrace_symbols(debug_fd_line_cb, &fdarg, frames, len);
#elif HAVE_BACKTRACE && HAVE_BACKTRACE_SYMBOLS_FD
	/* backtrace_symbols_fd() writes straight to the descriptor and, unlike
	 * backtrace_symbols(), is documented not to call malloc() */
	backtrace_symbols_fd(frames, len, fd);
#else
	debug_fd_nosym(fd, frames, len);
#endif
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
	if (buf != NULL && maxlen > 0) {
		buf[ctx.written < maxlen ? ctx.written : maxlen - 1] = '\0';
	}
	return (int)ctx.written;
}
