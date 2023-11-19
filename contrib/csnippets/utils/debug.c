#include "debug.h"
#include "arraysize.h"
#include "buffer.h"

#if WITH_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#elif HAVE_BACKTRACE
#include <execinfo.h>
#endif

#include <ctype.h>
#include <stddef.h>
#include <string.h>
#include <inttypes.h>

#define STRLEN(s) (ARRAY_SIZE(s) - 1)

struct vbuffer *
print_txt(struct vbuffer *vbuf, const char *indent, const void *data, size_t n)
{
	const unsigned char *restrict s = data;
	size_t line = 1, wrap = 0;
	for (size_t i = 0; s[i] != '\0' && i < n; i++) {
		if (wrap == 0) {
			vbuf = VBUF_APPENDF(vbuf, "%s%4zu ", indent, line);
		}
		unsigned char ch = s[i];
		if (ch == '\n') {
			/* soft wrap */
			vbuf = VBUF_APPENDCONST(vbuf, "\n");
			line++;
			wrap = 0;
			continue;
		}
		if (wrap >= 70) {
			/* hard wrap */
			vbuf = VBUF_APPENDF(vbuf, " +\n%s     ", indent);
			wrap = 0;
		}
		if (!isprint(ch)) {
			ch = '?';
		}
		vbuf = VBUF_APPEND(vbuf, &ch, 1);
		wrap++;
	}
	if (wrap > 0) {
		vbuf = VBUF_APPENDCONST(vbuf, "\n");
	}
	return vbuf;
}

struct vbuffer *
print_bin(struct vbuffer *vbuf, const char *indent, const void *data, size_t n)
{
	const size_t wrap = 16;
	const unsigned char *restrict b = data;
	for (size_t i = 0; i < n; i += wrap) {
		vbuf = VBUF_APPENDF(vbuf, "%s%p: ", indent, (void *)(b + i));
		for (size_t j = 0; j < wrap; j++) {
			if ((i + j) < n) {
				vbuf = VBUF_APPENDF(
					vbuf, "%02" PRIX8 " ", b[i + j]);
			} else {
				vbuf = VBUF_APPENDCONST(vbuf, "   ");
			}
		}
		vbuf = VBUF_APPENDCONST(vbuf, " ");
		for (size_t j = 0; j < wrap; j++) {
			unsigned char ch = ' ';
			if ((i + j) < n) {
				ch = b[i + j];
				if (!isprint(ch)) {
					ch = '.';
				}
			}
			vbuf = VBUF_APPEND(vbuf, &ch, 1);
		}
		vbuf = VBUF_APPENDCONST(vbuf, "\n");
	}
	return vbuf;
}

void print_stacktrace(struct buffer *buf, const char *indent)
{
#if WITH_LIBUNWIND
	unw_context_t uc;
	unw_getcontext(&uc);
	unw_cursor_t cursor;
	unw_init_local(&cursor, &uc);
	size_t i = 0;
	while (unw_step(&cursor) > 0) {
		unw_word_t pc;
		if (unw_get_reg(&cursor, UNW_REG_IP, &pc) != 0) {
			break;
		}
		i++;
		BUF_APPENDF(*buf, "%s#%zu 0x%jx: ", indent, i, (uintmax_t)pc);
		char *sym = (char *)buf->data + buf->len;
		const size_t cap = buf->cap - buf->len;
		if (cap < 1) {
			break;
		}
		unw_word_t offset;
		if (unw_get_proc_name(&cursor, sym, cap, &offset) != 0) {
			BUF_APPENDF(*buf, "<unknown>\n", sym);
			continue;
		}
		buf->len += strlen(sym);
		BUF_APPENDF(*buf, "+0x%jx\n", (uintmax_t)offset);
	}
#elif HAVE_BACKTRACE
	void *bt[256];
	const int n = backtrace(bt, sizeof(bt));
	char **syms = backtrace_symbols(bt, n);
	if (syms == NULL) {
		for (int i = 1; i < n; i++) {
			BUF_APPENDF(*buf, "%s#%zu %p\n", indent, i, bt[i]);
		}
		return;
	}
	for (int i = 1; i < n; i++) {
		BUF_APPENDF(*buf, "%s#%zu %s\n", indent, i, syms[i]);
	}
	free(syms);
#else
	(void)buf;
	(void)indent;
#endif
}
