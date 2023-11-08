#include "debug.h"
#include "arraysize.h"
#include "buffer.h"

#include <ctype.h>
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
