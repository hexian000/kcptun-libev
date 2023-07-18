/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "slog.h"

#include <ctype.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>

int slog_level = LOG_LEVEL_VERBOSE;
FILE *slog_file = NULL;

#define STRLEN(s) (sizeof(s) - 1)

void slog_write_txt(const void *data, const size_t n)
{
	FILE *log_fp = slog_file ? slog_file : stdout;
	const char *restrict s = data;
	size_t line = 1, wrap = 0;
	for (size_t i = 0; s[i] != '\0' && i < n; i++) {
		if (wrap == 0) {
			fprintf(log_fp, "%4zu ", line);
		}
		const unsigned char ch = s[i];
		if (ch == '\n') {
			/* soft wrap */
			fputc('\n', log_fp);
			line++;
			wrap = 0;
			continue;
		}
		if (wrap >= (80 - STRLEN("  0000 ") - STRLEN(" +"))) {
			/* hard wrap */
			fputs(" +\n     ", log_fp);
			wrap = 0;
		}
		fputc(isprint(ch) ? ch : '?', log_fp);
		wrap++;
	}
	if (wrap > 0) {
		fputc('\n', log_fp);
	}
	fflush(log_fp);
}

void slog_write_bin(const void *data, const size_t n)
{
	FILE *log_fp = slog_file ? slog_file : stdout;
	const size_t wrap = 16;
	const unsigned char *restrict b = data;
	for (size_t i = 0; i < n; i += wrap) {
		fprintf(log_fp, "  %p: ", (void *)(b + i));
		for (size_t j = 0; j < wrap; j++) {
			if ((i + j) < n) {
				fprintf(log_fp, "%02" PRIX8 " ", b[i + j]);
			} else {
				fputs("   ", log_fp);
			}
		}
		fputc(' ', log_fp);
		for (size_t j = 0; j < wrap; j++) {
			unsigned char ch = ' ';
			if ((i + j) < n) {
				ch = b[i + j];
				if (!isprint(ch)) {
					ch = '.';
				}
			}
			fputc(ch, log_fp);
		}
		fputc('\n', log_fp);
	}
	fflush(log_fp);
}
