/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "slog.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>

int slog_level = LOG_LEVEL_VERBOSE;
FILE *slog_file = NULL;

void slog_write_bin(const void *data, const size_t n)
{
	FILE *log_fp = slog_file ? slog_file : stdout;
	const unsigned char *restrict b = data;
	for (size_t i = 0; i < n; i += 16) {
		fprintf(log_fp, "  %p: ", (void *)(b + i));
		for (size_t j = 0; j < 16; j++) {
			if ((i + j) < n) {
				fprintf(log_fp, "%02" PRIX8 " ", b[i + j]);
			} else {
				fputs("   ", log_fp);
			}
		}
		fputc(' ', log_fp);
		for (size_t j = 0; j < 16; j++) {
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
