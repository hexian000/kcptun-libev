/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef FORMATS_H
#define FORMATS_H

#include <stddef.h>
#include <stdint.h>

int format_iec_bytes(char *buf, size_t bufsize, double value);

struct duration {
	signed int sign; /* +1 or -1, 0 is null, otherwise undefined */
	unsigned int days;
	unsigned int hours;
	unsigned int minutes;
	unsigned int seconds;
	unsigned int millis;
	unsigned int micros;
	unsigned int nanos;
};

struct duration make_duration(double seconds);
struct duration make_duration_nanos(int64_t nanos);

/* the value is truncated */
int format_duration_seconds(char *b, size_t size, struct duration d);
/* the value is truncated */
int format_duration_millis(char *b, size_t size, struct duration d);
/* the value is precise */
int format_duration_nanos(char *b, size_t size, struct duration d);
/* the value is rounded */
int format_duration(char *b, size_t size, struct duration d);

#endif /* FORMATS_H */
