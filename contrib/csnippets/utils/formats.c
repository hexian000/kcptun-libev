/* csnippets (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "formats.h"
#include "utils/arraysize.h"
#include "utils/minmax.h"

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

static int format_abnormal(char *buf, const size_t bufsize, const double value)
{
	if (isnan(value)) {
		if (signbit(value)) {
			return snprintf(buf, bufsize, "%s", "-nan");
		}
		return snprintf(buf, bufsize, "%s", "nan");
	}
	if (!isfinite(value)) {
		if (signbit(value)) {
			return snprintf(buf, bufsize, "%s", "-inf");
		}
		return snprintf(buf, bufsize, "%s", "inf");
	}
	if (value == 0.0) {
		if (signbit(value)) {
			return snprintf(buf, bufsize, "%s", "-0");
		}
		return snprintf(buf, bufsize, "%s", "0");
	}
	return snprintf(buf, bufsize, "%e", value);
}

static char *si_prefix_pos[] = {
	"k", "M", "G", "T", "P", "E", "Z", "Y", "R", "Q",
};

static char *si_prefix_neg[] = {
	"m", u8"μ", "n", "p", "f", "a", "z", "y", "r", "q",
};

int format_si_prefix(char *buf, const size_t bufsize, const double value)
{
	if (!isnormal(value)) {
		return format_abnormal(buf, bufsize, value);
	}
	const double absvalue = fabs(value);
	if (!(1e-30 < absvalue && absvalue < 1e+31)) {
		return snprintf(buf, bufsize, "%.2e", value);
	}
	const int e = (int)floor(log10(absvalue) / 3.0);
	if (e == 0) {
		return snprintf(buf, bufsize, "%.3g", value);
	}
	if (e < 0) {
		const size_t i = MIN((size_t)-e, ARRAY_SIZE(si_prefix_neg));
		const double v = value / pow(10, -3.0 * (double)i);
		const char *prefix = si_prefix_neg[i - 1];
		return snprintf(buf, bufsize, "%.3g%s", v, prefix);
	}
	const size_t i = MIN((size_t)e, ARRAY_SIZE(si_prefix_pos));
	const double v = value / pow(10, 3.0 * (double)i);
	const char *prefix = si_prefix_pos[i - 1];
	return snprintf(buf, bufsize, "%.3g%s", v, prefix);
}

static const char *iec_units[] = {
	"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB",
};

int format_iec_bytes(char *buf, const size_t bufsize, const double value)
{
	if (!isnormal(value)) {
		return format_abnormal(buf, bufsize, value);
	}
	const int e = ((int)log2(fabs(value)) - 1) / 10;
	const int i = CLAMP(e, 0, (int)ARRAY_SIZE(iec_units) - 1);
	const double v = ldexp(value, i * -10);
	if (i > 0) {
		if (-10.0 < v && v < 10.0) {
			return snprintf(
				buf, bufsize, "%.2f%s", v, iec_units[i]);
		}
		if (-100.0 < v && v < 100.0) {
			return snprintf(
				buf, bufsize, "%.1f%s", v, iec_units[i]);
		}
	}
	return snprintf(buf, bufsize, "%.0f%s", v, iec_units[i]);
}

struct duration make_duration(double value)
{
	struct duration d;
	if (value < 0.0) {
		d.sign = -1;
		value = -value;
	} else {
		d.sign = 1;
	}
	d.nano = (unsigned int)fmod(value * 1e+9, 1000.0);
	d.micro = (unsigned int)fmod(value * 1e+6, 1000.0);
	d.milli = (unsigned int)fmod(value * 1e+3, 1000.0);
	d.second = (unsigned int)fmod(value, 60.0);
	value /= 60.0;
	d.minute = (unsigned int)fmod(value, 60.0);
	value /= 60.0;
	d.hour = (unsigned int)fmod(value, 24.0);
	value /= 24.0;
	d.day = (unsigned int)value;
	return d;
}

struct duration make_duration_nanos(int_least64_t value)
{
	struct duration d;
	if (value < INT64_C(0)) {
		d.sign = -1;
	} else {
		d.sign = 1;
	}
	d.nano = (unsigned int)(value % 1000 * d.sign);
	value /= 1000;
	value *= d.sign;
	d.micro = (unsigned int)(value % 1000);
	value /= 1000;
	d.milli = (unsigned int)(value % 1000);
	value /= 1000;
	d.second = (unsigned int)(value % 60);
	value /= 60;
	d.minute = (unsigned int)(value % 60);
	value /= 60;
	d.hour = (unsigned int)(value % 24);
	value /= 24;
	d.day = (unsigned int)value;
	return d;
}

#define SIGNED_STR(sign, literal) ((sign) < 0 ? "-" literal : (literal))

int format_duration_seconds(char *b, const size_t size, const struct duration d)
{
	if (d.day) {
		return snprintf(
			b, size, SIGNED_STR(d.sign, "%ud%02u:%02u:%02u"), d.day,
			d.hour, d.minute, d.second);
	}
	if (d.hour) {
		return snprintf(
			b, size, SIGNED_STR(d.sign, "%u:%02u:%02u"), d.hour,
			d.minute, d.second);
	}
	return snprintf(
		b, size, SIGNED_STR(d.sign, "%u:%02u"), d.minute, d.second);
}

int format_duration_millis(char *b, const size_t size, const struct duration d)
{
	if (d.day) {
		return snprintf(
			b, size, SIGNED_STR(d.sign, "%ud%02u:%02u:%02u.%03u"),
			d.day, d.hour, d.minute, d.second, d.milli);
	}
	if (d.hour) {
		return snprintf(
			b, size, SIGNED_STR(d.sign, "%u:%02u:%02u.%03u"),
			d.hour, d.minute, d.second, d.milli);
	}
	return snprintf(
		b, size, SIGNED_STR(d.sign, "%u:%02u.%03u"), d.minute, d.second,
		d.milli);
}

int format_duration_nanos(char *b, const size_t size, const struct duration d)
{
	if (d.day) {
		return snprintf(
			b, size,
			SIGNED_STR(d.sign, "%ud%02u:%02u:%02u.%03u%03u%03u"),
			d.day, d.hour, d.minute, d.second, d.milli, d.micro,
			d.nano);
	}
	if (d.hour) {
		return snprintf(
			b, size,
			SIGNED_STR(d.sign, "%u:%02u:%02u.%03u%03u%03u"), d.hour,
			d.minute, d.second, d.milli, d.micro, d.nano);
	}
	return snprintf(
		b, size, SIGNED_STR(d.sign, "%u:%02u.%03u%03u%03u"), d.minute,
		d.second, d.milli, d.micro, d.nano);
}

int format_duration(char *b, size_t size, struct duration d)
{
	if (d.day) {
		const double seconds = d.second + d.milli * 1e-3 +
				       d.micro * 1e-6 + d.nano * 1e-9;
		return snprintf(
			b, size, SIGNED_STR(d.sign, "%ud%02u:%02u:%02.0f"),
			d.day, d.hour, d.minute, seconds);
	}
	if (d.hour) {
		const double seconds = d.second + d.milli * 1e-3 +
				       d.micro * 1e-6 + d.nano * 1e-9;
		return snprintf(
			b, size, SIGNED_STR(d.sign, "%u:%02u:%02.0f"), d.hour,
			d.minute, seconds);
	}
	if (d.minute) {
		const double seconds = d.second + d.milli * 1e-3 +
				       d.micro * 1e-6 + d.nano * 1e-9;
		if (d.minute >= 10) {
			return snprintf(
				b, size, SIGNED_STR(d.sign, "%u:%02.0f"),
				d.minute, seconds);
		}
		return snprintf(
			b, size, SIGNED_STR(d.sign, "%u:%04.1f"), d.minute,
			seconds);
	}
	if (d.second) {
		if (d.second >= 10) {
			const double seconds = d.second + d.milli * 1e-3 +
					       d.micro * 1e-6 + d.nano * 1e-9;
			return snprintf(
				b, size, SIGNED_STR(d.sign, "%.2fs"), seconds);
		}
		const double millis = d.second * 1e+3 + d.milli +
				      d.micro * 1e-3 + d.nano * 1e-6;
		return snprintf(b, size, SIGNED_STR(d.sign, "%.0fms"), millis);
	}
	if (d.milli) {
		const double millis = d.milli + d.micro * 1e-3 + d.nano * 1e-6;
		if (d.milli >= 100) {
			return snprintf(
				b, size, SIGNED_STR(d.sign, "%.1fms"), millis);
		}
		if (d.milli >= 10) {
			return snprintf(
				b, size, SIGNED_STR(d.sign, "%.2fms"), millis);
		}
		return snprintf(b, size, SIGNED_STR(d.sign, "%.3fms"), millis);
	}
	if (d.micro) {
		if (d.micro >= 100) {
			const double micros = d.micro + d.nano * 1e-3;
			return snprintf(
				b, size, SIGNED_STR(d.sign, "%.1fµs"), micros);
		}
		if (d.micro >= 10) {
			const double micros = d.micro + d.nano * 1e-3;
			return snprintf(
				b, size, SIGNED_STR(d.sign, "%.2fµs"), micros);
		}
		const unsigned int nanos = d.micro * 1000u + d.nano;
		return snprintf(b, size, SIGNED_STR(d.sign, "%uns"), nanos);
	}
	if (d.nano) {
		return snprintf(b, size, SIGNED_STR(d.sign, "%uns"), d.nano);
	}
	return snprintf(b, size, SIGNED_STR(d.sign, "0"));
}
