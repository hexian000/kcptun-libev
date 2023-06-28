/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "formats.h"
#include "utils/arraysize.h"

#include <stdint.h>
#include <stdio.h>
#include <math.h>

static const char *iec_units[] = {
	"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB",
};

int format_iec_bytes(char *buf, const size_t bufsize, const double value)
{
	if (!isfinite(value) || (value < 8192.0)) {
		return snprintf(buf, bufsize, "%.0lf %s", value, iec_units[0]);
	}
	const int x = ((int)log2(value) - 3) / 10;
	const int n = (int)ARRAY_SIZE(iec_units) - 1;
	const int i = (x <= n ? x : n);
	const double v = ldexp(value, i * -10);
	if (v < 10.0) {
		return snprintf(buf, bufsize, "%.02lf %s", v, iec_units[i]);
	}
	if (v < 100.0) {
		return snprintf(buf, bufsize, "%.01lf %s", v, iec_units[i]);
	}
	return snprintf(buf, bufsize, "%.0lf %s", v, iec_units[i]);
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
	d.nanos = (unsigned int)fmod(value * 1e+9, 1000.0);
	d.micros = (unsigned int)fmod(value * 1e+6, 1000.0);
	d.millis = (unsigned int)fmod(value * 1e+3, 1000.0);
	d.seconds = (unsigned int)fmod(value, 60.0);
	value /= 60.0;
	d.minutes = (unsigned int)fmod(value, 60.0);
	value /= 60.0;
	d.hours = (unsigned int)fmod(value, 24.0);
	value /= 24.0;
	d.days = (unsigned int)value;
	return d;
}

struct duration make_duration_nanos(int64_t value)
{
	struct duration d;
	if (value < INT64_C(0)) {
		d.sign = -1;
	} else {
		d.sign = 1;
	}
	d.nanos = (unsigned int)(value % 1000 * d.sign);
	value /= 1000;
	value *= d.sign;
	d.micros = (unsigned int)(value % 1000);
	value /= 1000;
	d.millis = (unsigned int)(value % 1000);
	value /= 1000;
	d.seconds = (unsigned int)(value % 60);
	value /= 60;
	d.minutes = (unsigned int)(value % 60);
	value /= 60;
	d.hours = (unsigned int)(value % 24);
	value /= 24;
	d.days = (unsigned int)value;
	return d;
}

#define SIGNED_STR(sign, literal) ((sign) < 0 ? "-" literal : (literal))

int format_duration_seconds(char *b, const size_t size, const struct duration d)
{
	if (d.days) {
		return snprintf(
			b, size, SIGNED_STR(d.sign, "%ud%02u:%02u:%02u"),
			d.days, d.hours, d.minutes, d.seconds);
	}
	if (d.hours) {
		return snprintf(
			b, size, SIGNED_STR(d.sign, "%u:%02u:%02u"), d.hours,
			d.minutes, d.seconds);
	}
	return snprintf(
		b, size, SIGNED_STR(d.sign, "%u:%02u"), d.minutes, d.seconds);
}

int format_duration_millis(char *b, const size_t size, const struct duration d)
{
	if (d.days) {
		return snprintf(
			b, size, SIGNED_STR(d.sign, "%ud%02u:%02u:%02u.%03u"),
			d.days, d.hours, d.minutes, d.seconds, d.millis);
	}
	if (d.hours) {
		return snprintf(
			b, size, SIGNED_STR(d.sign, "%u:%02u:%02u.%03u"),
			d.hours, d.minutes, d.seconds, d.millis);
	}
	return snprintf(
		b, size, SIGNED_STR(d.sign, "%u:%02u.%03u"), d.minutes,
		d.seconds, d.millis);
}

int format_duration_nanos(char *b, const size_t size, const struct duration d)
{
	if (d.days) {
		return snprintf(
			b, size,
			SIGNED_STR(d.sign, "%ud%02u:%02u:%02u.%03u%03u%03u"),
			d.days, d.hours, d.minutes, d.seconds, d.millis,
			d.micros, d.nanos);
	}
	if (d.hours) {
		return snprintf(
			b, size,
			SIGNED_STR(d.sign, "%u:%02u:%02u.%03u%03u%03u"),
			d.hours, d.minutes, d.seconds, d.millis, d.micros,
			d.nanos);
	}
	return snprintf(
		b, size, SIGNED_STR(d.sign, "%u:%02u.%03u%03u%03u"), d.minutes,
		d.seconds, d.millis, d.micros, d.nanos);
}

int format_duration(char *b, size_t size, struct duration d)
{
	if (d.days) {
		const double seconds = d.seconds + d.millis * 1e-3 +
				       d.micros * 1e-6 + d.nanos * 1e-9;
		return snprintf(
			b, size, SIGNED_STR(d.sign, "%ud%02u:%02u:%02.0f"),
			d.days, d.hours, d.minutes, seconds);
	}
	if (d.hours) {
		const double seconds = d.seconds + d.millis * 1e-3 +
				       d.micros * 1e-6 + d.nanos * 1e-9;
		return snprintf(
			b, size, SIGNED_STR(d.sign, "%u:%02u:%02.0f"), d.hours,
			d.minutes, seconds);
	}
	if (d.minutes) {
		const double seconds = d.seconds + d.millis * 1e-3 +
				       d.micros * 1e-6 + d.nanos * 1e-9;
		if (d.minutes >= 10) {
			return snprintf(
				b, size, SIGNED_STR(d.sign, "%u:%02.0f"),
				d.minutes, seconds);
		}
		return snprintf(
			b, size, SIGNED_STR(d.sign, "%u:%04.01f"), d.minutes,
			seconds);
	}
	if (d.seconds) {
		if (d.seconds >= 10) {
			const double seconds = d.seconds + d.millis * 1e-3 +
					       d.micros * 1e-6 + d.nanos * 1e-9;
			return snprintf(
				b, size, SIGNED_STR(d.sign, "%.02fs"), seconds);
		}
		const double millis = d.seconds * 1e+3 + d.millis +
				      d.micros * 1e-3 + d.nanos * 1e-6;
		return snprintf(b, size, SIGNED_STR(d.sign, "%.0fms"), millis);
	}
	if (d.millis) {
		if (d.millis >= 100) {
			const double millis =
				d.millis + d.micros * 1e-3 + d.nanos * 1e-6;
			return snprintf(
				b, size, SIGNED_STR(d.sign, "%.01fms"), millis);
		}
		if (d.millis >= 10) {
			const double millis =
				d.millis + d.micros * 1e-3 + d.nanos * 1e-6;
			return snprintf(
				b, size, SIGNED_STR(d.sign, "%.02fms"), millis);
		}
		const double micros =
			d.millis * 1e+3 + d.micros + d.nanos * 1e-3;
		return snprintf(b, size, SIGNED_STR(d.sign, "%.0fµs"), micros);
	}
	if (d.micros) {
		if (d.micros >= 100) {
			const double micros = d.micros + d.nanos * 1e-3;
			return snprintf(
				b, size, SIGNED_STR(d.sign, "%.01fµs"), micros);
		}
		if (d.micros >= 10) {
			const double micros = d.micros + d.nanos * 1e-3;
			return snprintf(
				b, size, SIGNED_STR(d.sign, "%.02fµs"), micros);
		}
		const unsigned int nanos = d.micros * 1000u + d.nanos;
		return snprintf(b, size, SIGNED_STR(d.sign, "%uns"), nanos);
	}
	return snprintf(b, size, SIGNED_STR(d.sign, "%uns"), d.nanos);
}
