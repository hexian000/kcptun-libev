/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "formats.h"
#include "utils/arraysize.h"
#include "utils/minmax.h"

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

static int
format_abnormal(char *restrict s, const size_t maxlen, const double value)
{
	if (isnan(value)) {
		if (signbit(value)) {
			return snprintf(s, maxlen, "%s", "-nan");
		}
		return snprintf(s, maxlen, "%s", "nan");
	}
	if (!isfinite(value)) {
		if (signbit(value)) {
			return snprintf(s, maxlen, "%s", "-inf");
		}
		return snprintf(s, maxlen, "%s", "inf");
	}
	if (value == 0.0) {
		if (signbit(value)) {
			return snprintf(s, maxlen, "%s", "-0");
		}
		return snprintf(s, maxlen, "%s", "0");
	}
	return snprintf(s, maxlen, "%e", value);
}

static const char *const si_prefix_pos[] = {
	"k", "M", "G", "T", "P", "E", "Z", "Y", "R", "Q",
};

static const char *const si_prefix_neg[] = {
	"m", u8"μ", "n", "p", "f", "a", "z", "y", "r", "q",
};

int format_si_prefix(char *restrict s, const size_t maxlen, const double value)
{
	if (!isnormal(value)) {
		return format_abnormal(s, maxlen, value);
	}
	const double absvalue = fabs(value);
	if (!(1e-30 <= absvalue && absvalue < 1e+31)) {
		return snprintf(s, maxlen, "%.2e", value);
	}
	const int e = (int)floor(log10(absvalue) / 3.0);
	if (e == 0) {
		return snprintf(s, maxlen, "%.3g", value);
	}
	if (e < 0) {
		const size_t i = MIN((size_t)-e, ARRAY_SIZE(si_prefix_neg));
		const double v = value / pow(10, -3.0 * (double)i);
		const char *prefix = si_prefix_neg[i - 1];
		return snprintf(s, maxlen, "%.3g%s", v, prefix);
	}
	const size_t i = MIN((size_t)e, ARRAY_SIZE(si_prefix_pos));
	const double v = value / pow(10, 3.0 * (double)i);
	const char *prefix = si_prefix_pos[i - 1];
	return snprintf(s, maxlen, "%.3g%s", v, prefix);
}

static const char *iec_units[] = {
	"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB",
};

int format_iec_bytes(char *restrict s, const size_t maxlen, const double value)
{
	if (!isnormal(value)) {
		return format_abnormal(s, maxlen, value);
	}
	const double absvalue = fabs(value);
	const int e = absvalue > 1.0 ? ((int)log2(absvalue) - 1) / 10 : 0.0;
	const int i = MIN(e, (int)ARRAY_SIZE(iec_units) - 1);
	const double v = ldexp(value, i * -10);
	if (i > 0) {
		if (-10.0 < v && v < 10.0) {
			return snprintf(s, maxlen, "%.2f%s", v, iec_units[i]);
		}
		if (-100.0 < v && v < 100.0) {
			return snprintf(s, maxlen, "%.1f%s", v, iec_units[i]);
		}
	}
	return snprintf(s, maxlen, "%.0f%s", v, iec_units[i]);
}

struct duration make_duration(const double seconds)
{
	double value = seconds;
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

struct duration make_duration_nanos(const int_least64_t nanos)
{
	uint_fast64_t value;
	struct duration d;
	if (nanos < INT64_C(0)) {
		d.sign = -1;
		value = -(uint_fast64_t)nanos;
	} else {
		d.sign = 1;
		value = (uint_fast64_t)nanos;
	}
	d.nano = (unsigned int)(value % 1000);
	value /= 1000;
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

int format_duration_seconds(
	char *restrict s, const size_t maxlen, const struct duration d)
{
	if (d.day) {
		return snprintf(
			s, maxlen, SIGNED_STR(d.sign, "%ud%02u:%02u:%02u"),
			d.day, d.hour, d.minute, d.second);
	}
	if (d.hour) {
		return snprintf(
			s, maxlen, SIGNED_STR(d.sign, "%u:%02u:%02u"), d.hour,
			d.minute, d.second);
	}
	return snprintf(
		s, maxlen, SIGNED_STR(d.sign, "%u:%02u"), d.minute, d.second);
}

int format_duration_millis(
	char *restrict s, const size_t maxlen, const struct duration d)
{
	if (d.day) {
		return snprintf(
			s, maxlen, SIGNED_STR(d.sign, "%ud%02u:%02u:%02u.%03u"),
			d.day, d.hour, d.minute, d.second, d.milli);
	}
	if (d.hour) {
		return snprintf(
			s, maxlen, SIGNED_STR(d.sign, "%u:%02u:%02u.%03u"),
			d.hour, d.minute, d.second, d.milli);
	}
	return snprintf(
		s, maxlen, SIGNED_STR(d.sign, "%u:%02u.%03u"), d.minute,
		d.second, d.milli);
}

int format_duration_nanos(
	char *restrict s, const size_t maxlen, const struct duration d)
{
	if (d.day) {
		return snprintf(
			s, maxlen,
			SIGNED_STR(d.sign, "%ud%02u:%02u:%02u.%03u%03u%03u"),
			d.day, d.hour, d.minute, d.second, d.milli, d.micro,
			d.nano);
	}
	if (d.hour) {
		return snprintf(
			s, maxlen,
			SIGNED_STR(d.sign, "%u:%02u:%02u.%03u%03u%03u"), d.hour,
			d.minute, d.second, d.milli, d.micro, d.nano);
	}
	return snprintf(
		s, maxlen, SIGNED_STR(d.sign, "%u:%02u.%03u%03u%03u"), d.minute,
		d.second, d.milli, d.micro, d.nano);
}

int format_duration(char *restrict s, size_t maxlen, const struct duration d)
{
	if (d.day) {
		const double seconds = d.second + d.milli * 1e-3 +
				       d.micro * 1e-6 + d.nano * 1e-9;
		return snprintf(
			s, maxlen, SIGNED_STR(d.sign, "%ud%02u:%02u:%02.0f"),
			d.day, d.hour, d.minute, seconds);
	}
	if (d.hour) {
		const double seconds = d.second + d.milli * 1e-3 +
				       d.micro * 1e-6 + d.nano * 1e-9;
		return snprintf(
			s, maxlen, SIGNED_STR(d.sign, "%u:%02u:%02.0f"), d.hour,
			d.minute, seconds);
	}
	if (d.minute) {
		const double seconds = d.second + d.milli * 1e-3 +
				       d.micro * 1e-6 + d.nano * 1e-9;
		if (d.minute >= 10) {
			return snprintf(
				s, maxlen, SIGNED_STR(d.sign, "%u:%02.0f"),
				d.minute, seconds);
		}
		return snprintf(
			s, maxlen, SIGNED_STR(d.sign, "%u:%04.1f"), d.minute,
			seconds);
	}
	if (d.second) {
		if (d.second >= 10) {
			const double seconds = d.second + d.milli * 1e-3 +
					       d.micro * 1e-6 + d.nano * 1e-9;
			return snprintf(
				s, maxlen, SIGNED_STR(d.sign, "%.2fs"),
				seconds);
		}
		const double millis = d.second * 1e+3 + d.milli +
				      d.micro * 1e-3 + d.nano * 1e-6;
		return snprintf(
			s, maxlen, SIGNED_STR(d.sign, "%.0fms"), millis);
	}
	if (d.milli) {
		const double millis = d.milli + d.micro * 1e-3 + d.nano * 1e-6;
		if (d.milli >= 100) {
			return snprintf(
				s, maxlen, SIGNED_STR(d.sign, "%.1fms"),
				millis);
		}
		if (d.milli >= 10) {
			return snprintf(
				s, maxlen, SIGNED_STR(d.sign, "%.2fms"),
				millis);
		}
		return snprintf(
			s, maxlen, SIGNED_STR(d.sign, "%.3fms"), millis);
	}
	if (d.micro) {
		if (d.micro >= 100) {
			const double micros = d.micro + d.nano * 1e-3;
			return snprintf(
				s, maxlen, SIGNED_STR(d.sign, "%.1fµs"),
				micros);
		}
		if (d.micro >= 10) {
			const double micros = d.micro + d.nano * 1e-3;
			return snprintf(
				s, maxlen, SIGNED_STR(d.sign, "%.2fµs"),
				micros);
		}
		const unsigned int nanos = d.micro * 1000u + d.nano;
		return snprintf(s, maxlen, SIGNED_STR(d.sign, "%uns"), nanos);
	}
	if (d.nano) {
		return snprintf(s, maxlen, SIGNED_STR(d.sign, "%uns"), d.nano);
	}
	return snprintf(s, maxlen, SIGNED_STR(d.sign, "0"));
}

#if HAVE_GMTIME_R
#define GMTIME(timer) gmtime_r((timer), &(struct tm){ 0 })
#else
#define GMTIME(timer) gmtime((timer))
#endif /* HAVE_GMTIME_R */

#if HAVE_LOCALTIME_R
#define LOCALTIME(timer) localtime_r((timer), &(struct tm){ 0 })
#else
#define LOCALTIME(timer) localtime((timer))
#endif /* HAVE_LOCALTIME_R */

#define STRLEN(s) (sizeof(s "") - sizeof(""))

#define LAYOUT_C "2006-01-02T15:04:05-0700"
#define LAYOUT_C_UTC "2006-01-02T15:04:05Z"

#define STRFTIME(s, maxlen, timer)                                             \
	(strftime((s), (maxlen), "%FT%T%z", LOCALTIME(timer)) ==               \
	 STRLEN(LAYOUT_C))

#define STRFTIME_UTC(s, maxlen, timer)                                         \
	(strftime((s), (maxlen), "%FT%TZ", GMTIME(timer)) ==                   \
	 STRLEN(LAYOUT_C_UTC))

#define LAYOUT_RFC3339 "2006-01-02T15:04:05-07:00"
#define LAYOUT_RFC3339_UTC "2006-01-02T15:04:05Z"

/* a fixed-length layout conforming to both ISO 8601 and RFC 3339 */
int format_rfc3339(
	char *restrict s, const size_t maxlen, const time_t timer,
	const bool utc)
{
	if (utc) {
		if (maxlen < sizeof(LAYOUT_RFC3339_UTC)) {
			if (maxlen > 0) {
				s[0] = '\0';
			}
			return (int)STRLEN(LAYOUT_RFC3339_UTC);
		}
		if (!STRFTIME_UTC(s, maxlen, &timer)) {
			if (maxlen > 0) {
				s[0] = '\0';
			}
			return -1;
		}
		return (int)STRLEN(LAYOUT_RFC3339_UTC);
	}

	if (maxlen < sizeof(LAYOUT_RFC3339)) {
		if (maxlen > 0) {
			s[0] = '\0';
		}
		return (int)STRLEN(LAYOUT_RFC3339);
	}
	if (!STRFTIME(s, maxlen, &timer)) {
		if (maxlen > 0) {
			s[0] = '\0';
		}
		return -1;
	}
	const char *restrict tz = s + STRLEN(LAYOUT_C);
	char *restrict e = s + sizeof(LAYOUT_RFC3339);
	*--e = '\0';
	*--e = *--tz;
	*--e = *--tz;
	*--e = ':';
	return (int)STRLEN(LAYOUT_RFC3339);
}

#define LAYOUT_RFC3339NANO "2006-01-02T15:04:05.999999999-07:00"
#define LAYOUT_RFC3339NANO_UTC "2006-01-02T15:04:05.999999999Z"

int format_rfc3339nano(
	char *restrict s, const size_t maxlen,
	const struct timespec *restrict tp, const bool utc)
{
	if (utc) {
		if (maxlen < sizeof(LAYOUT_RFC3339NANO_UTC)) {
			if (maxlen > 0) {
				s[0] = '\0';
			}
			return (int)STRLEN(LAYOUT_RFC3339NANO_UTC);
		}
		if (!STRFTIME_UTC(s, maxlen, &tp->tv_sec)) {
			if (maxlen > 0) {
				s[0] = '\0';
			}
			return -1;
		}
		unsigned char *restrict e =
			(unsigned char *)s + sizeof(LAYOUT_RFC3339NANO_UTC);
		int ns = (int)tp->tv_nsec;
		*--e = '\0';
		*--e = 'Z';
		*--e = '0' + ns % 10, ns /= 10;
		*--e = '0' + ns % 10, ns /= 10;
		*--e = '0' + ns % 10, ns /= 10;
		*--e = '0' + ns % 10, ns /= 10;
		*--e = '0' + ns % 10, ns /= 10;
		*--e = '0' + ns % 10, ns /= 10;
		*--e = '0' + ns % 10, ns /= 10;
		*--e = '0' + ns % 10, ns /= 10;
		*--e = '0' + ns % 10;
		*--e = '.';
		return (int)STRLEN(LAYOUT_RFC3339NANO_UTC);
	}

	if (maxlen < sizeof(LAYOUT_RFC3339NANO)) {
		if (maxlen > 0) {
			s[0] = '\0';
		}
		return (int)STRLEN(LAYOUT_RFC3339NANO);
	}
	if (!STRFTIME(s, maxlen, &tp->tv_sec)) {
		if (maxlen > 0) {
			s[0] = '\0';
		}
		return -1;
	}
	const unsigned char *restrict tz =
		(unsigned char *)s + STRLEN(LAYOUT_C);
	unsigned char *restrict e =
		(unsigned char *)s + sizeof(LAYOUT_RFC3339NANO);
	*--e = '\0';
	*--e = *--tz;
	*--e = *--tz;
	*--e = ':';
	*--e = *--tz;
	*--e = *--tz;
	*--e = *--tz;
	int ns = (int)tp->tv_nsec;
	*--e = '0' + ns % 10, ns /= 10;
	*--e = '0' + ns % 10, ns /= 10;
	*--e = '0' + ns % 10, ns /= 10;
	*--e = '0' + ns % 10, ns /= 10;
	*--e = '0' + ns % 10, ns /= 10;
	*--e = '0' + ns % 10, ns /= 10;
	*--e = '0' + ns % 10, ns /= 10;
	*--e = '0' + ns % 10, ns /= 10;
	*--e = '0' + ns % 10;
	*--e = '.';
	return (int)STRLEN(LAYOUT_RFC3339NANO);
}
