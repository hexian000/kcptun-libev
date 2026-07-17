/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "formats.h"

#include "meta/arraysize.h"
#include "meta/minmax.h"

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
	/* U+00B5 MICRO SIGN, matching format_duration; a plain (non-u8) literal
	 * so it stays char[] under C23 too */
	"m", "µ", "n", "p", "f", "a", "z", "y", "r", "q",
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
	int e = (int)floor(log10(absvalue) / 3.0);
	double v = value / pow(10, 3.0 * (double)e);
	/* the scaled mantissa is in [1, 1000), but %.3g rounds a value in
	 * [999.5, 1000) up to "1e+03"; promote to the next prefix so it reads
	 * "1<next>" rather than "1e+03<prev>" */
	if (fabs(v) >= 999.5) {
		e++;
		v /= 1000.0;
	}
	if (e == 0) {
		return snprintf(s, maxlen, "%.3g", v);
	}
	const char *prefix;
	if (e < 0) {
		const size_t i = (size_t)(-e);
		if (i > ARRAY_SIZE(si_prefix_neg)) {
			return snprintf(s, maxlen, "%.2e", value);
		}
		prefix = si_prefix_neg[i - 1];
	} else {
		const size_t i = (size_t)e;
		if (i > ARRAY_SIZE(si_prefix_pos)) {
			return snprintf(s, maxlen, "%.2e", value);
		}
		prefix = si_prefix_pos[i - 1];
	}
	return snprintf(s, maxlen, "%.3g%s", v, prefix);
}

static const char *const iec_units[] = {
	"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB",
};

int format_iec_bytes(char *restrict s, const size_t maxlen, const double value)
{
	if (!isnormal(value)) {
		return format_abnormal(s, maxlen, value);
	}
	const double absvalue = fabs(value);
	const int e = absvalue > 1.0 ? ((int)log2(absvalue) - 1) / 10 : 0;
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

struct duration make_duration_nanos(const int_fast64_t nanos)
{
	uint_fast64_t value;
	struct duration d;
	if (nanos < 0) {
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
	const double frac = d.milli * 1e-3 + d.micro * 1e-6 + d.nano * 1e-9;
	if (d.day || d.hour || d.minute >= 10) {
		/* whole-second display: round the seconds field the way "%.0f"
		 * would, then carry a rounded-up 60 through minute->hour->day so
		 * no field is ever printed as "60" */
		struct duration t = d;
		unsigned int sec = (unsigned int)nearbyint(t.second + frac);
		if (sec >= 60) {
			sec -= 60;
			if (++t.minute >= 60) {
				t.minute = 0;
				if (++t.hour >= 24) {
					t.hour = 0;
					t.day++;
				}
			}
		}
		if (t.day) {
			return snprintf(
				s, maxlen,
				SIGNED_STR(d.sign, "%ud%02u:%02u:%02u"), t.day,
				t.hour, t.minute, sec);
		}
		if (t.hour) {
			return snprintf(
				s, maxlen, SIGNED_STR(d.sign, "%u:%02u:%02u"),
				t.hour, t.minute, sec);
		}
		return snprintf(
			s, maxlen, SIGNED_STR(d.sign, "%u:%02u"), t.minute,
			sec);
	}
	if (d.minute) {
		/* sub-10-minute display keeps tenth-second precision; carry a
		 * rounded-up 60.0 into the minute field */
		struct duration t = d;
		unsigned int tenths =
			(unsigned int)nearbyint((t.second + frac) * 10.0);
		if (tenths >= 600) {
			tenths -= 600;
			t.minute++;
		}
		return snprintf(
			s, maxlen, SIGNED_STR(d.sign, "%u:%04.1f"), t.minute,
			tenths / 10.0);
	}
	if (d.second) {
		if (d.second >= 10) {
			const double seconds = d.second + d.milli * 1e-3 +
					       d.micro * 1e-6 + d.nano * 1e-9;
			/* a value that rounds up to 60.00s carries into a
			 * one-minute display instead of printing "60.00s" */
			if (nearbyint(seconds * 100.0) >= 60.0 * 100.0) {
				return format_duration(
					s, maxlen,
					(struct duration){ .sign = d.sign,
							   .minute = 1 });
			}
			return snprintf(
				s, maxlen, SIGNED_STR(d.sign, "%.2fs"),
				seconds);
		}
		const double millis = d.second * 1e+3 + d.milli +
				      d.micro * 1e-3 + d.nano * 1e-6;
		/* a value that rounds up to 10000ms carries into the >=10s
		 * seconds display */
		if (nearbyint(millis) >= 10.0 * 1000.0) {
			return format_duration(
				s, maxlen,
				(struct duration){ .sign = d.sign,
						   .second = 10 });
		}
		return snprintf(
			s, maxlen, SIGNED_STR(d.sign, "%.0fms"), millis);
	}
	if (d.milli) {
		const double millis = d.milli + d.micro * 1e-3 + d.nano * 1e-6;
		if (d.milli >= 100) {
			/* a value that rounds up to 1000.0ms carries into a
			 * one-second display */
			if (nearbyint(millis * 10.0) >= 1000.0 * 10.0) {
				return format_duration(
					s, maxlen,
					(struct duration){ .sign = d.sign,
							   .second = 1 });
			}
			return snprintf(
				s, maxlen, SIGNED_STR(d.sign, "%.1fms"),
				millis);
		}
		if (d.milli >= 10) {
			/* mirror the micro>=10 guard: rounding up to 100.0 drops
			 * to one decimal, so "100.0ms" not "100.00ms" */
			if (nearbyint(millis * 100.0) >= 100.0 * 100.0) {
				return snprintf(
					s, maxlen, SIGNED_STR(d.sign, "%.1fms"),
					millis);
			}
			return snprintf(
				s, maxlen, SIGNED_STR(d.sign, "%.2fms"),
				millis);
		}
		/* milli < 10: rounding up to 10.0 drops to two decimals, so
		 * "10.00ms" (matching the milli>=10 range) not "10.000ms" */
		if (nearbyint(millis * 1000.0) >= 10.0 * 1000.0) {
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
			/* a value that rounds up to 1000.0us carries into a
			 * one-millisecond display */
			if (nearbyint(micros * 10.0) >= 1000.0 * 10.0) {
				return format_duration(
					s, maxlen,
					(struct duration){ .sign = d.sign,
							   .milli = 1 });
			}
			return snprintf(
				s, maxlen, SIGNED_STR(d.sign, "%.1fµs"),
				micros);
		}
		if (d.micro >= 10) {
			const double micros = d.micro + d.nano * 1e-3;
			/* a mid-range value that rounds up to 100.0 gains an
			 * integer digit; drop a decimal (as the >=100 branch does)
			 * so the width stays ~3 significant figures instead of
			 * printing "100.00µs" */
			if (nearbyint(micros * 100.0) >= 100.0 * 100.0) {
				return snprintf(
					s, maxlen, SIGNED_STR(d.sign, "%.1fµs"),
					micros);
			}
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

/* localtime_r/gmtime_r return NULL with EOVERFLOW when the time_t cannot be
 * represented in a struct tm, which strftime would then dereference.  Report
 * it as a zero-length result so the callers below take the failure path they
 * already have for a strftime that produced the wrong length. */
static size_t strftime_checked(
	char *restrict s, const size_t maxlen, const char *restrict format,
	const struct tm *restrict tm)
{
	if (tm == NULL) {
		return 0;
	}
	/* RFC 3339 §5.6 requires date-fullyear = 4DIGIT; the length gate cannot
	 * enforce it (a negative year renders as a 4-char "-NNN" of the expected
	 * width), so reject any year outside [1000, 9999] here. */
	if (tm->tm_year < 1000 - 1900 || tm->tm_year > 9999 - 1900) {
		return 0;
	}
	return strftime(s, maxlen, format, tm);
}

#define STRFTIME(s, maxlen, timer)                                             \
	(strftime_checked((s), (maxlen), "%FT%T%z", LOCALTIME(timer)) ==       \
	 STRLEN(LAYOUT_C))

#define STRFTIME_UTC(s, maxlen, timer)                                         \
	(strftime_checked((s), (maxlen), "%FT%TZ", GMTIME(timer)) ==           \
	 STRLEN(LAYOUT_C_UTC))

#define LAYOUT_RFC3339 "2006-01-02T15:04:05-07:00"
#define LAYOUT_RFC3339_UTC "2006-01-02T15:04:05Z"

#define LAYOUT_RFC3339NANO "2006-01-02T15:04:05.999999999-07:00"
#define LAYOUT_RFC3339NANO_UTC "2006-01-02T15:04:05.999999999Z"

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
			s[0] = '\0';
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
		s[0] = '\0';
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

int format_rfc3339nano(
	char *restrict s, const size_t maxlen,
	const struct timespec *restrict tp, const bool utc)
{
	/* the nine-digit unroll below assumes a normalized tv_nsec; POSIX
	 * constrains it to [0, 999999999], and outside that range the unroll
	 * would emit non-digit bytes or silently drop a carried second */
	if (tp->tv_nsec < 0 || tp->tv_nsec > 999999999) {
		if (maxlen > 0) {
			s[0] = '\0';
		}
		return -1;
	}
	if (utc) {
		if (maxlen < sizeof(LAYOUT_RFC3339NANO_UTC)) {
			if (maxlen > 0) {
				s[0] = '\0';
			}
			return (int)STRLEN(LAYOUT_RFC3339NANO_UTC);
		}
		if (!STRFTIME_UTC(s, maxlen, &tp->tv_sec)) {
			s[0] = '\0';
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
		s[0] = '\0';
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
