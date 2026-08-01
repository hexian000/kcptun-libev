/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "time.h"

#include "utils/ctype_ascii.h"

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

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

#define LAYOUT_RFC3339 "2006-01-02T15:04:05-07:00"
#define LAYOUT_RFC3339_UTC "2006-01-02T15:04:05Z"

#define LAYOUT_RFC3339NANO "2006-01-02T15:04:05.999999999-07:00"
#define LAYOUT_RFC3339NANO_UTC "2006-01-02T15:04:05.999999999Z"

/* the fixed-length "YYYY-MM-DDTHH:MM:SS" head, shared by both formatters */
#define LAYOUT_DATETIME "2006-01-02T15:04:05"

/* time_t is assumed a signed two's-complement integer (POSIX plus C23); its
 * bounds gate the tz-offset application below without invoking overflow UB. */
static_assert((time_t)-1 < 0, "time_t must be a signed type");
#define TIME_T_MAX                                                             \
	((time_t)(((uintmax_t)1 << (sizeof(time_t) * CHAR_BIT - 1U)) - 1))
#define TIME_T_MIN ((time_t)(-TIME_T_MAX - 1))

static bool fits_time_t(const int_least64_t v)
{
	return (int_least64_t)TIME_T_MIN <= v && v <= (int_least64_t)TIME_T_MAX;
}

/* Break t + tzoff down into calendar fields for RFC 3339 rendering, rejecting
 * anything that cannot form a conforming stamp: an offset application that
 * overflows time_t, a time_t that gmtime cannot represent (NULL/EOVERFLOW), or
 * a year outside RFC 3339 §5.6's 4-digit [1000, 9999]. */
static bool break_down(const time_t t, const int tzoff, struct tm *restrict out)
{
	if (tzoff > 0 ? (t > TIME_T_MAX - tzoff) : (t < TIME_T_MIN - tzoff)) {
		return false;
	}
	const time_t local = t + tzoff;
	const struct tm *restrict p = GMTIME(&local);
	if (p == NULL) {
		return false;
	}
	if (p->tm_year < 1000 - 1900 || p->tm_year > 9999 - 1900) {
		return false;
	}
	*out = *p;
	return true;
}

/* Write the fixed 19-char "YYYY-MM-DDTHH:MM:SS" head; tm_year is known in
 * [1000-1900, 9999-1900], so the year is exactly four digits. */
static void put_datetime(char *restrict s, const struct tm *restrict tm)
{
	const int year = tm->tm_year + 1900;
	s[0] = (char)('0' + year / 1000 % 10);
	s[1] = (char)('0' + year / 100 % 10);
	s[2] = (char)('0' + year / 10 % 10);
	s[3] = (char)('0' + year % 10);
	s[4] = '-';
	const int mon = tm->tm_mon + 1;
	s[5] = (char)('0' + mon / 10);
	s[6] = (char)('0' + mon % 10);
	s[7] = '-';
	s[8] = (char)('0' + tm->tm_mday / 10);
	s[9] = (char)('0' + tm->tm_mday % 10);
	s[10] = 'T';
	s[11] = (char)('0' + tm->tm_hour / 10);
	s[12] = (char)('0' + tm->tm_hour % 10);
	s[13] = ':';
	s[14] = (char)('0' + tm->tm_min / 10);
	s[15] = (char)('0' + tm->tm_min % 10);
	s[16] = ':';
	s[17] = (char)('0' + tm->tm_sec / 10);
	s[18] = (char)('0' + tm->tm_sec % 10);
}

/* Write the zone suffix ('Z' for UTC, else minute-granular "±HH:MM") and return
 * its length. The magnitude is taken through unsigned so tzoff == INT_MIN cannot
 * overflow. */
static int put_zone(char *restrict s, const int tzoff)
{
	if (tzoff == 0) {
		s[0] = 'Z';
		return (int)STRLEN("Z");
	}
	const unsigned off = tzoff < 0 ? -(unsigned)tzoff : (unsigned)tzoff;
	const unsigned hh = off / 3600U;
	const unsigned mm = off / 60U % 60U;
	s[0] = tzoff < 0 ? '-' : '+';
	s[1] = (char)('0' + hh / 10U % 10U);
	s[2] = (char)('0' + hh % 10U);
	s[3] = ':';
	s[4] = (char)('0' + mm / 10U);
	s[5] = (char)('0' + mm % 10U);
	return (int)STRLEN("+07:00");
}

int format_rfc3339(
	char *restrict s, const size_t maxlen, const time_t t, const int tzoff)
{
	/* Check representability before the buffer size so an unrepresentable
	 * time returns -1 even on a size query, instead of being masked by the
	 * snprintf-style needed-size return. */
	struct tm tm;
	if (!break_down(t, tzoff, &tm)) {
		if (maxlen > 0) {
			s[0] = '\0';
		}
		return -1;
	}
	const size_t need = tzoff == 0 ? STRLEN(LAYOUT_RFC3339_UTC) :
					 STRLEN(LAYOUT_RFC3339);
	if (maxlen < need + 1) {
		if (maxlen > 0) {
			s[0] = '\0';
		}
		return (int)need;
	}
	put_datetime(s, &tm);
	const int len = (int)STRLEN(LAYOUT_DATETIME) + put_zone(s + 19, tzoff);
	s[len] = '\0';
	return len;
}

int format_rfc3339nano(
	char *restrict s, const size_t maxlen,
	const struct timespec *restrict tp, const int tzoff)
{
	if (tp->tv_nsec < 0 || tp->tv_nsec > 999999999) {
		if (maxlen > 0) {
			s[0] = '\0';
		}
		return -1;
	}
	/* representability before buffer size (see format_rfc3339) */
	struct tm tm;
	if (!break_down(tp->tv_sec, tzoff, &tm)) {
		if (maxlen > 0) {
			s[0] = '\0';
		}
		return -1;
	}
	const size_t need = tzoff == 0 ? STRLEN(LAYOUT_RFC3339NANO_UTC) :
					 STRLEN(LAYOUT_RFC3339NANO);
	if (maxlen < need + 1) {
		if (maxlen > 0) {
			s[0] = '\0';
		}
		return (int)need;
	}
	put_datetime(s, &tm);
	s[19] = '.';
	int ns = (int)tp->tv_nsec;
	for (int i = 8; i >= 0; i--) {
		s[20 + i] = (char)('0' + ns % 10);
		ns /= 10;
	}
	const int len = (int)STRLEN(LAYOUT_DATETIME ".999999999") +
			put_zone(s + 29, tzoff);
	s[len] = '\0';
	return len;
}

int local_tzoff(const time_t t)
{
	/* Copy each result out before the next call: without _r, localtime and
	 * gmtime may share one static struct tm; the offset is then their
	 * wall-clock difference, correct for |offset| < 24h and DST-aware
	 * because localtime reflects the DST rule in effect at t. */
	const struct tm *p = LOCALTIME(&t);
	if (p == NULL) {
		return 0;
	}
	const struct tm lt = *p;
	p = GMTIME(&t);
	if (p == NULL) {
		return 0;
	}
	const struct tm gt = *p;
	int dday;
	if (lt.tm_year != gt.tm_year) {
		dday = lt.tm_year > gt.tm_year ? 1 : -1;
	} else {
		dday = lt.tm_yday - gt.tm_yday;
	}
	const int dhour = dday * 24 + (lt.tm_hour - gt.tm_hour);
	const int dmin = dhour * 60 + (lt.tm_min - gt.tm_min);
	return dmin * 60 + (lt.tm_sec - gt.tm_sec);
}

/* Days since 1970-01-01 for the proleptic-Gregorian date y-m-d (Howard
 * Hinnant's algorithm); m in [1, 12], d in [1, 31]. */
static int_least64_t
days_from_civil(int_least64_t y, const unsigned m, const unsigned d)
{
	y -= m <= 2;
	const int_least64_t era = (y >= 0 ? y : y - 399) / 400;
	const unsigned yoe = (unsigned)(y - era * 400);
	const unsigned doy =
		(153U * (m > 2 ? m - 3 : m + 9) + 2U) / 5U + d - 1U;
	const unsigned doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;
	return era * 146097 + (int_least64_t)doe - 719468;
}

time_t parse_rfc3339(const char *restrict tstamp)
{
	struct timespec tp;
	if (parse_rfc3339nano(&tp, tstamp) != 0) {
		return (time_t)-1;
	}
	return tp.tv_sec;
}

int parse_rfc3339nano(struct timespec *restrict tp, const char *restrict tstamp)
{
	enum { MAX_LEN = 64 };
	size_t len = strnlen(tstamp, MAX_LEN);
	if (len < STRLEN(LAYOUT_RFC3339_UTC) || len == MAX_LEN) {
		return -1;
	}
	const unsigned char *restrict s = (const unsigned char *)tstamp;
	if (!isdigit(s[0]) || !isdigit(s[1]) || !isdigit(s[2]) ||
	    !isdigit(s[3]) || s[4] != '-' || !isdigit(s[5]) || !isdigit(s[6]) ||
	    s[7] != '-' || !isdigit(s[8]) || !isdigit(s[9]) ||
	    (s[10] != 'T' && s[10] != 't') || !isdigit(s[11]) ||
	    !isdigit(s[12]) || s[13] != ':' || !isdigit(s[14]) ||
	    !isdigit(s[15]) || s[16] != ':' || !isdigit(s[17]) ||
	    !isdigit(s[18])) {
		return -1;
	}
	const int year = (s[0] - '0') * 1000 + (s[1] - '0') * 100 +
			 (s[2] - '0') * 10 + (s[3] - '0');
	const int mon = (s[5] - '0') * 10 + (s[6] - '0');
	const int mday = (s[8] - '0') * 10 + (s[9] - '0');
	const int hour = (s[11] - '0') * 10 + (s[12] - '0');
	const int min = (s[14] - '0') * 10 + (s[15] - '0');
	const int sec = (s[17] - '0') * 10 + (s[18] - '0');
	if (year < 1000 || mon < 1 || mon > 12 || mday < 1 || hour > 23 ||
	    min > 59 || sec > 60) {
		return -1;
	}
	/* reject impossible calendar dates: mon is valid now, so index its
	 * length and widen February in a leap year, rather than letting
	 * days_from_civil silently normalize e.g. 2023-02-29 into March. */
	static const int mdays[12] = { 31, 28, 31, 30, 31, 30,
				       31, 31, 30, 31, 30, 31 };
	int maxday = mdays[mon - 1];
	if (mon == 2 &&
	    ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0)) {
		maxday = 29;
	}
	if (mday > maxday) {
		return -1;
	}
	s += 19, len -= 19;

	long nsec = 0;
	if (s[0] == '.') {
		++s, --len;
		if (len == 0 || !isdigit(s[0])) {
			return -1;
		}
		/* first fractional digit is 1e8 ns; drop digits past nanos */
		for (long scale = 100000000L; len > 0 && isdigit(s[0]);
		     ++s, --len) {
			if (scale > 0) {
				nsec += (long)(s[0] - '0') * scale;
				scale /= 10;
			}
		}
	}

	int offset = 0;
	switch (s[0]) {
	/* RFC 3339 section 5.6 NOTE: the 'T' and 'Z' separators may also be
	 * lower case, so both spellings are accepted here and at s[10] above.
	 * The formatter still emits only the upper-case forms. */
	case 'Z':
	case 'z':
		if (len != STRLEN("Z")) {
			return -1;
		}
		break;
	case '+':
	case '-': {
		const int sign = s[0] == '-' ? -1 : 1;
		++s, --len;
		/* "HH", "HHMM", or "HH:MM" */
		if (len != 2 && len != 4 && len != 5) {
			return -1;
		}
		if (!isdigit(s[0]) || !isdigit(s[1])) {
			return -1;
		}
		const int oh = (s[0] - '0') * 10 + (s[1] - '0');
		s += 2, len -= 2;
		int om = 0;
		if (len > 0) {
			if (s[0] == ':') {
				++s, --len;
			}
			if (len != 2 || !isdigit(s[0]) || !isdigit(s[1])) {
				return -1;
			}
			om = (s[0] - '0') * 10 + (s[1] - '0');
		}
		/* RFC 3339 time-numoffset: time-hour is 00-23 and time-minute
		 * 00-59, the same bounds the time-of-day fields above check.
		 * Without this, "+99:99" parses and shifts the instant by a
		 * span no zone has. */
		if (oh > 23 || om > 59) {
			return -1;
		}
		offset = sign * (oh * 3600 + om * 60);
	} break;
	default:
		return -1;
	}

	const int_least64_t days =
		days_from_civil(year, (unsigned)mon, (unsigned)mday);
	const int_least64_t epoch =
		days * 86400 + (hour * 3600 + min * 60 + sec) - offset;
	if (!fits_time_t(epoch)) {
		return -1;
	}
	tp->tv_sec = (time_t)epoch;
	tp->tv_nsec = nsec;
	return 0;
}
