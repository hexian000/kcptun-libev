/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "float.h"

#include <assert.h>
#include <float.h>
#include <stdbool.h>
#include <stdint.h>

static_assert(sizeof(double) == 8, "IEEE 754 binary64 required");
static_assert(FLT_RADIX == 2, "IEEE 754 binary64 required");
static_assert(DBL_MANT_DIG == 53, "IEEE 754 binary64 required");

union dbits {
	double d;
	uint64_t u;
};

uint64_t float_tobits(const double x)
{
	/* type punning through a union is well-defined in ISO C */
	return (union dbits){ .d = x }.u;
}

double float_frombits(const uint64_t bits)
{
	return (union dbits){ .u = bits }.d;
}

enum float_class float_classify(const double x)
{
	const uint64_t u = float_tobits(x);
	const uint32_t be = (uint32_t)(u >> 52) & 0x7FF;
	const uint64_t frac = u & ((UINT64_C(1) << 52) - 1);
	if (be == 0x7FF) {
		return frac != 0 ? FLOAT_NAN : FLOAT_INF;
	}
	if (be == 0) {
		return frac != 0 ? FLOAT_SUBNORMAL : FLOAT_ZERO;
	}
	return FLOAT_NORMAL;
}

bool float_signbit(const double x)
{
	return (float_tobits(x) >> 63) != 0;
}

uint64_t float_decompose(const double x, int *const e2)
{
	const uint64_t u = float_tobits(x);
	const int be = (int)((u >> 52) & 0x7FF);
	const uint64_t frac = u & ((UINT64_C(1) << 52) - 1);
	if (be == 0) {
		/* zero or subnormal: no implicit bit */
		*e2 = -1074;
		return frac;
	}
	/* unbias, then shift the point past the 52 fraction bits */
	*e2 = be - 1075;
	return frac | (UINT64_C(1) << 52);
}

/* --- correctly-rounded decimal conversion --------------------------------- *
 * Exact big-integer method with base-10^9 limbs, after musl's fmt_fp
 * (src/stdio/vfprintf.c, MIT). The finite value M * 2^E is held exactly as
 * N * (10^9)^scale, so folding 2^E in needs only multiplication/division by
 * small powers of two, never general bignum division.
 */

#define LIMB_BASE UINT32_C(1000000000)
#define LIMB_DIGITS 9

/* fits the exact expansion at either extreme (integer part of DBL_MAX,
 * fraction of 2^-1074) with margin */
enum {
	BIGLEN = (DBL_MANT_DIG + 28) / 29 + 1 +
		 (DBL_MAX_EXP + DBL_MANT_DIG + 28 + 8) / 9
};

struct bignum {
	uint32_t limb[BIGLEN]; /* base-10^9, most significant at limb[a] */
	int a, z; /* live region [a, z) */
	int scale; /* value = N * (10^9)^scale */
};

static const uint32_t pow10[LIMB_DIGITS] = {
	1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000,
};

/* N *= 2^sh; sh <= 29 keeps limb << sh + carry within uint64_t */
static void mul_pow2(struct bignum *restrict bn, const int sh)
{
	uint32_t carry = 0;
	for (int i = bn->z - 1; i >= bn->a; i--) {
		const uint64_t v = ((uint64_t)bn->limb[i] << sh) + carry;
		bn->limb[i] = (uint32_t)(v % LIMB_BASE);
		carry = (uint32_t)(v / LIMB_BASE);
	}
	if (carry != 0) {
		/* carry < 2^29 + 1 < 10^9: at most one new leading limb */
		assert(bn->a > 0);
		bn->limb[--bn->a] = carry;
	}
}

/* N /= 2^sh; sh <= 9, so 10^9 == 2^9 * 5^9 lets one appended limb absorb
 * the remainder exactly */
static void div_pow2(struct bignum *restrict bn, const int sh)
{
	const uint32_t mask = (UINT32_C(1) << sh) - 1;
	uint32_t rem = 0;
	for (int i = bn->a; i < bn->z; i++) {
		const uint64_t v = (uint64_t)rem * LIMB_BASE + bn->limb[i];
		bn->limb[i] = (uint32_t)(v >> sh);
		rem = (uint32_t)v & mask;
	}
	while (bn->a < bn->z && bn->limb[bn->a] == 0) {
		bn->a++;
	}
	if (rem != 0) {
		const uint64_t v = (uint64_t)rem * LIMB_BASE;
		assert(bn->z < BIGLEN);
		bn->limb[bn->z++] = (uint32_t)(v >> sh);
		bn->scale--;
	}
}

static void load(struct bignum *restrict bn, const uint64_t m, const int e2)
{
	bn->scale = 0;
	if (e2 >= 0) {
		/* only mul_pow2 follows: grow leftward from the right end */
		bn->a = bn->z = BIGLEN;
		uint64_t v = m;
		do {
			bn->limb[--bn->a] = (uint32_t)(v % LIMB_BASE);
			v /= LIMB_BASE;
		} while (v != 0);
	} else {
		/* only div_pow2 follows: grow rightward from the left end */
		uint32_t tmp[3];
		int n = 0;
		uint64_t v = m;
		do {
			tmp[n++] = (uint32_t)(v % LIMB_BASE);
			v /= LIMB_BASE;
		} while (v != 0);
		for (int i = 0; i < n; i++) {
			bn->limb[i] = tmp[n - 1 - i];
		}
		bn->a = 0, bn->z = n;
	}
	for (int e = e2; e > 0;) {
		const int sh = e < 29 ? e : 29;
		mul_pow2(bn, sh);
		e -= sh;
	}
	for (int e = e2; e < 0;) {
		const int sh = -e < 9 ? -e : 9;
		div_pow2(bn, sh);
		e += sh;
	}
	/* trim trailing zero limbs: N /= 10^9, value preserved via scale */
	while (bn->z - bn->a > 1 && bn->limb[bn->z - 1] == 0) {
		bn->z--;
		bn->scale++;
	}
}

static int limb_digits(const uint32_t v)
{
	int n = 1;
	while (n < LIMB_DIGITS && v >= pow10[n]) {
		n++;
	}
	return n;
}

/* digit at 1-based position pos, counted from the most significant digit;
 * pad is the count of implied leading zeros in limb[a] */
static int
digit_at(const struct bignum *restrict bn, const int pad, const int pos)
{
	const int j = pad + pos - 1;
	const int idx = bn->a + j / LIMB_DIGITS;
	assert(idx < bn->z);
	return (int)(bn->limb[idx] / pow10[LIMB_DIGITS - 1 - j % LIMB_DIGITS] %
		     10);
}

/* any nonzero digit strictly below position pos */
static bool
rest_nonzero(const struct bignum *restrict bn, const int pad, const int pos)
{
	const int j = pad + pos - 1;
	const int idx = bn->a + j / LIMB_DIGITS;
	if (bn->limb[idx] % pow10[LIMB_DIGITS - 1 - j % LIMB_DIGITS] != 0) {
		return true;
	}
	for (int i = idx + 1; i < bn->z; i++) {
		if (bn->limb[i] != 0) {
			return true;
		}
	}
	return false;
}

int float_todecimal(
	const double x, const int ndigits, char *const digits,
	int *const dec_exp)
{
	int e2;
	const uint64_t m = float_decompose(x, &e2);
	if (m == 0) {
		*dec_exp = 0;
		return 0;
	}
	struct bignum bn;
	load(&bn, m, e2);
	/* N != 0: the live region is never empty */
	assert(bn.a < bn.z);
	const int t = limb_digits(bn.limb[bn.a]);
	const int pad = LIMB_DIGITS - t;
	const int count = t + LIMB_DIGITS * (bn.z - 1 - bn.a);
	int tz = 0;
	for (uint32_t v = bn.limb[bn.z - 1]; v != 0 && v % 10 == 0; v /= 10) {
		tz++;
	}
	/* significant length of the exact expansion */
	const int sig = count - tz;
	assert(0 < sig && sig <= FLOAT_DECIMAL_DIGITS);
	int k = count + LIMB_DIGITS * bn.scale;
	if (ndigits <= 0) {
		/* every digit dropped; the value may still round up to 10^k */
		if (ndigits == 0) {
			const int d1 = digit_at(&bn, pad, 1);
			if (d1 > 5 || (d1 == 5 && rest_nonzero(&bn, pad, 1))) {
				digits[0] = '1';
				*dec_exp = k + 1;
				return 1;
			}
		}
		*dec_exp = k;
		return 0;
	}
	int n = ndigits < sig ? ndigits : sig;
	for (int i = 0; i < n; i++) {
		digits[i] = (char)('0' + digit_at(&bn, pad, i + 1));
	}
	if (n < sig) {
		/* round-half-even: the tie test scans every remaining digit */
		const int next = digit_at(&bn, pad, n + 1);
		bool up = next > 5;
		if (next == 5) {
			up = rest_nonzero(&bn, pad, n + 1) ||
			     (digits[n - 1] - '0') % 2 != 0;
		}
		if (up) {
			int i = n - 1;
			for (; i >= 0 && digits[i] == '9'; i--) {
				digits[i] = '0';
			}
			if (i >= 0) {
				digits[i]++;
			} else {
				/* carry out of the leading digit */
				digits[0] = '1';
				k++;
			}
		}
	}
	while (n > 0 && digits[n - 1] == '0') {
		n--;
	}
	*dec_exp = k;
	return n;
}

/* --- correctly-rounded decimal parsing ------------------------------------ *
 * Read-side companion to float_todecimal. The significand is held exactly in a
 * base-2^32 big integer, so the rounded 53-bit mantissa with its guard/round/
 * sticky bits falls out of shifts, a multiply by 5^e (e >= 0), or one exact
 * divide by 5^-e (e < 0). Pure integer rounding: no libc, no FPU rounding.
 */

/* powers of five that stay below 2^31, for chunked multiply/divide */
static const uint32_t pow5[] = {
	1,     5,      25,	125,	 625,	   3125,      15625,
	78125, 390625, 1953125, 9765625, 48828125, 244140625, 1220703125,
};

/* the significand fills at most FLOAT_DECIMAL_DIGITS digits (~2548 bits); the
 * e < 0 path shifts it left by ~5^-e's bit length before the divide, so ~2600
 * bits with margin */
enum { BINLIMBS = FLOAT_DECIMAL_DIGITS / 8 + 32 };

struct binint {
	uint32_t limb[BINLIMBS]; /* base-2^32, least significant at limb[0] */
	int len; /* live limbs; 0 iff the value is zero */
};

/* b = b * mul + add (both small) */
static void
binint_muladd(struct binint *restrict b, const uint32_t mul, const uint32_t add)
{
	uint64_t carry = add;
	for (int i = 0; i < b->len; i++) {
		const uint64_t v = (uint64_t)b->limb[i] * mul + carry;
		b->limb[i] = (uint32_t)v;
		carry = v >> 32;
	}
	while (carry != 0) {
		assert(b->len < BINLIMBS);
		b->limb[b->len++] = (uint32_t)carry;
		carry >>= 32;
	}
}

/* b /= d; returns the remainder */
static uint32_t binint_divmod(struct binint *restrict b, const uint32_t d)
{
	uint64_t rem = 0;
	for (int i = b->len - 1; i >= 0; i--) {
		const uint64_t cur = (rem << 32) | b->limb[i];
		b->limb[i] = (uint32_t)(cur / d);
		rem = cur % d;
	}
	while (b->len > 0 && b->limb[b->len - 1] == 0) {
		b->len--;
	}
	return (uint32_t)rem;
}

/* b <<= sh (sh >= 0) */
static void binint_shl(struct binint *restrict b, const int sh)
{
	if (b->len == 0 || sh == 0) {
		return;
	}
	const int words = sh / 32;
	const int bits = sh % 32;
	const int newlen = b->len + words + 1;
	assert(newlen <= BINLIMBS);
	/* high to low so each source limb is read before it is overwritten */
	for (int j = newlen - 1; j >= 0; j--) {
		const int s = j - words;
		const uint32_t lo = (s >= 0 && s < b->len) ? b->limb[s] : 0;
		const uint32_t hi =
			(s - 1 >= 0 && s - 1 < b->len) ? b->limb[s - 1] : 0;
		b->limb[j] = (uint32_t)(lo << bits) |
			     (bits != 0 ? hi >> (32 - bits) : 0);
	}
	b->len = newlen;
	while (b->len > 0 && b->limb[b->len - 1] == 0) {
		b->len--;
	}
}

static int binint_bitlen(const struct binint *restrict b)
{
	if (b->len == 0) {
		return 0;
	}
	int bits = 0;
	for (uint32_t top = b->limb[b->len - 1]; top != 0; top >>= 1) {
		bits++;
	}
	return (b->len - 1) * 32 + bits;
}

static int binint_bit(const struct binint *restrict b, const int pos)
{
	const int i = pos / 32;
	if (i >= b->len) {
		return 0;
	}
	return (int)((b->limb[i] >> (pos % 32)) & 1u);
}

/* any set bit strictly below position pos */
static bool binint_low_nonzero(const struct binint *restrict b, const int pos)
{
	const int i = pos / 32;
	for (int j = 0; j < i && j < b->len; j++) {
		if (b->limb[j] != 0) {
			return true;
		}
	}
	if (i < b->len) {
		const uint32_t mask =
			(pos % 32) != 0 ? (UINT32_C(1) << (pos % 32)) - 1 : 0;
		if ((b->limb[i] & mask) != 0) {
			return true;
		}
	}
	return false;
}

/* floor(b / 2^sh) truncated to 64 bits; the caller guarantees it fits */
static uint64_t binint_shr_u64(const struct binint *restrict b, const int sh)
{
	const int i = sh / 32;
	const int r = sh % 32;
	const uint64_t l0 = (i >= 0 && i < b->len) ? b->limb[i] : 0;
	const uint64_t l1 = (i + 1 >= 0 && i + 1 < b->len) ? b->limb[i + 1] : 0;
	if (r == 0) {
		return l0 | (l1 << 32);
	}
	const uint64_t l2 = (i + 2 >= 0 && i + 2 < b->len) ? b->limb[i + 2] : 0;
	return (l0 >> r) | (l1 << (32 - r)) | (l2 << (64 - r));
}

/* b << sh as a 64-bit value; the caller guarantees b has <= 53 bits */
static uint64_t binint_shl_u64(const struct binint *restrict b, const int sh)
{
	assert(0 <= sh && sh < 64);
	uint64_t v = 0;
	for (int i = b->len - 1; i >= 0; i--) {
		v = (v << 32) | b->limb[i];
	}
	return v << sh;
}

/* Round the exact value x * 2^p (x != 0, plus a positive tail below 2^p iff
 * sticky_tail) to the nearest binary64 magnitude, round-half-even. */
static double
assemble(const struct binint *restrict x, const int p, const bool sticky_tail)
{
	const int bl = binint_bitlen(x);
	int expb = bl + p + 1022; /* biased exponent for a normal mantissa */
	int drop = bl - 53; /* x bits to drop for 53 significant bits */
	if (expb < 1) {
		/* subnormal: the least significant bit is fixed at 2^-1074 */
		drop = -1074 - p;
		expb = 0;
	}
	uint64_t m;
	int roundbit = 0;
	bool sticky = sticky_tail;
	if (drop <= 0) {
		m = binint_shl_u64(x, -drop);
	} else {
		m = binint_shr_u64(x, drop);
		roundbit = binint_bit(x, drop - 1);
		sticky = sticky || binint_low_nonzero(x, drop - 1);
	}
	if (roundbit != 0 && (sticky || (m & 1) != 0)) {
		m++;
	}
	if (expb == 0) {
		/* m in [0, 2^52]; m == 2^52 carries into the exponent field */
		return float_frombits(m);
	}
	if (m == (UINT64_C(1) << 53)) {
		/* rounding overflowed the mantissa: 1.11..1 -> 10.0 */
		m >>= 1;
		expb++;
	}
	if (expb >= 2047) {
		return float_frombits(UINT64_C(0x7FF) << 52); /* +inf */
	}
	return float_frombits(
		(uint64_t)expb << 52 | (m & ((UINT64_C(1) << 52) - 1)));
}

double float_fromdecimal(
	const char *const digits, const int ndigits, const int dec_exp)
{
	/* leading zeros do not change the integer significand; trailing zeros
	 * only shift the exponent */
	int lo = 0;
	while (lo < ndigits && digits[lo] == '0') {
		lo++;
	}
	if (lo == ndigits) {
		return 0.0;
	}
	int hi = ndigits;
	while (hi > lo && digits[hi - 1] == '0') {
		hi--;
	}
	/* value in [10^(mag-1), 10^mag). Neither dec_exp nor the digit count is
	 * restricted, and dec_exp - hi overflows int at the extremes, so reach
	 * the magnitude the other way round -- it is exactly dec_exp - lo -- and
	 * compute it wide enough that nothing can wrap. */
	const int_fast64_t mag = (int_fast64_t)dec_exp - lo;
	if (mag > 309) {
		return float_frombits(UINT64_C(0x7FF) << 52); /* +inf */
	}
	if (mag < -323) {
		return 0.0; /* below 2^-1075, rounds to zero */
	}
	/* Correct rounding never needs more significant digits than
	 * float_todecimal can emit; beyond that the tail only has to be known to
	 * be nonzero, which sticky carries into assemble(). Dropping it is also
	 * what holds the binint inside BINLIMBS, sized for exactly that many
	 * digits. Trailing zeros are already gone, so a dropped tail ends in a
	 * nonzero digit and is never all zero. */
	bool sticky = false;
	if (hi - lo > FLOAT_DECIMAL_DIGITS) {
		hi = lo + FLOAT_DECIMAL_DIGITS;
		sticky = true;
	}
	/* value = D * 10^e10, D = integer(digits[lo..hi)); mag is within
	 * [-323, 309] and nd within [1, FLOAT_DECIMAL_DIGITS], so e10 lands
	 * well inside int */
	const int nd = hi - lo;
	const int e10 = (int)(mag - nd);
	struct binint x = { .len = 0 };
	for (int t = lo; t < hi; t++) {
		binint_muladd(&x, 10, (uint32_t)(digits[t] - '0'));
	}
	int p;
	if (e10 >= 0) {
		for (int e = e10; e > 0;) {
			const int c = e < 13 ? e : 13;
			binint_muladd(&x, pow5[c], 0);
			e -= c;
		}
		p = e10;
	} else {
		const int k = -e10;
		/* leave floor(D << g / 5^k) with ~55 significant bits; the divide
		 * folds every lower bit into the sticky flag */
		const int bits5k =
			(int)(((int64_t)k * 2321929 + 999999) / 1000000) + 1;
		int g = bits5k + 55 - binint_bitlen(&x);
		if (g < 0) {
			g = 0;
		}
		binint_shl(&x, g);
		for (int e = k; e > 0;) {
			const int c = e < 13 ? e : 13;
			if (binint_divmod(&x, pow5[c]) != 0) {
				sticky = true;
			}
			e -= c;
		}
		p = e10 - g;
	}
	if (x.len == 0) {
		return 0.0;
	}
	return assemble(&x, p, sticky);
}
