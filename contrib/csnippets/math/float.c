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
