/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "intlog2.h"

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

const int intlog2_debruijn_bsr32[32] = {
	0, 9,  1,  10, 13, 21, 2,  29, 11, 14, 16, 18, 22, 25, 3, 30,
	8, 12, 20, 28, 15, 17, 24, 7,  19, 27, 23, 6,  26, 5,  4, 31,
};

const int intlog2_debruijn_bsf32[32] = {
	0,  1,	28, 2,	29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4,  8,
	31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6,  11, 5,  10, 9,
};

const int intlog2_debruijn_bsr64[64] = {
	0,  47, 1,  56, 48, 27, 2,  60, 57, 49, 41, 37, 28, 16, 3,  61,
	54, 58, 35, 52, 50, 42, 21, 44, 38, 32, 29, 23, 17, 11, 4,  62,
	46, 55, 26, 59, 40, 36, 15, 53, 34, 51, 20, 43, 31, 22, 10, 45,
	25, 39, 14, 33, 19, 30, 9,  24, 13, 18, 8,  12, 7,  6,	5,  63,
};

const int intlog2_debruijn_bsf64[64] = {
	0,  1,	2,  36, 3,  47, 59, 37, 44, 4,	7,  48, 60, 30, 54, 38,
	34, 45, 5,  28, 26, 8,	49, 10, 61, 51, 31, 19, 55, 22, 39, 12,
	63, 35, 46, 58, 43, 6,	29, 53, 33, 27, 25, 9,	50, 18, 21, 11,
	62, 57, 42, 52, 32, 24, 17, 20, 56, 41, 23, 16, 40, 15, 14, 13,
};

/* Width (number of bits) of uintmax_t on this platform. */
#define UINTMAX_W ((int)(sizeof(uintmax_t) * (size_t)CHAR_BIT))

/*
 * --- Width-generic De Bruijn generator ---
 *
 * Builds a binary De Bruijn sequence B(2, k) and the BSR/BSF lookup tables
 * derived from it, for any width w = 2^k with w <= UINTMAX_W. Used at
 * runtime by the wide-uintmax_t path below (only compiled when uintmax_t
 * is wider than unsigned long long), and exercised directly by
 * intlog2_test.c at several widths on every platform, regardless of
 * native uintmax_t width. External linkage with an intlog2_ prefix (but
 * no public header entry) so the test binary, which links this
 * translation unit directly, can call them without exposing them as
 * public API.
 */

/* Mask selecting the low w bits of a uintmax_t (w <= UINTMAX_W). */
static uintmax_t low_bits_mask(int w)
{
	return (w < UINTMAX_W) ? (((uintmax_t)1 << w) - 1) : (uintmax_t)-1;
}

/*
 * Recursive step of the FKT (Fredricksen-Kessler-Maiorana) algorithm:
 * depth-first visits every binary necklace representative for period n,
 * appending each cycle's first p symbols to *seq at *pos whenever
 * n % p == 0 (the classic construction of the lexicographically-least
 * De Bruijn sequence). a[1..n] holds the string built so far; a[0] is a
 * fixed 0 sentinel. Recursion depth is exactly n+1 - trivially bounded,
 * since n is the log2 of a bit-width.
 */
static void fkt_visit(int t, int p, int n, int a[], uintmax_t *seq, int *pos)
{
	if (t > n) {
		if (n % p == 0) {
			for (int j = 1; j <= p; j++) {
				if (a[j]) {
					*seq |= (uintmax_t)1 << *pos;
				}
				(*pos)++;
			}
		}
		return;
	}
	a[t] = a[t - p];
	fkt_visit(t + 1, p, n, a, seq, pos);
	for (int j = a[t - p] + 1; j <= 1; j++) {
		a[t] = j;
		fkt_visit(t + 1, t, n, a, seq, pos);
	}
}

/*
 * Generate a binary De Bruijn sequence B(2, k) packed into the low 2^k
 * bits of an uintmax_t (LSB = position 0).
 */
uintmax_t intlog2_fkt_gen(int k)
{
	int a[UINTMAX_W + 1] = { 0 };
	uintmax_t seq = 0;
	int pos = 0;
	fkt_visit(1, 1, k, a, &seq, &pos);
	return seq;
}

/*
 * Verify that De Bruijn constant M can serve as a BSF constant for width w,
 * filling table[] as a side effect. BSF looks up (x & -x), always a power
 * of 2, via a plain (non-rotating) shift - (M << p) mod 2^w, then the top
 * k bits - to match countr_zeromax()'s multiply-shift lookup exactly. That
 * plain shift only agrees with a true cyclic rotation of M for p that
 * doesn't shift any of M's top (k-1) bits out, so - contrary to the common
 * claim that any De Bruijn sequence works for BSF - only the rotations
 * whose top (k-1) bits are 0 give a collision-free table; the rest
 * silently alias two positions onto the same index.
 * Returns true if M gives distinct table indices for all p.
 */
static bool verify_bsf(uintmax_t M, int w, int k, int table[])
{
	/* k >= 1 (not just k >= 0) so shift = w - k never reaches
	 * UINTMAX_W itself: shifting a full type width is UB too. */
	assert(k >= 1 && k < w && w <= UINTMAX_W);
	bool seen[UINTMAX_W] = { false };
	uintmax_t mask = low_bits_mask(w);
	int shift = w - k;
	for (int p = 0; p < w; p++) {
		/* Left shift by p, reduced mod 2^w, then take the top k bits. */
		uintmax_t idx = ((M << p) & mask) >> shift;
		if (seen[idx]) {
			return false;
		}
		seen[idx] = true;
		table[idx] = p;
	}
	return true;
}

/*
 * Verify that De Bruijn constant M can serve as a BSR constant for width w.
 * BSR uses the filled value v = (2^w - 1) >> (w-1-p), which is NOT a power
 * of 2, so not every De Bruijn sequence works; we must verify.
 * Returns true if M gives distinct table indices for all p.
 */
static bool verify_bsr(uintmax_t M, int w, int k, int table[])
{
	/* k >= 1 (not just k >= 0) so shift = w - k never reaches
	 * UINTMAX_W itself: shifting a full type width is UB too. */
	assert(k >= 1 && k < w && w <= UINTMAX_W);
	bool seen[UINTMAX_W] = { false };
	uintmax_t mask = low_bits_mask(w);
	int shift = w - k;
	for (int p = 0; p < w; p++) {
		/* filled = 2^(p+1) - 1: all ones up to and including bit p,
		 * reduced mod 2^w. */
		uintmax_t filled =
			(p + 1 < w) ? (((uintmax_t)1 << (p + 1)) - 1) : mask;
		uintmax_t product = (M * filled) & mask;
		uintmax_t idx = product >> shift;
		if (seen[idx]) {
			return false;
		}
		seen[idx] = true;
		table[idx] = p;
	}
	return true;
}

/*
 * Find a rotation of the base FKT(k) sequence that verify() accepts as a
 * De Bruijn constant for width w (a power of 2), filling table[] as a
 * side effect. At least one rotation always works for a valid 2^k De
 * Bruijn sequence; returns the found constant.
 */
static uintmax_t find_rotated_const(
	int w, int k, int table[], bool (*verify)(uintmax_t, int, int, int *))
{
	uintmax_t mask = low_bits_mask(w);
	uintmax_t base = intlog2_fkt_gen(k) & mask;
	for (int rot = 0; rot < w; rot++) {
		/* Rotating right by 0 is the identity; the general formula
		 * below would otherwise shift left by w, which is UB when
		 * w == UINTMAX_W. */
		uintmax_t M =
			(rot == 0) ?
				base :
				(((base >> rot) | (base << (w - rot))) & mask);
		if (verify(M, w, k, table)) {
			return M;
		}
	}
	/* Unreachable for valid De Bruijn input and power-of-2 width. */
	return 0;
}

/*
 * Find a BSF-compatible De Bruijn constant for width w. See verify_bsf()
 * for why - unlike BSR - only some rotations of the base sequence work.
 */
uintmax_t intlog2_find_bsf_const(int w, int k, int table[])
{
	return find_rotated_const(w, k, table, verify_bsf);
}

/* Find a BSR-compatible De Bruijn constant for width w. */
uintmax_t intlog2_find_bsr_const(int w, int k, int table[])
{
	return find_rotated_const(w, k, table, verify_bsr);
}

#if UINTMAX_MAX > ULLONG_MAX

#include <threads.h>

/* --- Runtime De Bruijn for arbitrary-width uintmax_t --- */

/* Thread-local De Bruijn state for wide uintmax_t. */
static thread_local struct {
	bool init;
	bool use_db; /* false when UINTMAX_W is not a power of 2 */
	int shift;
	uintmax_t bsr_const;
	uintmax_t bsf_const;
	int bsr_table[UINTMAX_W];
	int bsf_table[UINTMAX_W];
} tl_db;

/* Initialise tl_db on first call in this thread. */
static void init_tl_db(void)
{
	if (tl_db.init) {
		return;
	}
	tl_db.init = true;

	int w = UINTMAX_W;
	/* k = log2(w); valid only when w is a power of 2. */
	int k = 0;
	for (int tmp = w; tmp > 1; tmp >>= 1) {
		k++;
	}
	if ((1 << k) != w) {
		/* Non-power-of-2 width: fall back to binary search. */
		tl_db.use_db = false;
		return;
	}
	tl_db.use_db = true;
	tl_db.shift = w - k;

	/* BSF and BSR constants each need a rotation that verify_bsf()/
	 * verify_bsr() accepts - see find_rotated_const(). */
	tl_db.bsf_const = intlog2_find_bsf_const(w, k, tl_db.bsf_table);
	tl_db.bsr_const = intlog2_find_bsr_const(w, k, tl_db.bsr_table);
}

/* Binary-search fallback for BSR (O(log w), used when w is not 2^k). */
static int bsr_bisect(uintmax_t x)
{
	int result = 0;
	int w = UINTMAX_W;
	for (int half = w >> 1; half > 0; half >>= 1) {
		if (x >> half) {
			result += half;
			x >>= half;
		}
	}
	return result;
}

int log2umax(uintmax_t x)
{
	assert(x > 0);
	init_tl_db();
	if (tl_db.use_db) {
		int w = UINTMAX_W;
		uintmax_t v = x;
		for (int s = 1; s < w; s <<= 1) {
			v |= v >> s;
		}
		return tl_db.bsr_table[(tl_db.bsr_const * v) >> tl_db.shift];
	}
	return bsr_bisect(x);
}

int countr_zeromax(uintmax_t x)
{
	assert(x > 0);
	init_tl_db();
	if (tl_db.use_db) {
		uintmax_t lsb = x & (uintmax_t)(-x);
		return tl_db.bsf_table[(tl_db.bsf_const * lsb) >> tl_db.shift];
	}
	/* log2(x & -x) == ctz(x) for any nonzero x. Isolate the lowest set bit
	 * with unsigned negation; converting to intmax_t first and negating
	 * INTMAX_MIN (an MSB-only x) would be signed-overflow UB. */
	return bsr_bisect(x & (uintmax_t)(-x));
}

int countl_zeromax(uintmax_t x)
{
	if (x == 0) {
		return UINTMAX_W;
	}
	return UINTMAX_W - 1 - log2umax(x);
}

#endif /* UINTMAX_MAX > ULLONG_MAX */

#undef UINTMAX_W
