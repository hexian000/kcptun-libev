/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "intlog2.h"

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

#if UINTMAX_MAX > ULLONG_MAX

#include <threads.h>

/* --- Runtime De Bruijn for arbitrary-width uintmax_t --- */

/* Width (number of bits) of uintmax_t on this platform. */
#define UINTMAX_W ((int)(sizeof(uintmax_t) * (size_t)CHAR_BIT))

/*
 * FKT algorithm: generate a binary De Bruijn sequence B(2, k) packed into the
 * low UINTMAX_W bits of an uintmax_t (LSB = position 0).
 *
 * Uses a fixed-size working array of depth k <= DBMAX_K; no heap allocation.
 * Returns the De Bruijn word with the sequence packed LSB-first.
 */
static uintmax_t fkt_gen(int k)
{
	/* a[i] holds the current string during FKT recursion. */
	int a[UINTMAX_W + 1];
	for (int i = 0; i <= UINTMAX_W; i++) {
		a[i] = 0;
	}
	int w = 1 << k; /* sequence length = 2^k */
	uintmax_t seq = 0;
	int pos = 0;

	/* Iterative FKT via explicit stack: (n, t) pairs. */
	typedef struct {
		int n, t;
	} frame_t;
	frame_t stack[UINTMAX_W + 1];
	int top = 0;
	stack[top++] = (frame_t){ .n = k, .t = 1 };

	while (top > 0) {
		frame_t f = stack[--top];
		int n = f.n, t = f.t;
		if (n == 0) {
			if (k % t == 0) {
				for (int j = 1; j <= t && pos < w; j++, pos++) {
					if (a[j]) {
						seq |= (uintmax_t)1 << pos;
					}
				}
			}
		} else {
			/* Push continuation first (LIFO), then recurse. */
			for (int j = a[n - t]; j <= 1; j++) {
				/* push (n-1, t) with a[n]=j */
				if (top < UINTMAX_W + 1) {
					a[n] = j;
					stack[top++] = (frame_t){
						.n = n - 1,
						.t = (j == a[n - t]) ? t : n
					};
				}
			}
		}
	}
	return seq;
}

/*
 * Build the BSF lookup table for a given De Bruijn constant M of width w.
 * For BSF, (x & -x) is always a power of 2, so (M << p) >> (w-k) gives
 * distinct indices for all 0 <= p < w; any De Bruijn sequence works.
 */
static void build_bsf_table(uintmax_t M, int w, int k, int table[])
{
	for (int p = 0; p < w; p++) {
		/* Logical left shift by p, then take top k bits. */
		int shift = w - k;
		uintmax_t idx = (M << p) >> shift;
		table[idx] = p;
	}
}

/*
 * Verify that De Bruijn constant M can serve as a BSR constant for width w.
 * BSR uses the filled value v = (uintmax_t)-1 >> (w-1-p), which is NOT a
 * power of 2, so not every De Bruijn sequence works; we must verify.
 * Returns true if M gives distinct table indices for all p.
 */
static bool verify_bsr(uintmax_t M, int w, int k, int table[])
{
	bool seen[UINTMAX_W] = { false };
	for (int p = 0; p < w; p++) {
		/* filled = 2^(p+1) - 1: all ones up to and including bit p */
		uintmax_t filled = (p + 1 < w) ?
					   (((uintmax_t)1 << (p + 1)) - 1) :
					   (uintmax_t)-1;
		int shift = w - k;
		uintmax_t product = M * filled;
		uintmax_t idx = product >> shift;
		if (seen[idx]) {
			return false;
		}
		seen[idx] = true;
		table[p] = (int)idx;
	}
	return true;
}

/*
 * Find a BSR-compatible De Bruijn constant for width w (must be a power of 2).
 * Generates a base sequence via FKT, then tries cyclic rotations until one
 * satisfies verify_bsr(). At least one rotation always works for 2^k De Bruijn
 * sequences; returns the found constant (never fails for valid k).
 */
static uintmax_t find_bsr_const(int w, int k, int table[])
{
	uintmax_t base = fkt_gen(k);
	uintmax_t mask =
		(w < UINTMAX_W) ? (((uintmax_t)1 << w) - 1) : (uintmax_t)-1;
	for (int rot = 0; rot < w; rot++) {
		uintmax_t M = ((base >> rot) | (base << (w - rot))) & mask;
		if (verify_bsr(M, w, k, table)) {
			return M;
		}
	}
	/* Unreachable for valid De Bruijn input and power-of-2 width. */
	return 0;
}

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
static void tl_db_init(void)
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

	/* BSF constant: any De Bruijn sequence works. */
	uintmax_t bsf_seq = fkt_gen(k);
	uintmax_t mask =
		(w < UINTMAX_W) ? (((uintmax_t)1 << w) - 1) : (uintmax_t)-1;
	tl_db.bsf_const = bsf_seq & mask;
	build_bsf_table(tl_db.bsf_const, w, k, tl_db.bsf_table);

	/* BSR constant: need a rotation that satisfies verify_bsr. */
	tl_db.bsr_const = find_bsr_const(w, k, tl_db.bsr_table);
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
	tl_db_init();
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
	tl_db_init();
	if (tl_db.use_db) {
		uintmax_t lsb = x & (uintmax_t)(-(intmax_t)x);
		return tl_db.bsf_table[(tl_db.bsf_const * lsb) >> tl_db.shift];
	}
	/* log2(x & -x) == ctz(x) for any nonzero x */
	return bsr_bisect(x & (uintmax_t)(-(intmax_t)x));
}

int countl_zeromax(uintmax_t x)
{
	if (x == 0) {
		return UINTMAX_W;
	}
	return UINTMAX_W - 1 - log2umax(x);
}

#undef UINTMAX_W

#endif /* UINTMAX_MAX > ULLONG_MAX */
