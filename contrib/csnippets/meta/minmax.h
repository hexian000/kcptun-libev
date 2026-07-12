/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef META_MINMAX_H
#define META_MINMAX_H

/* NaN comparisons are always false, so with NaN inputs these macros can
 * silently ignore a bound or (BETWEEN) report NaN as in-range. Avoid with
 * operands that may hold NaN. */

/* Each macro may evaluate its operands more than once (twice for a/b, three
 * times for x in CLAMP and twice in BETWEEN), so the operands must be
 * side-effect-free: e.g. MAX(i++, 0) would double-apply the increment. */

#ifndef MAX
#define MAX(a, b) ((a) < (b) ? (b) : (a))
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef CLAMP
#define CLAMP(x, a, b) ((x) < (a) ? (a) : ((b) < (x) ? (b) : (x)))
#endif

#ifndef BETWEEN
#define BETWEEN(x, a, b) (!((x) < (a) || (b) < (x)))
#endif

#endif /* META_MINMAX_H */
