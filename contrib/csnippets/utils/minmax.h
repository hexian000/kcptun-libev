/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_MINMAX_H
#define UTILS_MINMAX_H

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

#endif /* UTILS_MINMAX_H */
