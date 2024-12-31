/* csnippets (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

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
