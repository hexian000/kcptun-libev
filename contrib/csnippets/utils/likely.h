/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#if defined(__has_builtin)
#if __has_builtin(__builtin_expect)

#ifndef LIKELY
#define LIKELY(x) __builtin_expect(!!(x), 1)
#endif

#ifndef UNLIKELY
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

#endif /* __has_builtin(__builtin_expect) */
#endif /* defined(__has_builtin) */

#ifndef LIKELY
#define LIKELY(x) (x)
#endif

#ifndef UNLIKELY
#define UNLIKELY(x) (x)
#endif
