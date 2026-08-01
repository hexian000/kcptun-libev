/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef META_LIKELY_H
#define META_LIKELY_H

/* META_FORCE_FALLBACK selects the portable identity definition even under GCC/
 * Clang, so a test can compile and exercise that otherwise-unreachable path. */
#if defined(__has_builtin) && !defined(META_FORCE_FALLBACK)
#if __has_builtin(__builtin_expect)

#ifndef LIKELY
#define LIKELY(x) __builtin_expect(!!(x), 1)
#endif

#ifndef UNLIKELY
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

#endif /* __has_builtin(__builtin_expect) */
#elif defined(__GNUC__) && !defined(META_FORCE_FALLBACK)
/* GCC before 10 predates __has_builtin but has provided __builtin_expect since
 * 3.0, so use it directly there instead of dropping the branch hint. */

#ifndef LIKELY
#define LIKELY(x) __builtin_expect(!!(x), 1)
#endif

#ifndef UNLIKELY
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

#endif /* __has_builtin / __GNUC__, and not META_FORCE_FALLBACK */

#ifndef LIKELY
#define LIKELY(x) (x)
#endif

#ifndef UNLIKELY
#define UNLIKELY(x) (x)
#endif

#endif /* META_LIKELY_H */
