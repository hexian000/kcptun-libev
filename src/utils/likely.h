/* csnippets (c) 2019-2022 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef LIKELY
#if defined(__GNUC__)
#define LIKELY(x) __builtin_expect(!!(x), 1)
#else /* __GNUC__ */
#define LIKELY(x) (x)
#endif /* __GNUC__ */
#endif /* LIKELY */

#ifndef UNLIKELY
#if defined(__GNUC__)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else /* __GNUC__ */
#define UNLIKELY(x) (x)
#endif /* __GNUC__ */
#endif /* UNLIKELY */
