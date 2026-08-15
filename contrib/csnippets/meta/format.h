/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef META_FORMAT_H
#define META_FORMAT_H

/**
 * @defgroup format
 * @brief Portable printf-style format-checking attribute.
 * @details `FORMAT_PRINTF(fmt, args)` marks a variadic function so the compiler
 * checks each call's arguments against the format string. `fmt` is the 1-based
 * index of the format-string parameter and `args` the 1-based index of the
 * first variadic argument; for a va_list wrapper pass 0 as `args`, so only the
 * format string itself is checked. The `printf` archetype fits any wrapper
 * accepting the C standard conversions. On compilers without the attribute it
 * expands to nothing, so declarations stay portable.
 * @{
 */

/* META_FORCE_FALLBACK selects the empty portable definition even under GCC/
 * Clang, so a test can compile and exercise that otherwise-unreachable path. */
#if defined(__has_attribute) && !defined(META_FORCE_FALLBACK)
#if __has_attribute(format)

#ifndef FORMAT_PRINTF
#define FORMAT_PRINTF(fmt, args)                                               \
	__attribute__((__format__(__printf__, fmt, args)))
#endif

#endif /* __has_attribute(format) */
#elif defined(__GNUC__) && !defined(META_FORCE_FALLBACK)
/* GCC before 5 predates __has_attribute but has provided the format attribute
 * since long before, so use it directly there instead of dropping the check. */

#ifndef FORMAT_PRINTF
#define FORMAT_PRINTF(fmt, args)                                               \
	__attribute__((__format__(__printf__, fmt, args)))
#endif

#endif /* __has_attribute / __GNUC__, and not META_FORCE_FALLBACK */

#ifndef FORMAT_PRINTF
#define FORMAT_PRINTF(fmt, args)
#endif

/** @} */

#endif /* META_FORMAT_H */
