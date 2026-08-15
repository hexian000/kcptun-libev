/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef META_STRLEN_H
#define META_STRLEN_H

/**
 * @defgroup strlen
 * @brief Compile-time byte length of a string literal.
 * @{
 */

/**
 * @brief Byte length of a narrow string literal, excluding the NUL.
 * @param s A narrow string literal, e.g. "abc".
 * @return The length as a size_t integer constant expression, usable in
 * static_assert and array dimensions.
 * @note The `s ""` concatenation is load-bearing: only a string literal
 * concatenates, so a pointer or array argument is a compile error rather than
 * a silent `sizeof(pointer) - 1`.
 * @note Narrow literals only. C11 concatenates a wide literal with a narrow
 * one, so `STRLEN(L"ab")` compiles and yields a meaningless byte count.
 */
#ifndef STRLEN
#define STRLEN(s) (sizeof(s "") - sizeof(""))
#endif

/** @} */

#endif /* META_STRLEN_H */
