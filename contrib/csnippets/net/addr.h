/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef NET_ADDR_H
#define NET_ADDR_H

#include <stdbool.h>

/**
 * @defgroup addr
 * @brief Utilities to process network address strings.
 * @{
 */

/**
 * @brief Split a socket address into host & port.
 * @details No allocations, the raw string is destructed.
 * @param str Socket address string, will be destructed.
 * @param[out] host Host name string. IPv6 brackets are removed.
 * @param[out] port Port number or service string.
 * @return false if no colon in str. Only in this case, str is not destructed.
 */
bool splithostport(char *str, char **host, char **port);

/** @} */

#endif /* NET_ADDR_H */
