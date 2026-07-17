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
 * @details No allocations, the raw string is destructed. An IPv6 literal must
 * be given in bracketed form as `[addr]:port`; an unbracketed host that still
 * contains a colon (e.g. a bare `::1`) is rejected rather than mis-split.
 * @param str Socket address string, will be destructed.
 * @param[out] host Host name string. IPv6 brackets are removed.
 * @param[out] port Port number or service string.
 * @return false if str has no colon, or if the host part is unbracketed yet
 * still contains a colon. When there is no colon at all str is left unmodified;
 * the multi-colon rejection may have already written into str.
 */
bool splithostport(char *str, char **restrict host, char **restrict port);

/** @} */

#endif /* NET_ADDR_H */
