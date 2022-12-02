/* csnippets (c) 2019-2022 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef ADDR_H
#define ADDR_H

#include <stdbool.h>

/**
 * @brief Split a socket address into host & port.
 * @details No allocations, the raw string is destructed.
 * @param str Socket address string, will be destructed.
 * @param host [OUT] Host name string. IPv6 brackets are removed.
 * @param port [OUT] Port number or service string.
 * @return false if no colon in str. Only in this case, str is not destructed.
 */
bool splithostport(char *str, char **host, char **port);

#endif /* ADDR_H */
