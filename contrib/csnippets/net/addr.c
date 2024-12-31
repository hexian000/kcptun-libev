/* csnippets (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "addr.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

bool splithostport(char *str, char **host, char **port)
{
	char *service = strrchr(str, ':');
	if (service == NULL) {
		return false;
	}
	*service = '\0';
	service++;

	char *hostname = str;
	if (hostname[0] == '[' && service[-2] == ']') {
		/* remove brackets */
		hostname++;
		service[-2] = '\0';
	}

	if (host != NULL) {
		*host = hostname;
	}
	if (port != NULL) {
		*port = service;
	}
	return true;
}
