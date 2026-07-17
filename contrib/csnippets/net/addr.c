/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "addr.h"

#include <stdbool.h>
#include <string.h>

bool splithostport(char *str, char **restrict host, char **restrict port)
{
	char *service = strrchr(str, ':');
	if (service == NULL) {
		return false;
	}
	*service = '\0';
	service++;

	char *hostname = str;
	bool bracketed = false;
	if (hostname[0] == '[' && service[-2] == ']') {
		/* remove brackets */
		hostname++;
		service[-2] = '\0';
		bracketed = true;
	}

	/* An IPv6 literal must be written as [addr]:port. Splitting at the last
	 * colon otherwise mis-parses a bare or bracket-less multi-colon host
	 * (e.g. "::1", "2001:db8::1", or "[::1]" with no port) into a bogus
	 * host/port pair, so reject an unbracketed host that still holds a colon
	 * rather than reporting success on garbage. */
	if (!bracketed && strchr(hostname, ':') != NULL) {
		return false;
	}

	if (host != NULL) {
		*host = hostname;
	}
	if (port != NULL) {
		*port = service;
	}
	return true;
}
