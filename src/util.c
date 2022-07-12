#include "util.h"
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>

void print_bin(const void *b, const size_t n)
{
#ifdef NDEBUG
	UNUSED(b);
	UNUSED(n);
#else
	fprintf(stderr, "[%zu] ", n);
	for (size_t i = 0; i < n; i++) {
		fprintf(stderr, "%02" PRIX8, ((const uint8_t *)b)[i]);
	}
	fprintf(stderr, "\n");
	fflush(stderr);
#endif /* NDEBUG */
}

char *util_strndup(const char *str, size_t n)
{
	if (str == NULL) {
		return NULL;
	}
	char *s = util_malloc(n + 1);
	if (s == NULL) {
		return NULL;
	}
	memcpy(s, str, n);
	s[n] = 0;
	return s;
}

char *util_strdup(const char *str)
{
	if (str == NULL) {
		return NULL;
	}
	return util_strndup(str, strlen(str));
}

static uint32_t rand32_state = UINT32_C(0);

uint32_t rand32()
{
	if (rand32_state == UINT32_C(0)) {
		rand32_state = time(NULL);
	}
	return rand32_state = xorshift32(rand32_state);
}
