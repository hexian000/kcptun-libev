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

/* Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs" */
static inline uint32_t xorshift32(uint32_t x)
{
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return x;
}

uint32_t rand32(void)
{
	static uint32_t x = UINT32_C(0);
	if (x == UINT32_C(0)) {
		x = time(NULL);
	}
	x = xorshift32(x);
	return x;
}
