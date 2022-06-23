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

char *clonestr(const char *str)
{
	if (str == NULL) {
		return NULL;
	}
	size_t len = strlen(str);
	char *s = util_malloc(len + 1);
	if (s == NULL) {
		return NULL;
	}
	memcpy(s, str, len);
	s[len] = 0;
	return s;
}

/* Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs" */
static inline uint32_t xorshift32(uint32_t x)
{
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return x;
}

static uint32_t rand32_state = UINT32_C(0);

uint32_t rand32()
{
	if (!rand32_state) {
		rand32_state = time(NULL);
	}
	return rand32_state = xorshift32(rand32_state);
}
