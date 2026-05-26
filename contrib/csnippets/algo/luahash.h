#if !defined(ALGO_LUAHASH_H)
#define ALGO_LUAHASH_H

#include <stddef.h>

static inline unsigned luahash(const void *ptr, size_t l, const unsigned seed)
{
	const unsigned char *str = ptr;
	unsigned int h = seed ^ (unsigned)l;
	for (; l > 0; l--) {
		h ^= (h << 5) + (h >> 2) + str[l - 1];
	}
	return h;
}

#endif /* ALGO_LUAHASH_H */
