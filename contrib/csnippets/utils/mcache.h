/* csnippets (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_MCACHE_H
#define UTILS_MCACHE_H

/**
 * @brief mcache.h is a fixed size object allocation cache
 * For single-threaded use only.
 */

#include <stddef.h>
#include <stdlib.h>

struct mcache {
	size_t cache_size, elem_size;
	size_t num_elem;
#if MCACHE_STATS
	size_t query, hit;
#endif
	void *p[];
};

static inline struct mcache *
mcache_new(const size_t cache_size, const size_t elem_size)
{
	struct mcache *cache =
		malloc(sizeof(struct mcache) + sizeof(void *) * cache_size);
	if (cache != NULL) {
		*cache = (struct mcache){
			.cache_size = cache_size,
			.elem_size = elem_size,
			.num_elem = 0,
		};
	}
	return cache;
}

static inline void mcache_free(struct mcache *restrict cache)
{
	if (cache == NULL) {
		return;
	}
	for (size_t i = 0; i < cache->num_elem; i++) {
		free(cache->p[i]);
	}
	free(cache);
}

static inline void *mcache_get(struct mcache *restrict cache)
{
#if MCACHE_STATS
	cache->query++;
#endif
	if (cache->num_elem == 0) {
		return malloc(cache->elem_size);
	}
#if MCACHE_STATS
	cache->hit++;
#endif
	return cache->p[--cache->num_elem];
}

static inline void mcache_put(struct mcache *restrict cache, void *elem)
{
	if (elem == NULL) {
		return;
	}
	if (cache->num_elem == cache->cache_size) {
		free(elem);
		return;
	}
	cache->p[cache->num_elem++] = elem;
}

static inline void
mcache_shrink(struct mcache *restrict cache, const size_t count)
{
	size_t n = cache->num_elem;
	const size_t stop = count < n ? n - count : 0;
	while (n > stop) {
		free(cache->p[--n]);
	}
	cache->num_elem = n;
}

#endif /* UTILS_MCACHE_H */
