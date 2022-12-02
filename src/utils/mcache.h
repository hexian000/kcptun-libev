/* csnippets (c) 2019-2022 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef MCACHE_H
#define MCACHE_H

#include <stdlib.h>

struct mcache {
	size_t cache_size, elem_size;
	size_t n;
#if MCACHE_STATS
	size_t query, hit;
#endif
	void *p[];
};

static inline struct mcache *mcache_new(size_t cache_size, size_t elem_size)
{
	struct mcache *cache =
		malloc(sizeof(struct mcache) + sizeof(void *) * cache_size);
	if (cache != NULL) {
		*cache = (struct mcache){
			.cache_size = cache_size,
			.elem_size = elem_size,
			.n = 0,
		};
	}
	return cache;
}

static inline void mcache_free(struct mcache *restrict cache)
{
	if (cache == NULL) {
		return;
	}
	for (size_t i = 0; i < cache->n; i++) {
		free(cache->p[i]);
	}
	free(cache);
}

static inline void *mcache_get(struct mcache *restrict cache)
{
	if (cache == NULL) {
		return malloc(cache->elem_size);
	}
#if MCACHE_STATS
	cache->query++;
#endif
	if (cache->n == 0) {
		return malloc(cache->elem_size);
	}
#if MCACHE_STATS
	cache->hit++;
#endif
	return cache->p[--cache->n];
}

static inline void mcache_put(struct mcache *restrict cache, void *elem)
{
	if (elem == NULL) {
		return;
	}
	if (cache == NULL || cache->n == cache->cache_size) {
		free(elem);
		return;
	}
	cache->p[cache->n++] = elem;
}

#endif /* MCACHE_H */
