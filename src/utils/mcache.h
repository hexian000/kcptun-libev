/* csnippets (c) 2019-2022 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef MCACHE_H
#define MCACHE_H

#include "likely.h"

#include <stdlib.h>

struct mcache {
	void **p;
	size_t cache_size, elem_size;
	size_t n;
#if MCACHE_STATS
	size_t query, hit;
#endif
};

static inline struct mcache mcache_new(size_t cache_size, size_t elem_size)
{
	return (struct mcache){
		.p = (void **)malloc(sizeof(void *) * cache_size),
		.cache_size = cache_size,
		.elem_size = elem_size,
	};
}

static inline void mcache_free(struct mcache *restrict p)
{
	if (p->p != NULL) {
		for (size_t i = 0; i < p->n; i++) {
			free(p->p[i]);
		}
		free(p->p);
	}
	*p = (struct mcache){ 0 };
}

static inline void *mcache_get(struct mcache *restrict p)
{
#if MCACHE_STATS
	p->query++;
#endif
	if (LIKELY(p->n > 0)) {
#if MCACHE_STATS
		p->hit++;
#endif
		return p->p[--p->n];
	}
	return malloc(p->elem_size);
}

static inline void mcache_put(struct mcache *restrict p, void *elem)
{
	if (UNLIKELY(elem == NULL)) {
		return;
	}
	if (LIKELY(p->n < p->cache_size)) {
		p->p[p->n++] = elem;
		return;
	}
	free(elem);
}

#endif /* MCACHE_H */
