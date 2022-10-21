#ifndef LEAKYPOOL_H
#define LEAKYPOOL_H

#include "util.h"
#include <stdlib.h>

struct leakypool {
	void **pool;
	size_t pool_size, elem_size;
	size_t n;
};

static inline struct leakypool pool_create(size_t pool_size, size_t elem_size)
{
	return (struct leakypool){
		.pool = (void **)util_malloc(sizeof(void *) * pool_size),
		.pool_size = pool_size,
		.elem_size = elem_size,
		.n = 0,
	};
}

static inline void pool_free(struct leakypool *restrict p)
{
	if (p->pool != NULL) {
		for (size_t i = 0; i < p->n; i++) {
			util_free(p->pool[i]);
		}
		util_free(p->pool);
	}
	*p = (struct leakypool){ 0 };
}

static inline void *pool_get(struct leakypool *restrict p)
{
	if (p->n > 0) {
		return p->pool[--p->n];
	}
	return util_malloc(p->elem_size);
}

static inline void pool_put(struct leakypool *restrict p, void *elem)
{
	if (p->n < p->pool_size) {
		p->pool[p->n++] = elem;
		return;
	}
	util_free(elem);
}

#endif /* LEAKYPOOL_H */
