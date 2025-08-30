/* csnippets (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_MCACHE_H
#define UTILS_MCACHE_H

/**
 * @file mcache.h
 * @brief Memory allocation cache for fixed-size objects
 *
 * mcache provides a simple fixed-size object cache that stores freed objects for reuse,
 * reducing malloc/free overhead for frequently allocated objects of the same size.
 * This implementation is optimized for single-threaded use only.
 *
 * The cache operates as a LIFO (Last In, First Out) stack - the most recently
 * returned object will be the first one reused.
 *
 * @note Thread safety: This implementation is NOT thread-safe
 * @note Memory alignment: No special alignment guarantees beyond malloc()
 */

#include <stddef.h>
#include <stdlib.h>

/**
 * @struct mcache
 * @brief Memory allocation cache structure
 *
 * Contains metadata and storage for cached memory blocks.
 */
struct mcache {
	size_t cache_size; /**< Maximum number of elements the cache can hold */
	size_t elem_size; /**< Size in bytes of each cached element */
	size_t num_elem; /**< Current number of elements in cache */
#if MCACHE_STATS
	size_t request; /**< Total number of allocation requests (statistics) */
	size_t hit; /**< Number of requests served from cache (statistics) */
#endif
	void *p[]; /**< Flexible array member storing pointers to cached elements */
};

/**
 * @brief Create a new memory allocation cache
 *
 * Allocates and initializes a new mcache structure that can hold up to
 * cache_size elements of elem_size bytes each.
 *
 * @param cache_size Maximum number of elements the cache can store
 * @param elem_size Size in bytes of each element to be cached
 * @return Pointer to newly allocated mcache structure, or NULL on allocation failure
 *
 * @note The returned cache starts empty and must be freed with mcache_free()
 * @note Setting cache_size to 0 creates a cache that never stores elements
 */
static inline struct mcache *
mcache_new(const size_t cache_size, const size_t elem_size)
{
	/* Allocate space for the structure plus the pointer array */
	struct mcache *cache =
		malloc(sizeof(struct mcache) + sizeof(void *) * cache_size);
	if (cache != NULL) {
		/* Initialize the cache structure */
		*cache = (struct mcache){
			.cache_size = cache_size,
			.elem_size = elem_size,
			.num_elem = 0, /* Start with empty cache */
		};
	}
	return cache;
}

/**
 * @brief Destroy a memory allocation cache and free all resources
 *
 * Frees all cached elements and the cache structure itself.
 * After calling this function, the cache pointer becomes invalid.
 *
 * @param cache Pointer to the cache to destroy (can be NULL)
 *
 * @note It's safe to pass NULL - the function will return immediately
 * @note All elements currently in the cache will be freed
 */
static inline void mcache_free(struct mcache *restrict cache)
{
	if (cache == NULL) {
		return; /* Safe to call with NULL pointer */
	}
	/* Free all cached elements */
	for (size_t i = 0; i < cache->num_elem; i++) {
		free(cache->p[i]);
	}
	/* Free the cache structure itself */
	free(cache);
}

/**
 * @brief Get an object from the cache
 *
 * Returns an object of elem_size bytes. If the cache has available
 * elements, returns a cached one (cache hit). Otherwise, allocates a new
 * block using malloc() (cache miss).
 *
 * @param cache Pointer to the cache to get element from
 * @return Pointer to object of elem_size bytes, or NULL on allocation failure
 *
 * @note The returned object is uninitialized - caller must initialize it
 * @note Cache operates as LIFO - most recently returned element is reused first
 * @note Statistics are updated if MCACHE_STATS is defined
 */
static inline void *mcache_get(struct mcache *restrict cache)
{
#if MCACHE_STATS
	cache->request++; /* Count total allocation requests */
#endif
	/* Cache miss: no elements available, allocate new one */
	if (cache->num_elem == 0) {
		return malloc(cache->elem_size);
	}
#if MCACHE_STATS
	cache->hit++; /* Count cache hits */
#endif
	/* Cache hit: return most recently cached element (LIFO) */
	return cache->p[--cache->num_elem];
}

/**
 * @brief Return an object to the cache for reuse
 *
 * Attempts to store the given object in the cache for future reuse.
 * If the cache is full, the element is freed immediately instead.
 *
 * @param cache Pointer to the cache to return element to
 * @param elem Pointer to object to cache (can be NULL)
 *
 * @note It's safe to pass NULL elem - the function will return immediately
 * @note The elem should have been allocated with the same size as cache->elem_size
 * @note If cache is full, elem is freed and not stored
 * @note Caller should not use elem after calling this function
 */
static inline void mcache_put(struct mcache *restrict cache, void *elem)
{
	if (elem == NULL) {
		return; /* Safe to call with NULL pointer */
	}
	/* Cache is full: free the element instead of caching it */
	if (cache->num_elem == cache->cache_size) {
		free(elem);
		return;
	}
	/* Store element in cache for future reuse */
	cache->p[cache->num_elem++] = elem;
}

/**
 * @brief Reduce cache size by freeing cached elements
 *
 * Removes and frees up to 'count' elements from the cache, reducing memory
 * usage. Elements are removed in LIFO order (most recently cached first).
 *
 * @param cache Pointer to the cache to shrink
 * @param count Maximum number of elements to remove from cache
 *
 * @note If count >= current cache size, all cached elements are freed
 * @note If count is 0, no elements are removed
 * @note This function only affects cached elements, not the cache structure itself
 * @note Useful for memory management when cache usage patterns change
 */
static inline void
mcache_shrink(struct mcache *restrict cache, const size_t count)
{
	size_t n = cache->num_elem;
	/* Calculate how many elements to keep (stop point) */
	const size_t stop = count < n ? n - count : 0;
	/* Free elements from the top of the stack (LIFO order) */
	while (n > stop) {
		free(cache->p[--n]);
	}
	/* Update the count of remaining elements */
	cache->num_elem = n;
}

#endif /* UTILS_MCACHE_H */
