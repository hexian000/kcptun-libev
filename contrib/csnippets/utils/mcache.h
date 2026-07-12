/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTILS_MCACHE_H
#define UTILS_MCACHE_H

/**
 * @file mcache.h
 * @brief Memory allocation caches that reuse freed blocks
 *
 * This header provides two related single-threaded allocation caches:
 *
 * - mcache: a fixed-size object cache. All blocks share one size, kept in a
 *   single LIFO free list.
 * - mmcache: a variable-size cache that segregates blocks into power-of-two
 *   size classes, each its own LIFO free list.
 *
 * Both reduce malloc/free overhead for frequently allocated objects by handing
 * back recently freed blocks (LIFO - the most recently returned block is reused
 * first) instead of going to malloc() every time.
 *
 * @note Thread safety: These implementations are NOT thread-safe
 * @note Memory alignment: No special alignment guarantees beyond malloc()
 */

#include "math/intlog2.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * @struct mcache
 * @brief Memory allocation cache structure
 *
 * Contains metadata and storage for cached memory blocks.
 */
struct mcache {
	/* maximum number of elements the cache can hold */
	size_t cache_size;
	/* size in bytes of each cached element */
	size_t elem_size;
	/* current number of elements in cache */
	size_t num_elem;
#if MCACHE_STATS
	/* total number of allocation requests */
	size_t request;
	/* number of requests served from cache */
	size_t hit;
#endif
	/* LIFO free list of cached element pointers */
	void *elems[];
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
	if (cache_size > (SIZE_MAX - sizeof(struct mcache)) / sizeof(void *)) {
		return NULL;
	}
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
		return;
	}
	for (size_t i = 0; i < cache->num_elem; i++) {
		free(cache->elems[i]);
	}
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
 * @note Statistics are updated if MCACHE_STATS is defined; read them back
 * with mcache_getstats()
 */
static inline void *mcache_get(struct mcache *restrict cache)
{
#if MCACHE_STATS
	cache->request++;
#endif
	if (cache->num_elem == 0) {
		return malloc(cache->elem_size);
	}
#if MCACHE_STATS
	cache->hit++;
#endif
	return cache->elems[--cache->num_elem];
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
		return;
	}
	if (cache->num_elem == cache->cache_size) {
		free(elem);
		return;
	}
	cache->elems[cache->num_elem++] = elem;
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
	const size_t stop = count < n ? n - count : 0;
	while (n > stop) {
		free(cache->elems[--n]);
	}
	cache->num_elem = n;
}

/**
 * @brief Read the cache's request/hit counters
 *
 * @param cache Pointer to the cache
 * @param request If non-NULL, set to the total number of mcache_get() calls
 * @param hit If non-NULL, set to the number of mcache_get() calls served
 * from the cache instead of malloc()
 *
 * @note Both are set to 0 when built without MCACHE_STATS
 */
static inline void mcache_getstats(
	const struct mcache *restrict cache, size_t *restrict request,
	size_t *restrict hit)
{
#if MCACHE_STATS
	if (request != NULL) {
		*request = cache->request;
	}
	if (hit != NULL) {
		*hit = cache->hit;
	}
#else
	(void)cache;
	if (request != NULL) {
		*request = 0;
	}
	if (hit != NULL) {
		*hit = 0;
	}
#endif /* MCACHE_STATS */
}

/**
 * @brief Memory allocation cache for variable-size objects
 *
 * mmcache caches freed blocks for reuse across a range of power-of-two size
 * classes. A request is rounded up to the smallest size class that can hold
 * it, so the returned block is always at least as large as requested.
 *
 * Each size class is an independent LIFO free list with the same capacity,
 * behaving exactly like an mcache. All free lists share one flat allocation:
 * a row of cache_size block pointers per class laid out row-major, followed by
 * one occupancy count per class. The count gives the live depth of each row,
 * so get()/put() are O(1) (see mmcache_counts()).
 *
 * Requests larger than the maximum size class bypass the cache and fall
 * through to malloc()/free() directly, so the cache works for any size while
 * only caching blocks within the configured range.
 *
 * @note The caller must pass the original request size to mmcache_put() so the
 * block can be routed back to the size class it came from.
 * @note Thread safety: This implementation is NOT thread-safe
 * @note Memory alignment: No special alignment guarantees beyond malloc()
 */

/**
 * @struct mmcache
 * @brief Variable-size memory allocation cache structure
 */
struct mmcache {
	/* log2 of the smallest size class; size <= (1 << min_shift) maps here */
	size_t min_shift;
	/* log2 of the largest cached size class; larger requests pass through */
	size_t max_shift;
	/* per-class capacity (free list depth) */
	size_t cache_size;
#if MCACHE_STATS
	/* total number of allocation requests */
	size_t request;
	/* number of requests served from cache */
	size_t hit;
#endif
	/* nclass rows of cache_size block pointers, followed by nclass
	 * per-class occupancy counts; see mmcache_counts() */
	void *slots[];
};

/**
 * @brief Locate the per-class occupancy counts within the cache allocation
 *
 * The counts array follows the block-pointer rows in the same allocation, one
 * size_t per size class. counts[c] is the number of live blocks in row c.
 *
 * @param cache Pointer to the cache
 * @return Pointer to the first of (max_shift - min_shift + 1) class counts
 */
static inline size_t *mmcache_counts(struct mmcache *restrict cache)
{
	const size_t nclass = cache->max_shift - cache->min_shift + 1;
	return (size_t *)(cache->slots + nclass * cache->cache_size);
}

/**
 * @brief Map a request size to its power-of-two size class exponent
 *
 * Returns the smallest exponent s such that (1 << s) >= size, clamped below to
 * min_shift. A return value greater than max_shift means the request exceeds
 * the cached range and must be served directly by malloc()/free().
 *
 * @param cache Pointer to the cache
 * @param size Requested size in bytes (0 maps to the smallest class)
 * @return Size class exponent for the request
 */
static inline size_t
mmcache_shift(const struct mmcache *restrict cache, const size_t size)
{
	if (size <= ((size_t)1 << cache->min_shift)) {
		return cache->min_shift;
	}
	/* ceil(log2(size)) for size >= 2: floor(log2(size - 1)) + 1 */
	return (size_t)intlog2((size_t)(size - 1)) + 1;
}

/**
 * @brief Create a new variable-size memory allocation cache
 *
 * Creates a cache with one size class per exponent in [min_shift, max_shift].
 * Each class caches up to cache_size blocks of (1 << exponent) bytes.
 *
 * @param min_shift log2 of the smallest size class
 * @param max_shift log2 of the largest cached size class (>= min_shift)
 * @param cache_size Maximum number of blocks each size class may hold
 * @return Pointer to a newly allocated mmcache, or NULL on allocation failure
 *
 * @note The returned cache must be freed with mmcache_free()
 */
static inline struct mmcache *mmcache_new(
	const size_t min_shift, const size_t max_shift, const size_t cache_size)
{
	assert(min_shift <= max_shift);
	const size_t nclass = max_shift - min_shift + 1;
	if (cache_size != 0 && nclass > SIZE_MAX / cache_size) {
		return NULL;
	}
	const size_t nslots = nclass * cache_size;
	if (nslots > (SIZE_MAX - sizeof(struct mmcache)) / sizeof(void *)) {
		return NULL;
	}
	const size_t head = sizeof(struct mmcache) + sizeof(void *) * nslots;
	if (nclass > (SIZE_MAX - head) / sizeof(size_t)) {
		return NULL;
	}
	struct mmcache *cache = malloc(head + sizeof(size_t) * nclass);
	if (cache == NULL) {
		return NULL;
	}
	*cache = (struct mmcache){
		.min_shift = min_shift,
		.max_shift = max_shift,
		.cache_size = cache_size,
	};
	/* Every class starts empty; block pointers are written lazily by put(). */
	size_t *counts = mmcache_counts(cache);
	for (size_t cls = 0; cls < nclass; cls++) {
		counts[cls] = 0;
	}
	return cache;
}

/**
 * @brief Destroy a variable-size cache and free all resources
 *
 * @param cache Pointer to the cache to destroy (can be NULL)
 *
 * @note It's safe to pass NULL - the function will return immediately
 * @note All blocks currently cached in any size class are freed
 */
static inline void mmcache_free(struct mmcache *restrict cache)
{
	if (cache == NULL) {
		return;
	}
	const size_t nclass = cache->max_shift - cache->min_shift + 1;
	const size_t cap = cache->cache_size;
	const size_t *counts = mmcache_counts(cache);
	for (size_t cls = 0; cls < nclass; cls++) {
		void *const *row = &cache->slots[cls * cap];
		for (size_t i = 0; i < counts[cls]; i++) {
			free(row[i]);
		}
	}
	free(cache);
}

/**
 * @brief Get a block of at least size bytes from the cache
 *
 * Routes the request to its size class and reuses a cached block when
 * available, otherwise allocates a new one. Requests larger than the maximum
 * size class are served directly by malloc().
 *
 * @param cache Pointer to the cache
 * @param size Requested size in bytes
 * @return Pointer to a block of at least size bytes, or NULL on failure
 *
 * @note The returned block is uninitialized
 * @note The same size must be passed to mmcache_put() when returning the block
 * @note Statistics are updated if MCACHE_STATS is defined; read them back
 * with mmcache_getstats()
 */
static inline void *
mmcache_get(struct mmcache *restrict cache, const size_t size)
{
#if MCACHE_STATS
	cache->request++;
#endif
	const size_t shift = mmcache_shift(cache, size);
	if (shift > cache->max_shift) {
		/* Oversized: served directly by malloc(), never a cache hit */
		return malloc(size);
	}
	const size_t cls = shift - cache->min_shift;
	size_t *restrict count = &mmcache_counts(cache)[cls];
	if (*count == 0) {
		return malloc((size_t)1 << shift);
	}
#if MCACHE_STATS
	cache->hit++;
#endif
	/* LIFO pop: take the top block of the class row */
	void **row = &cache->slots[cls * cache->cache_size];
	return row[--(*count)];
}

/**
 * @brief Return a block to the cache for reuse
 *
 * Routes the block back to the size class implied by size. Blocks larger than
 * the maximum size class, or returned to a full class, are freed directly.
 *
 * @param cache Pointer to the cache
 * @param ptr Pointer to the block to return (can be NULL)
 * @param size The size originally passed to mmcache_get() for this block
 *
 * @note It's safe to pass NULL ptr - the function will return immediately
 * @note size must match the mmcache_get() request that produced ptr
 * @note Caller should not use ptr after calling this function
 */
static inline void
mmcache_put(struct mmcache *restrict cache, void *ptr, const size_t size)
{
	if (ptr == NULL) {
		return;
	}
	const size_t shift = mmcache_shift(cache, size);
	if (shift > cache->max_shift) {
		free(ptr);
		return;
	}
	const size_t cls = shift - cache->min_shift;
	size_t *restrict count = &mmcache_counts(cache)[cls];
	if (*count == cache->cache_size) {
		free(ptr);
		return;
	}
	/* LIFO push onto the top of the class row */
	void **row = &cache->slots[cls * cache->cache_size];
	row[(*count)++] = ptr;
}

/**
 * @brief Reduce memory usage by freeing cached blocks in every size class
 *
 * @param cache Pointer to the cache to shrink
 * @param count Maximum number of blocks to free from each size class
 *
 * @note Blocks are freed in LIFO order within each class
 */
static inline void
mmcache_shrink(struct mmcache *restrict cache, const size_t count)
{
	const size_t nclass = cache->max_shift - cache->min_shift + 1;
	const size_t cap = cache->cache_size;
	size_t *counts = mmcache_counts(cache);
	for (size_t cls = 0; cls < nclass; cls++) {
		void **row = &cache->slots[cls * cap];
		size_t n = counts[cls];
		const size_t stop = count < n ? n - count : 0;
		while (n > stop) {
			free(row[--n]);
		}
		counts[cls] = n;
	}
}

/**
 * @brief Read the cache's request/hit counters
 *
 * @param cache Pointer to the cache
 * @param request If non-NULL, set to the total number of mmcache_get() calls
 * @param hit If non-NULL, set to the number of mmcache_get() calls served
 * from the cache instead of malloc()
 *
 * @note Both are set to 0 when built without MCACHE_STATS
 */
static inline void mmcache_getstats(
	const struct mmcache *restrict cache, size_t *restrict request,
	size_t *restrict hit)
{
#if MCACHE_STATS
	if (request != NULL) {
		*request = cache->request;
	}
	if (hit != NULL) {
		*hit = cache->hit;
	}
#else
	(void)cache;
	if (request != NULL) {
		*request = 0;
	}
	if (hit != NULL) {
		*hit = 0;
	}
#endif /* MCACHE_STATS */
}

#endif /* UTILS_MCACHE_H */
