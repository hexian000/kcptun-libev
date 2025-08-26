/* csnippets (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "hashtable.h"

#include "algo/cityhash.h"
#include "math/rand.h"
#include "utils/arraysize.h"
#include "utils/minmax.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if HASHTABLE_LOG
#include <inttypes.h>
#include <stdio.h>
#endif

/* start from 2^4 */
static const size_t capacity_list[] = {
	13,	    31,		61,	    127,       251,	   509,
	1021,	    2039,	4093,	    8191,      16381,	   32749,
	65521,	    87359,	116507,	    155333,    207127,	   276173,
	368233,	    490969,	654629,	    872843,    1163791,	   1551733,
	2068973,    2758633,	3678179,    4904233,   6539003,	   8718673,
	11624887,   15499843,	20666453,   27555337,  36740443,   48987283,
	65316371,   87088531,	116118031,  154824023, 206431987,  275242757,
	366990361,  489320479,	652427287,  869903063, 1159870741, 1546494359,
	2061992483, 2749323301, 3665764391,
};

#define COLLISION_THRESHOLD 100

#define INITIAL_CAPACITY (capacity_list[0])
#define LAST_CAPACITY (capacity_list[ARRAY_SIZE(capacity_list) - 1])
#define MAX_CAPACITY (SIZE_MAX - 1)

static inline size_t ceil_capacity(const size_t x)
{
	if (x > LAST_CAPACITY) {
		/* huge hashtable */
		return MIN(x | 1, MAX_CAPACITY);
	}
	size_t idx = 0;
	while (x > capacity_list[idx]) {
		idx++;
	}
	return capacity_list[idx];
}

typedef size_t elemid_type;
#define ID_NIL SIZE_MAX

struct hash_element {
	elemid_type bucket, next;
	bool valid : 1;
	uint_least32_t hash;
	struct hashkey key;
	void *element;
};

struct hashtable {
	size_t size, capacity, max_load;
	elemid_type freelist;
	uint_least32_t seed;
	int flags;
#ifndef NDEBUG
	unsigned int version;
#endif
	struct hash_element p[];
};

#define KEY_EQUALS(a, b)                                                       \
	((a).len == (b).len && memcmp((a).data, (b).data, (a).len) == 0)

#define GET_HASH(x, seed) (cityhash64low_32((x).data, (x).len, (seed)))

static inline void
init_elements(struct hashtable *restrict table, const size_t start)
{
	const size_t capacity = table->capacity;
	/* initialize items */
	for (size_t i = start; i < capacity; i++) {
		table->p[i] = (struct hash_element){
			.bucket = ID_NIL,
			.next = ID_NIL,
			.valid = false,
		};
	}
}

static inline void table_compact(struct hashtable *restrict table)
{
	/* compact table */
	const size_t capacity = table->capacity;
	for (size_t r = 0, w = 0; r < capacity; r++) {
		struct hash_element *restrict p = &table->p[r];
		/* clear all buckets */
		p->bucket = ID_NIL;
		if (!p->valid) {
			continue;
		}
		if (r > w) {
			struct hash_element *restrict q = &table->p[w];
			q->hash = p->hash;
			q->key = p->key;
			q->element = p->element;
			p->valid = false;
		}
		w++;
	}
	table->freelist = ID_NIL;
}

static inline void table_rehash(struct hashtable *restrict table)
{
	/*  table must be compacted */
	assert(table->freelist == ID_NIL);
	/* perform rehash */
	const size_t size = table->size;
	const size_t capacity = table->capacity;
	const uint_least32_t seed = table->seed;
	for (size_t i = 0; i < size; i++) {
		struct hash_element *restrict p = &table->p[i];
		const size_t hash = GET_HASH(p->key, seed);
		const size_t bucket = hash % capacity;
		p->hash = hash;
		p->next = table->p[bucket].bucket;
		table->p[bucket].bucket = i;
	}
}

static inline void
set_capacity(struct hashtable *restrict table, const size_t new_capacity)
{
	table->capacity = new_capacity;
	/* max load factor: 1.0 - normal, 0.75 - fast */
	if (table->flags & TABLE_FAST) {
		table->max_load = table->capacity / 4 * 3;
	} else {
		table->max_load = table->capacity;
	}
}

static inline struct hashtable *
table_realloc(struct hashtable *restrict table, const size_t new_capacity)
{
	const size_t old_capacity = table->capacity;
	if (old_capacity == new_capacity) {
		return table;
	}
	assert(new_capacity >= table->size);
	struct hashtable *restrict m = realloc(
		table, sizeof(struct hashtable) +
			       new_capacity * sizeof(struct hash_element));
	if (m == NULL) {
		return table;
	}
	set_capacity(m, new_capacity);

	if (new_capacity > old_capacity) {
		/* init newly allocated memory */
		init_elements(m, old_capacity);
	}
	return m;
}

static inline struct hashtable *table_grow(struct hashtable *restrict table)
{
	static const size_t threshold =
		2 * 1024 * 1024 / sizeof(struct hash_element);
	const size_t want =
		table->size < threshold ? table->size : table->size / 3 + 1;
	size_t estimated = table->size;
	if (estimated < MAX_CAPACITY - want) {
		estimated += want;
	} else {
		estimated = MAX_CAPACITY;
	}
	return table_reserve(table, estimated);
}

static inline void table_reseed(struct hashtable *restrict table)
{
	table->seed = (uint_least32_t)rand64n(UINT32_MAX);
#if HASHTABLE_LOG
	(void)fprintf(
		stderr, "table reseed: size=%zu new_seed=%" PRIX32 "\n",
		table->size, table->seed);
#endif
	table_compact(table);
	table_rehash(table);
}

struct hashtable *table_set(
	struct hashtable *restrict table, const struct hashkey key,
	void **restrict element)
{
	assert(table != NULL && element != NULL);
	const uint_least32_t hash = GET_HASH(key, table->seed);
	elemid_type bucket = hash % table->capacity;
	size_t collision = 0;
	for (elemid_type i = table->p[bucket].bucket; i != ID_NIL;
	     i = table->p[i].next) {
		struct hash_element *restrict p = &table->p[i];
		if (p->hash == hash && KEY_EQUALS(p->key, key)) {
			/* replace existing element */
			void *old_elem = p->element;
			p->key = key;
			p->element = *element;
#ifndef NDEBUG
			table->version++;
#endif
			if (collision > COLLISION_THRESHOLD) {
				table_reseed(table);
			}
			*element = old_elem;
			return table;
		}
		collision++;
	}

	elemid_type index;
	if (table->freelist != ID_NIL) {
		assert(table->size < table->capacity);
		index = table->freelist;
		table->freelist = table->p[index].next;
		table->size++;
	} else {
		if (table->size >= table->max_load) {
			table = table_grow(table);
			if (table->size == table->capacity) {
				/* allocation failed */
				return table;
			}
			bucket = hash % table->capacity;
		}
		index = table->size;
		table->size++;
	}

	struct hash_element *restrict p = &table->p[index];
	p->valid = true;
	p->hash = hash;
	p->key = key;
	p->element = *element;
	elemid_type *old_bucket = &table->p[bucket].bucket;
	p->next = *old_bucket;
	*old_bucket = index;
#ifndef NDEBUG
	table->version++;
#endif

	if (collision > COLLISION_THRESHOLD) {
		table_reseed(table);
	}
	*element = NULL;
	return table;
}

bool table_find(
	const struct hashtable *restrict table, const struct hashkey key,
	void **element)
{
	if (table == NULL) {
		return false;
	}
	const uint_least32_t hash = GET_HASH(key, table->seed);
	const elemid_type bucket = hash % table->capacity;
	for (elemid_type i = table->p[bucket].bucket; i != ID_NIL;
	     i = table->p[i].next) {
		const struct hash_element *restrict p = &(table->p[i]);
		if (p->hash == hash && KEY_EQUALS(p->key, key)) {
			/* found */
			if (element != NULL) {
				*element = p->element;
			}
			return true;
		}
	}
	return false;
}

struct hashtable *table_del(
	struct hashtable *restrict table, const struct hashkey key,
	void **restrict element)
{
	if (table == NULL) {
		return NULL;
	}
	const uint_least32_t hash = GET_HASH(key, table->seed);
	const elemid_type bucket = hash % table->capacity;
	elemid_type *last_next = &table->p[bucket].bucket;
	for (elemid_type i = *last_next; i != ID_NIL; i = *last_next) {
		struct hash_element *restrict p = &table->p[i];
		if (p->hash == hash && KEY_EQUALS(p->key, key)) {
			*last_next = p->next;
			p->valid = false;
			p->next = table->freelist;
			table->freelist = i;
			table->size--;
#ifndef NDEBUG
			table->version++;
#endif
			if (element != NULL) {
				*element = p->element;
			}
			return table;
		}
		last_next = &(p->next);
	}
	if (element != NULL) {
		*element = NULL;
	}
	return table;
}

struct hashtable *table_new(const int flags)
{
	struct hashtable *restrict table =
		malloc(sizeof(struct hashtable) +
		       sizeof(struct hash_element) * INITIAL_CAPACITY);
	if (table == NULL) {
		return NULL;
	}
	*table = (struct hashtable){
		.size = 0,
		.freelist = ID_NIL,
		.seed = (uint_least32_t)rand64n(UINT32_MAX),
		.flags = flags,
#ifndef NDEBUG
		.version = 0,
#endif
	};
	set_capacity(table, INITIAL_CAPACITY);
	init_elements(table, 0);
	return table;
}

void table_free(struct hashtable *restrict table)
{
	free(table);
}

struct hashtable *
table_reserve(struct hashtable *restrict table, const size_t new_size)
{
	assert(table != NULL);
	size_t new_capacity = new_size;
	if (new_capacity < table->size) {
		new_capacity = table->size;
	}
	if (table->flags & TABLE_FAST) {
		const size_t want = new_size / 3 + 1;
		if (new_capacity < MAX_CAPACITY - want) {
			new_capacity += want;
		} else {
			new_capacity = MAX_CAPACITY;
		}
	}
	new_capacity = ceil_capacity(new_capacity);
	if (table->capacity == new_capacity) {
		return table;
	}
#if HASHTABLE_LOG
	(void)fprintf(
		stderr,
		"table resize: size=%zu capacity=%zu new_capacity=%zu\n",
		table->size, table->capacity, new_capacity);
#endif
#ifndef NDEBUG
	table->version++;
#endif
	table_compact(table);
	table = table_realloc(table, new_capacity);
	table_rehash(table);
	return table;
}

struct hashtable *table_filter(
	struct hashtable *restrict table, const table_iterate_cb f, void *data)
{
	if (table == NULL) {
		return NULL;
	}
#ifndef NDEBUG
	const unsigned int version = table->version;
#endif
	const size_t capacity = table->capacity;
	for (elemid_type bucket = 0; bucket < capacity; bucket++) {
		size_t *last_next = &table->p[bucket].bucket;
		for (size_t i = *last_next; i != ID_NIL; i = *last_next) {
#ifndef NDEBUG
			assert(version == table->version);
#endif
			struct hash_element *restrict p = &(table->p[i]);
			const bool ok = f(table, p->key, p->element, data);
			if (ok) {
				last_next = &(p->next);
				continue;
			}
			/* delete item */
			*last_next = p->next;
			p->valid = false;
			p->next = table->freelist;
			table->freelist = i;
			table->size--;
		}
	}
	return table;
}

void table_iterate(
	const struct hashtable *restrict table, const table_iterate_cb f,
	void *data)
{
	if (table == NULL) {
		return;
	}
#ifndef NDEBUG
	const unsigned int version = table->version;
#endif
	const size_t capacity = table->capacity;
	for (size_t i = 0; i < capacity; i++) {
#ifndef NDEBUG
		assert(version == table->version);
#endif
		const struct hash_element *restrict p = &table->p[i];
		if (!p->valid) {
			continue;
		}
		if (!f(table, p->key, p->element, data)) {
			return;
		}
	}
}

size_t table_size(const struct hashtable *restrict table)
{
	if (table == NULL) {
		return 0;
	}
	return table->size;
}
