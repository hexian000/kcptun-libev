/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "hashtable.h"
#include "algo/cityhash.h"
#include "math/rand.h"
#include "utils/arraysize.h"
#include "utils/buffer.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#if HASHTABLE_LOG
#include <stdio.h>
#include <inttypes.h>
#endif

/* start from 2^4 */
static const int prime_list[] = {
	13,	31,	61,	 127,	  251,	   509,	   1021,
	2039,	4093,	6143,	 10223,	  16381,   24571,  36857,
	55291,	83939,	114679,	 163819,  229373,  311293, 425977,
	573437, 770047, 1032191, 1376237, 1835003,
};

#define COLLISION_THRESHOLD 100

#define INITIAL_CAPACITY (prime_list[0])

static inline int ceil_capacity(int x)
{
	const int last_prime = prime_list[ARRAY_SIZE(prime_list) - 1];
	if (x > last_prime) {
		/* huge hashtable */
		return x | 1;
	}
	size_t idx = 0;
	while (x > prime_list[idx]) {
		idx++;
	}
	return prime_list[idx];
}

struct hash_item {
	int bucket;
	int hash, next;
	const hashkey_t *key;
	void *element;
};

struct hashtable {
	struct hash_item *p;
	int size, capacity, max_load;
	int freelist;
	uint32_t seed;
	int flags;
#ifndef NDEBUG
	unsigned int version;
#endif
};

#define KEY_EQUALS(a, b) VBUF_EQUALS(a, b)

static inline int get_hash(const hashkey_t *restrict x, const uint32_t seed)
{
	const uint32_t h = cityhash64low_32(x->data, x->len, seed);
	return (int)(h & (uint32_t)INT_MAX);
}

static inline void table_init(struct hashtable *restrict table, const int start)
{
	const int capacity = table->capacity;
	/* initialize items */
	for (int i = start; i < capacity; i++) {
		table->p[i] = (struct hash_item){
			.bucket = -1,
			.hash = -1,
			.next = -1,
		};
	}
}

static inline void table_compact(struct hashtable *restrict table)
{
	/* compact table */
	const int capacity = table->capacity;
	for (int r = 0, w = 0; r < capacity; r++) {
		struct hash_item *restrict p = &(table->p[r]);
		/* clear all buckets */
		p->bucket = -1;
		if (p->hash < 0) {
			continue;
		}
		if (r > w) {
			struct hash_item *restrict q = &(table->p[w]);
			q->hash = p->hash;
			q->key = p->key;
			q->element = p->element;
			p->hash = -1;
		}
		w++;
	}
	table->freelist = -1;
}

static inline void table_rehash(struct hashtable *restrict table)
{
	/*  table must be compacted */
	assert(table->freelist == -1);
	/* perform rehash */
	const int size = table->size;
	const int capacity = table->capacity;
	const uint32_t seed = table->seed;
	for (int i = 0; i < size; i++) {
		struct hash_item *restrict p = &(table->p[i]);
		const int hash = get_hash(p->key, seed);
		const int bucket = hash % capacity;
		p->hash = hash;
		p->next = table->p[bucket].bucket;
		table->p[bucket].bucket = i;
	}
}

static inline void
table_realloc(struct hashtable *restrict table, const int new_capacity)
{
	const int old_capacity = table->capacity;
	if (old_capacity == new_capacity) {
		return;
	}
	assert(new_capacity >= table->size);
	const size_t item_size = new_capacity * sizeof(struct hash_item);
	struct hash_item *m = (struct hash_item *)realloc(table->p, item_size);
	if (m == NULL) {
		return;
	}
#if HASHTABLE_LOG
	if (table->p != NULL && table->p != m) {
		fprintf(stderr, " * realloc moved memory from %p to %p\n",
			(void *)table->p, (void *)m);
	}
#endif
	table->p = m;
	table->capacity = new_capacity;
	/* max load factor: 1.0 - normal, 0.75 - fast */
	if (table->flags & TABLE_FAST) {
		table->max_load = new_capacity / 4 * 3;
	} else {
		table->max_load = new_capacity;
	}

	if (new_capacity > old_capacity) {
		/* init newly allocated memory */
		table_init(table, old_capacity);
	}
}

static inline void table_grow(struct hashtable *restrict table)
{
	const int want = table->size / 3 + 1;
	int estimated = table->size;
	if (estimated < (INT_MAX - want)) {
		estimated += want;
	} else {
		estimated = INT_MAX;
	}
	table_reserve(table, estimated);
}

static inline void table_reseed(struct hashtable *restrict table)
{
	table->seed = (uint32_t)rand64();
#if HASHTABLE_LOG
	fprintf(stderr, "table reseed: size=%d new_seed=%" PRIX32 "\n",
		table->size, table->seed);
#endif
	table_compact(table);
	table_rehash(table);
}

void *
table_set(struct hashtable *restrict table, const hashkey_t *key, void *element)
{
	assert(element != NULL);
	const int hash = get_hash(key, table->seed);
	int bucket = hash % table->capacity;
	int collision = 0;
	for (int i = table->p[bucket].bucket; i >= 0; i = table->p[i].next) {
		struct hash_item *restrict p = &(table->p[i]);
		if (p->hash == hash && KEY_EQUALS(p->key, key)) {
			/* replace existing element */
			void *old_elem = p->element;
			p->key = key;
			p->element = element;
#ifndef NDEBUG
			table->version++;
#endif
			if (collision > COLLISION_THRESHOLD) {
				table_reseed(table);
			}
			return old_elem;
		}
		collision++;
	}

	int index;
	if (table->freelist >= 0) {
		assert(table->size < table->capacity);
		index = table->freelist;
		table->freelist = table->p[index].next;
		table->size++;
	} else {
		if (table->size >= table->max_load) {
			table_grow(table);
			if (table->size == table->capacity) {
				/* allocation failed */
				return element;
			}
			bucket = hash % table->capacity;
		}
		index = table->size;
		table->size++;
	}

	struct hash_item *restrict p = &(table->p[index]);
	p->key = key;
	p->element = element;
	p->hash = hash;
	int *old_bucket = &(table->p[bucket].bucket);
	p->next = *old_bucket;
	*old_bucket = index;
#ifndef NDEBUG
	table->version++;
#endif

	if (collision > COLLISION_THRESHOLD) {
		table_reseed(table);
	}
	return NULL;
}

void *table_find(const struct hashtable *restrict table, const hashkey_t *key)
{
	const int hash = get_hash(key, table->seed);
	const int bucket = hash % table->capacity;
	for (int i = table->p[bucket].bucket; i >= 0; i = table->p[i].next) {
		struct hash_item *restrict p = &(table->p[i]);
		if (p->hash == hash && KEY_EQUALS(p->key, key)) {
			/* found */
			return p->element;
		}
	}
	return NULL;
}

void *table_del(struct hashtable *restrict table, const hashkey_t *key)
{
	const int hash = get_hash(key, table->seed);
	int bucket = hash % table->capacity;
	int *last_next = &(table->p[bucket].bucket);
	for (int i = *last_next; i >= 0; i = *last_next) {
		struct hash_item *restrict p = &(table->p[i]);
		if (p->hash == hash && KEY_EQUALS(p->key, key)) {
			*last_next = p->next;
			p->hash = -1;
			p->next = table->freelist;
			table->freelist = i;
			table->size--;
#ifndef NDEBUG
			table->version++;
#endif
			return p->element;
		}
		last_next = &(p->next);
	}
	return NULL;
}

void table_free(struct hashtable *restrict table)
{
	if (table != NULL) {
		free(table->p);
	}
	free(table);
}

void table_reserve(struct hashtable *restrict table, const int new_size)
{
	int new_capacity = new_size;
	if (new_capacity < table->size) {
		new_capacity = table->size;
	}
	if (table->flags & TABLE_FAST) {
		const int want = new_size / 3 + 1;
		if (new_capacity < (INT_MAX - want)) {
			new_capacity += want;
		} else {
			new_capacity = INT_MAX;
		}
	}
	new_capacity = ceil_capacity(new_capacity);
	if (table->capacity == new_capacity) {
		return;
	}
#if HASHTABLE_LOG
	fprintf(stderr, "table resize: size=%d capacity=%d new_capacity=%d\n",
		table->size, table->capacity, new_capacity);
#endif
#ifndef NDEBUG
	table->version++;
#endif
	table_compact(table);
	table_realloc(table, new_capacity);
	table_rehash(table);
}

struct hashtable *table_new(const int flags)
{
	struct hashtable *restrict table = malloc(sizeof(struct hashtable));
	if (table == NULL) {
		return NULL;
	}
	*table = (struct hashtable){
		.p = NULL,
		.size = 0,
		.capacity = 0,
		.max_load = 0,
		.freelist = -1,
		.seed = (uint32_t)rand64(),
		.flags = flags,
#ifndef NDEBUG
		.version = 0,
#endif
	};
	table_realloc(table, INITIAL_CAPACITY);
	if (table->p == NULL) {
		free(table);
		return NULL;
	}
	return table;
}

void table_filter(
	struct hashtable *restrict table, table_iterate_cb f, void *data)
{
	if (table->size == 0) {
		return;
	}
#ifndef NDEBUG
	const unsigned int version = table->version;
#endif
	const int capacity = table->capacity;
	for (int bucket = 0; bucket < capacity; bucket++) {
		int *last_next = &(table->p[bucket].bucket);
		for (int i = *last_next; i >= 0; i = *last_next) {
#ifndef NDEBUG
			assert(version == table->version);
#endif
			struct hash_item *restrict p = &(table->p[i]);
			const bool ok = f(table, p->key, p->element, data);
			if (ok) {
				last_next = &(p->next);
				continue;
			}
			/* delete item */
			*last_next = p->next;
			p->hash = -1;
			p->next = table->freelist;
			table->freelist = i;
			table->size--;
		}
	}
}

void table_iterate(
	const struct hashtable *restrict table, table_iterate_cb f, void *data)
{
	if (table->size == 0) {
		return;
	}
#ifndef NDEBUG
	const unsigned int version = table->version;
#endif
	const int capacity = table->capacity;
	for (int i = 0; i < capacity; i++) {
#ifndef NDEBUG
		assert(version == table->version);
#endif
		struct hash_item *restrict p = &(table->p[i]);
		if (p->hash < 0) {
			continue;
		}
		if (!f(table, p->key, p->element, data)) {
			return;
		}
	}
}

int table_size(const struct hashtable *restrict table)
{
	return table->size;
}
