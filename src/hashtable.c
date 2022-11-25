#include "hashtable.h"
#include "util.h"
#include "murmur3/murmurhash3.h"

#include <assert.h>
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
	13,   31,    61,    127,   251,	   509,	   1021,   2039,    4093,
	8191, 16381, 32749, 65521, 131071, 262139, 524287, 1048573, 2097143,
};

#define COLLISION_THRESHOLD 100

#define INITIAL_CAPACITY (prime_list[0])

static inline int get_capacity(int x)
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
	hashkey_t key;
	void *value;
};

struct hashtable {
	struct hash_item *p;
	int size, capacity;
	int freelist;
	uint32_t seed;
#ifndef NDEBUG
	unsigned int version;
#endif
};

static inline bool key_equals(const hashkey_t *a, const hashkey_t *b)
{
	return memcmp(a, b, sizeof(hashkey_t)) == 0;
}

static inline void key_set(hashkey_t *dst, const hashkey_t *src)
{
	memcpy(dst, src, sizeof(hashkey_t));
}

static inline int get_hash(const hashkey_t *restrict x, const uint32_t seed)
{
	const uint32_t h = murmurhash3(x, sizeof(hashkey_t), seed);
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
			key_set(&q->key, &p->key);
			q->value = p->value;
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
		const int hash = get_hash(&p->key, seed);
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
	struct hash_item *m =
		(struct hash_item *)util_realloc(table->p, item_size);
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

	if (new_capacity > old_capacity) {
		/* init newly allocated memory */
		table_init(table, old_capacity);
	}
}

static inline void table_grow(struct hashtable *restrict table)
{
	const int last_prime = prime_list[ARRAY_SIZE(prime_list) - 1];
	if (table->size < last_prime) {
		/* will fit next number in prime_list */
		table_reserve(table, table->size + 1);
	} else if (table->size < (INT_MAX - last_prime)) {
		table_reserve(table, table->size + last_prime);
	} else {
		table_reserve(table, INT_MAX);
	}
}

static inline void table_reseed(struct hashtable *restrict table)
{
	table->seed = rand32();
#if HASHTABLE_LOG
	fprintf(stderr, "table reseed: size=%d new_seed=%" PRIX32 "\n",
		table->size, table->seed);
#endif
	table_compact(table);
	table_rehash(table);
}

bool table_set(
	struct hashtable *restrict table, const hashkey_t *key, void *value)
{
	const int hash = get_hash(key, table->seed);
	int bucket = hash % table->capacity;
	int collision = 0;
	for (int i = table->p[bucket].bucket; i >= 0; i = table->p[i].next) {
		struct hash_item *restrict p = &(table->p[i]);
		if (p->hash == hash && key_equals(&p->key, key)) {
			/* overwrite */
			p->value = value;
#ifndef NDEBUG
			table->version++;
#endif
			if (collision > COLLISION_THRESHOLD) {
				table_reseed(table);
			}
			return true;
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
		if (table->size == table->capacity) {
			table_grow(table);
			if (table->size == table->capacity) {
				// cannot grow, return failure
				return false;
			}
			bucket = hash % table->capacity;
		}
		index = table->size;
		table->size++;
	}

	struct hash_item *restrict p = &(table->p[index]);
	key_set(&p->key, key);
	p->value = value;
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
	return true;
}

bool table_find(
	struct hashtable *restrict table, const hashkey_t *key, void **value)
{
	const int hash = get_hash(key, table->seed);
	int bucket = hash % table->capacity;
	for (int i = table->p[bucket].bucket; i >= 0; i = table->p[i].next) {
		struct hash_item *restrict p = &(table->p[i]);
		if (p->hash == hash && key_equals(&p->key, key)) {
			/* found */
			if (value != NULL) {
				*value = p->value;
			}
			return true;
		}
	}
	return false;
}

bool table_del(
	struct hashtable *restrict table, const hashkey_t *key, void **value)
{
	const int hash = get_hash(key, table->seed);
	int bucket = hash % table->capacity;
	int *last_next = &(table->p[bucket].bucket);
	for (int i = *last_next; i >= 0; i = *last_next) {
		struct hash_item *restrict p = &(table->p[i]);
		if (p->hash == hash && key_equals(&p->key, key)) {
			if (value != NULL) {
				*value = p->value;
			}
			*last_next = p->next;
			p->hash = -1;
			p->next = table->freelist;
			table->freelist = i;
			table->size--;
#ifndef NDEBUG
			table->version++;
#endif
			return true;
		}
		last_next = &(p->next);
	}
	return false;
}

void table_free(struct hashtable *restrict table)
{
	if (table->p != NULL) {
		util_free(table->p);
	}
	util_free(table);
}

void table_reserve(struct hashtable *restrict table, int new_capacity)
{
	if (new_capacity < table->size) {
		new_capacity = table->size;
	}
	new_capacity = get_capacity(new_capacity);
	if (table->capacity == new_capacity) {
		return;
	}
#if HASHTABLE_LOG
	fprintf(stderr, "table resize: size=%d capacity=%d new_capacity=%d\n",
		table->size, table->capacity, new_capacity);
#endif
	table_compact(table);
	table_realloc(table, new_capacity);
	table_rehash(table);
}

struct hashtable *table_create(void)
{
	struct hashtable *table = util_malloc(sizeof(struct hashtable));
	if (table == NULL) {
		return NULL;
	}
	*table = (struct hashtable){
		.p = NULL,
		.capacity = 0,
		.size = 0,
		.freelist = -1,
		.seed = rand32(),
#ifndef NDEBUG
		.version = 0,
#endif
	};
	int capacity = INITIAL_CAPACITY;
	table_realloc(table, capacity);
	if (table->p == NULL) {
		util_free(table);
		return NULL;
	}
	return table;
}

int table_size(struct hashtable *restrict table)
{
	return table->size;
}

void table_filter(
	struct hashtable *restrict table, table_iterate_cb f, void *data)
{
#ifndef NDEBUG
	const unsigned int version = table->version;
#endif
	const int capacity = table->capacity;
	for (int bucket = 0; bucket < capacity; bucket++) {
		int *last_next = &(table->p[bucket].bucket);
		for (int i = *last_next; i >= 0; i = *last_next) {
			assert(version == table->version);
			struct hash_item *restrict p = &(table->p[i]);
			const bool ok = f(table, &p->key, p->value, data);
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
	struct hashtable *restrict table, table_iterate_cb f, void *data)
{
#ifndef NDEBUG
	const unsigned int version = table->version;
#endif
	const int capacity = table->capacity;
	for (int i = 0; i < capacity; i++) {
		assert(version == table->version);
		struct hash_item *restrict p = &(table->p[i]);
		if (p->hash < 0) {
			continue;
		}
		if (!f(table, &p->key, p->value, data)) {
			return;
		}
	}
}
