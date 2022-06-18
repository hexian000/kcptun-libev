#include "hashtable.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#ifndef NDEBUG
#include <stdio.h>
#endif

#define countof(x) (sizeof(x) / sizeof((x)[0]))

/* start from 2^4 */
static const int prime_list[] = {
	13,   31,    61,    127,   251,	   509,	   1021,   2039,    4093,
	8191, 16381, 32749, 65521, 131071, 262139, 524287, 1048573, 2097143,
};

#define INITIAL_CAPACITY (prime_list[0])

static inline int get_capacity(int x)
{
	const int threshold = prime_list[countof(prime_list) - 1];
	if (x > threshold) {
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
};

static inline bool
key_equals(const hashkey_t *restrict a, const hashkey_t *restrict b)
{
	return memcmp(a, b, sizeof(hashkey_t)) == 0;
}

/* Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs" */
static inline uint32_t xorshift32(uint32_t x)
{
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return x;
}

static inline int get_hash(const hashkey_t *restrict key)
{
	uint32_t h = 0;
	for (size_t i = 0; i < sizeof(hashkey_t) / sizeof(uint32_t); i++) {
		h = xorshift32(key->b[i] ^ h);
	}
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
	for (int i = 0; i < size; i++) {
		struct hash_item *restrict p = &(table->p[i]);
		const int hash = get_hash(&p->key);
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
#ifndef NDEBUG
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
	const int threshold = prime_list[countof(prime_list) - 1];
	if (table->size < threshold) {
		/* will fit next number in prime_list */
		table_reserve(table, table->size + 1);
	} else if (table->size < (INT_MAX - threshold)) {
		table_reserve(table, table->size + threshold);
	} else {
		table_reserve(table, INT_MAX);
	}
}

bool table_set(
	struct hashtable *restrict table, const hashkey_t *key, void *value)
{
	const int hash = get_hash(key);
	int bucket = hash % table->capacity;
	for (int i = table->p[bucket].bucket; i >= 0; i = table->p[i].next) {
		struct hash_item *restrict p = &(table->p[i]);
		if (p->hash == hash && key_equals(&p->key, key)) {
			/* overwrite */
			p->value = value;
			return true;
		}
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
	p->key = *key;
	p->value = value;
	p->hash = hash;
	int *old_bucket = &(table->p[bucket].bucket);
	p->next = *old_bucket;
	*old_bucket = index;

	return true;
}

bool table_find(
	struct hashtable *restrict table, const hashkey_t *key, void **value)
{
	const int hash = get_hash(key);
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
	const int hash = get_hash(key);
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
			return true;
		}
		last_next = &(p->next);
	}
	return false;
}

void table_free(struct hashtable *restrict table)
{
	if (table->p != NULL) {
		free(table->p);
	}
	free(table);
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
#ifndef NDEBUG
	fprintf(stderr, "table resize: capacity=%d new_capacity=%d\n",
		table->capacity, new_capacity);
#endif
	table_compact(table);
	table_realloc(table, new_capacity);
	table_rehash(table);
}

struct hashtable *table_create()
{
	struct hashtable *table = malloc(sizeof(struct hashtable));
	if (table == NULL) {
		return NULL;
	}
	*table = (struct hashtable){
		.p = NULL,
		.capacity = 0,
		.size = 0,
		.freelist = -1,
	};
	int capacity = INITIAL_CAPACITY;
	table_realloc(table, capacity);
	if (table->p == NULL) {
		free(table);
		return NULL;
	}
	return table;
}

int table_size(struct hashtable *restrict table)
{
	return table->size;
}

void table_filter(
	struct hashtable *restrict table, table_iterate_cb f, void *context)
{
	int count = 0;
	const int capacity = table->capacity;
	for (int bucket = 0; bucket < capacity; bucket++) {
		int *last_next = &(table->p[bucket].bucket);
		for (int i = *last_next; i >= 0; i = *last_next) {
			struct hash_item *restrict p = &(table->p[i]);
			const bool ok = f(table, &p->key, p->value, context);
			count++;
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
	struct hashtable *restrict table, table_iterate_cb f, void *context)
{
	const int capacity = table->capacity;
	for (int i = 0; i < capacity; i++) {
		struct hash_item *restrict p = &(table->p[i]);
		if (p->hash < 0) {
			continue;
		}
		if (!f(table, &p->key, p->value, context)) {
			return;
		}
	}
}
