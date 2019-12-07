#include "conv.h"
#include "util.h"

#include <assert.h>
#include <limits.h>
#include <math.h>
#include <string.h>

#define INITIAL_CAPACITY 256

struct conv_item {
	int hash, next;
	uint32_t conv;
	void *session;
};

struct conv_table {
	int *buckets;
	struct conv_item *p;
	size_t size, capacity;
	int freelist;
};

static inline bool is_prime(size_t x)
{
	assert(x > 2);
	size_t n = (size_t)sqrt((double)x);
	for (size_t i = 2; i <= n; i++) {
		if (x % i == 0) {
			return false;
		}
	}
	return true;
}

static inline size_t get_prime(size_t x)
{
	assert(x > 2);
	size_t n;
	for (n = x | 1u; !is_prime(n); n += 2) {
	}
	return n;
}

static inline int get_hash(uint32_t key)
{
	return key & 0x7FFFFFFFu;
}

static void table_resize(struct conv_table * /*table*/);

static inline void table_set(struct conv_table *restrict table, uint32_t conv,
			     void *session, bool add)
{
	int hash = get_hash(conv);
	int bucket = hash % table->capacity;
	for (int i = table->buckets[bucket]; i >= 0; i = table->p[i].next) {
		struct conv_item *restrict p = &(table->p[i]);
		if (p->hash == hash && p->conv == conv) {
			/* overwrite */
			UTIL_ASSERT(!add);
			p->session = session;
			return;
		}
	}

	assert(table->size < (size_t)INT_MAX);
	int index;
	if (table->freelist >= 0) {
		index = table->freelist;
		table->freelist = table->p[index].next;
		table->size++;
	} else {
		if (table->size == table->capacity) {
			table_resize(table);
			bucket = hash % table->capacity;
		}
		index = (int)table->size;
		table->size++;
	}

	table->p[index] = (struct conv_item){
		.conv = conv,
		.session = session,
		.hash = hash,
		.next = table->buckets[bucket],
	};
	table->buckets[bucket] = index;
}

static inline bool table_find(struct conv_table *restrict table, uint32_t conv,
			      void **session)
{
	int hash = get_hash(conv);
	int bucket = hash % table->capacity;
	for (int i = table->buckets[bucket]; i >= 0; i = table->p[i].next) {
		struct conv_item *restrict p = &(table->p[i]);
		assert(p->hash >= 0);
		if (p->hash == hash && p->conv == conv) {
			/* found */
			if (session != NULL) {
				*session = p->session;
			}
			return true;
		}
	}
	return false;
}

static inline bool table_del(struct conv_table *restrict table, uint32_t conv)
{
	int hash = get_hash(conv);
	int bucket = hash % table->capacity;
	int *last_next = &(table->buckets[bucket]);
	for (int i = *last_next; i >= 0; i = *last_next) {
		struct conv_item *restrict p = &(table->p[i]);
		assert(p->hash >= 0);
		if (p->hash == hash && p->conv == conv) {
			*last_next = p->next;
			*p = (struct conv_item){
				.conv = 0,
				.session = NULL,
				.hash = -1,
				.next = table->freelist,
			};
			table->freelist = i;
			table->size--;
			return true;
		}
		last_next = &(p->next);
	}
	return false;
}

static inline void table_init(struct conv_table *restrict table,
			      size_t capacity)
{
	capacity = get_prime(capacity);
	assert(capacity < (size_t)INT_MAX);
	const size_t size_in_bytes = capacity * sizeof(struct conv_item);
	*table = (struct conv_table){
		.capacity = capacity,
		.size = 0,
		.p = util_malloc(size_in_bytes),
		.buckets = util_malloc(capacity * sizeof(int)),
		.freelist = -1,
	};
	assert(table->p);
	assert(table->buckets);
	/* initialize buckets */
	for (size_t i = 0; i < capacity; i++) {
		table->buckets[i] = -1;
	}
	/* initialize entries */
	for (size_t i = 0; i < capacity; i++) {
		table->p[i] = (struct conv_item){
			.conv = 0,
			.session = NULL,
			.hash = -1,
			.next = -1,
		};
	}
}

static inline void table_free(struct conv_table *restrict table)
{
	if (table->p != NULL) {
		util_free(table->p);
	}
	if (table->buckets != NULL) {
		util_free(table->buckets);
	}
	*table = (struct conv_table){
		.capacity = 0,
		.size = 0,
		.p = NULL,
		.buckets = NULL,
		.freelist = -1,
	};
}

static void table_resize(struct conv_table *restrict table)
{
	assert(table->size == table->capacity);
	struct conv_table new_table;
	table_init(&new_table, table->size * 2);
	LOGF_D("resize: capacity=%zu new_capacity=%zu", table->capacity,
	       new_table.capacity);
	for (int i = 0; i < (int)table->capacity; i++) {
		struct conv_item *restrict p = &(new_table.p[i]);
		*p = table->p[i];
		if (p->hash >= 0) {
			int bucket = p->hash % new_table.capacity;
			p->next = new_table.buckets[bucket];
			new_table.buckets[bucket] = i;
		}
	}
	new_table.size = table->size;
	table_free(table);
	*table = new_table;
}

struct conv_table *conv_table_create()
{
	struct conv_table *table = util_malloc(sizeof(struct conv_table));
	if (table == NULL) {
		return NULL;
	}
	table_init(table, INITIAL_CAPACITY);
	return table;
}

void conv_table_free(struct conv_table *restrict table)
{
	table_free(table);
	util_free(table);
}

uint32_t conv_new(struct conv_table *restrict table)
{
	/* 0 is reserved */
	uint32_t conv;
	do {
		conv = rand_uint32();
	} while (table_find(table, conv, NULL));
	return conv;
}

void conv_insert(struct conv_table *restrict table, uint32_t conv,
		 void *session)
{
	table_set(table, conv, session, true);
}

void conv_free(struct conv_table *restrict table, uint32_t conv)
{
	UTIL_ASSERT(table_del(table, conv));
}

void *conv_find(struct conv_table *restrict table, uint32_t conv)
{
	void *session;
	if (!table_find(table, conv, &session)) {
		return NULL;
	}
	return session;
}

size_t conv_size(struct conv_table *restrict table)
{
	return table->size;
}

static inline bool conv_iterate_chain(struct conv_table *restrict table,
				      conv_iterate_cb f, void *user, int bucket)
{
	int *last_next = &(table->buckets[bucket]);
	for (int i = *last_next; i >= 0; i = *last_next) {
		struct conv_item *restrict p = &(table->p[i]);
		assert(p->hash >= 0);
		bool delete = false;
		const bool continu =
			f(table, p->conv, p->session, user, &delete);
		if (delete) {
			*last_next = p->next;
			*p = (struct conv_item){
				.conv = 0,
				.session = NULL,
				.hash = -1,
				.next = table->freelist,
			};
			table->freelist = i;
			table->size--;
		} else {
			last_next = &(p->next);
		}
		if (!continu) {
			return false;
		}
	}
	return true;
}

void conv_iterate(struct conv_table *restrict table, conv_iterate_cb f,
		  void *user)
{
	for (int bucket = 0; bucket < (int)table->capacity; bucket++) {
		if (!conv_iterate_chain(table, f, user, bucket)) {
			return;
		}
	}
}
