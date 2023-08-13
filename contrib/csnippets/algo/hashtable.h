/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef ALGO_HASHTABLE_H
#define ALGO_HASHTABLE_H

#include "utils/buffer.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @defgroup hashtable
 * @brief An unordered map container implemented with a hash table.
 * @{
 */

typedef struct vbuffer hashkey_t;

struct hashtable;

typedef bool (*table_iterate_cb)(
	const struct hashtable *table, const hashkey_t *key, void *element,
	void *data);

enum table_flags {
	TABLE_DEFAULT = 0,
	/* set max load factor to 75%, trading space for speed */
	TABLE_FAST = 1 << 0,
};

/**
 * @brief Create a new hash table.
 * @param flags Any combination of enum table_flags.
 * @return Pointer to the newly created table.
 */
struct hashtable *table_new(int flags);

/**
 * @brief Free all memory used by a table.
 * @param table Pointer to the table.
 */
void table_free(struct hashtable *table);

/**
 * @brief Explicitly reallocate memory for the table.
 * @details 1. Preallocate memory for faster table filling. <br>
 * 2. Passing any new_size less than current size to shrink a table.
 * @param table Pointer to the table.
 * @param new_size Expected new table size.
 */
void table_reserve(struct hashtable *table, int new_size);

/**
 * @brief Insert or assign to an element in the table.
 * @param table Pointer to the table.
 * @param key The key of the new element.
 * @param element The new element where the key should be stored, not NULL.
 * @return When success, the existing element or NULL. If allocation failed or
 * the table size will exceed INT_MAX, no operation is performed and the new
 * element is returned.
 */
void *table_set(struct hashtable *table, const hashkey_t *key, void *element);

/**
 * @brief Find an element by key.
 * @param table Pointer to the table.
 * @param key The key to find.
 * @return The existing element or NULL.
 */
void *table_find(const struct hashtable *table, const hashkey_t *key);

/**
 * @brief Delete an element by key.
 * @param table Pointer to the table.
 * @param key The key to find and delete.
 * @return The existing element or NULL.
 */
void *table_del(struct hashtable *table, const hashkey_t *key);

/**
 * @brief Delete elements while iterating over the table.
 * @param table Pointer to the table.
 * @param f Callback function, return false to delete.
 * @param data Transparently passed to f
 */
void table_filter(struct hashtable *table, table_iterate_cb f, void *data);

/**
 * @brief Iterate over a table.
 * @param table Pointer to the table.
 * @param f Callback function, return true to continue.
 * @param data Transparently passed to f
 */
void table_iterate(
	const struct hashtable *table, table_iterate_cb f, void *data);

/**
 * @brief Get the number of elements in a table.
 * @param table Pointer to a table.
 * @return The number of elements in the table.
 */
int table_size(const struct hashtable *table);

/** @} */

#endif /* ALGO_HASHTABLE_H */
