/* csnippets (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef ALGO_HASHTABLE_H
#define ALGO_HASHTABLE_H

#include <stdbool.h>
#include <stddef.h>

/**
 * @defgroup hashtable
 * @brief An unordered map container implemented with a hash table.
 * @{
 */

struct hashkey {
	size_t len;
	const void *data; /* the pointer should be contained in the element */
};

struct hashtable;

typedef bool (*table_iterate_cb)(
	const struct hashtable *table, struct hashkey key, void *element,
	void *data);

enum table_flags {
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
 * @param table Pointer to the table is invalidated after call.
 * @param new_size Expected new table size.
 * @return Pointer to the modified table.
 * @details 1. Preallocate memory for faster table filling. <br>
 * 2. Passing any new_size less than current size to shrink a table.
 */
struct hashtable *table_reserve(struct hashtable *table, size_t new_size);

/**
 * @brief Insert or assign to an element in the table.
 * @param table Pointer to the table is invalidated after call.
 * @param key The key of the new element.
 * @param[inout] element The new element in, the replaced element out.
 * If allocation failed or the table size will exceed INT_MAX, no operation
 * is performed and the new element is returned.
 * @return Pointer to the modified table.
 */
struct hashtable *
table_set(struct hashtable *table, struct hashkey key, void **element);

/**
 * @brief Find an element by key.
 * @param table Pointer to the table.
 * @param key The key to find.
 * @param[out] element If found, returns the element when not NULL. Otherwise
 * undefined.
 * @return false if not found.
 */
bool table_find(
	const struct hashtable *table, struct hashkey key, void **element);

/**
 * @brief Delete an element by key.
 * @param table Pointer to the table is invalidated after call.
 * @param key The key to find and delete.
 * @param[out] element The existing element or NULL.
 * @return Pointer to the modified table.
 */
struct hashtable *
table_del(struct hashtable *table, struct hashkey key, void **element);

/**
 * @brief Delete elements while iterating over the table.
 * @param table Pointer to the table is invalidated after call.
 * @param f Callback function, return false to delete.
 * @param data Transparently passed to f
 * @return Pointer to the modified table.
 */
struct hashtable *
table_filter(struct hashtable *table, table_iterate_cb f, void *data);

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
size_t table_size(const struct hashtable *table);

/** @} */

#endif /* ALGO_HASHTABLE_H */
