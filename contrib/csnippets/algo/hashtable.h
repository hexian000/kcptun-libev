/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef HASHTABLE_H
#define HASHTABLE_H
/* hashtable is an unordered map whose keys are of fixed length */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef HASHKEY_LEN
#define HASHKEY_LEN 32
#endif

typedef struct {
	unsigned char raw[HASHKEY_LEN];
} hashkey_t;

struct hashtable;

typedef bool (*table_iterate_cb)(
	struct hashtable *table, const hashkey_t *key, void *value, void *data);

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
 * @brief Insert or assign to an item in the table.
 * @param table Pointer to the table.
 * @param key The key to insert or assign to.
 * @param value The new value.
 * @return false only if table size will exceed INT_MAX
 */
bool table_set(struct hashtable *table, const hashkey_t *key, void *value);

/**
 * @brief Find an item by key.
 * @param table Pointer to the table.
 * @param key The key to find.
 * @param value Stores value of the found item. Pass NULL if you don't care
 * about the value. If the key can't be found, the value is unchanged.
 * @return true if the key can be found.
 */
bool table_find(struct hashtable *table, const hashkey_t *key, void **value);

/**
 * @brief Delete an item by key.
 * @param table Pointer to the table.
 * @param key The key to find and delete.
 * @param value Stores old value of the item. Pass NULL if you don't care
 * about the value. If the key can't be found, the value is unchanged.
 * @return true if the key can be found.
 */
bool table_del(struct hashtable *table, const hashkey_t *key, void **value);

/**
 * @brief Delete items while iterating over the table.
 * @param table Pointer to the table.
 * @param f Callback function, return false to delete.
 * @param data Directly passed to f
 */
void table_filter(struct hashtable *table, table_iterate_cb f, void *data);

/**
 * @brief Iterate over a table.
 * @param table Pointer to the table.
 * @param f Callback function, return true to continue.
 * @param data Directly passed to f
 */
void table_iterate(struct hashtable *table, table_iterate_cb f, void *data);

/**
 * @brief Get the item count in a table.
 * @param table Pointer to the table.
 * @return Number of items in the table.
 */
int table_size(struct hashtable *table);

#endif /* HASHTABLE_H */
