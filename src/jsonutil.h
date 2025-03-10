/* kcptun-libev (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef JSONUTIL_H
#define JSONUTIL_H

#include <stdbool.h>
#include <stddef.h>

struct jutil_value; /* opaque */

struct jutil_value *jutil_parse(const char *json, size_t length);
struct jutil_value *jutil_parsefile(const char *filename);

void jutil_free(struct jutil_value *value);

typedef bool (*jutil_walk_object_cb)(
	void *ud, const char *key, const struct jutil_value *value);
bool jutil_walk_object(
	void *ud, const struct jutil_value *obj, jutil_walk_object_cb cb);

typedef bool (*jutil_walk_array_cb)(void *ud, const struct jutil_value *value);
bool jutil_walk_array(
	void *ud, const struct jutil_value *arr, jutil_walk_array_cb cb);

bool jutil_get_bool(const struct jutil_value *value, bool *b);

bool jutil_get_int(const struct jutil_value *value, int *i);

const char *jutil_get_lstring(const struct jutil_value *value, size_t *len);
const char *jutil_get_string(const struct jutil_value *value);

char *jutil_dup_lstring(const struct jutil_value *value, size_t *len);
char *jutil_dup_string(const struct jutil_value *value);

#endif /* JSONUTIL_H */
