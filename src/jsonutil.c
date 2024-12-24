/* kcptun-libev (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "jsonutil.h"

#include "utils/debug.h"

#include <json-c/json.h>

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct jutil_value;

struct jutil_value *jutil_parse(const char *json, size_t length)
{
	if (length > INT_MAX) {
		return NULL;
	}
	struct json_tokener *tok = json_tokener_new();
	if (tok == NULL) {
		return NULL;
	}
	struct json_object *obj = json_tokener_parse_ex(tok, json, (int)length);
	json_tokener_free(tok);
	return (struct jutil_value *)obj;
}

struct jutil_value *jutil_parsefile(const char *filename)
{
	return (struct jutil_value *)json_object_from_file(filename);
}

void jutil_free(struct jutil_value *value)
{
	if (value == NULL) {
		return;
	}
	CHECK(json_object_put((struct json_object *)value));
}

bool jutil_walk_object(
	void *ud, const struct jutil_value *value, jutil_walk_object_cb cb)
{
	struct json_object *obj = (struct json_object *)value;
	if (!json_object_is_type(obj, json_type_object)) {
		return false;
	}
	const struct json_object_iterator it_end = json_object_iter_end(obj);
	for (struct json_object_iterator it = json_object_iter_begin(obj);
	     !json_object_iter_equal(&it, &it_end);
	     json_object_iter_next(&it)) {
		const char *k = json_object_iter_peek_name(&it);
		struct json_object *v = json_object_iter_peek_value(&it);
		if (!cb(ud, k, (struct jutil_value *)v)) {
			return false;
		}
	}
	return true;
}

bool jutil_walk_array(
	void *ud, const struct jutil_value *value, jutil_walk_array_cb cb)
{
	struct json_object *obj = (struct json_object *)value;
	if (!json_object_is_type(obj, json_type_array)) {
		return false;
	}
	const size_t n = json_object_array_length(obj);
	for (size_t i = 0; i < n; i++) {
		struct json_object *v = json_object_array_get_idx(obj, i);
		if (!cb(ud, (struct jutil_value *)v)) {
			return false;
		}
	}
	return true;
}

bool jutil_get_bool(const struct jutil_value *value, bool *b)
{
	struct json_object *obj = (struct json_object *)value;
	if (!json_object_is_type(obj, json_type_boolean)) {
		return false;
	}
	if (b != NULL) {
		*b = json_object_get_boolean(obj);
	}
	return true;
}

bool jutil_get_int(const struct jutil_value *value, int *i)
{
	struct json_object *obj = (struct json_object *)value;
	if (!json_object_is_type(obj, json_type_int)) {
		return false;
	}
	if (i != NULL) {
		*i = json_object_get_int(obj);
	}
	return true;
}

const char *jutil_get_lstring(const struct jutil_value *value, size_t *len)
{
	struct json_object *obj = (struct json_object *)value;
	if (!json_object_is_type(obj, json_type_string)) {
		return NULL;
	}
	if (len != NULL) {
		*len = json_object_get_string_len(obj);
	}
	return json_object_get_string(obj);
}

const char *jutil_get_string(const struct jutil_value *value)
{
	return jutil_get_lstring(value, NULL);
}

char *jutil_dup_lstring(const struct jutil_value *value, size_t *len)
{
	size_t n;
	const char *s = jutil_get_lstring(value, &n);
	if (s == NULL) {
		return NULL;
	}
	if (len != NULL) {
		*len = n;
	}
	return strndup(s, n);
}

char *jutil_dup_string(const struct jutil_value *value)
{
	size_t n;
	const char *s = jutil_get_lstring(value, &n);
	if (s == NULL) {
		return NULL;
	}
	return strndup(s, n);
}
