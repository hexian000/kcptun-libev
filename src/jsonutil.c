/* kcptun-libev (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "jsonutil.h"
#include "utils/slog.h"

#include "json.h"

#include <limits.h>
#include <string.h>

struct jutil_value;

struct jutil_value *jutil_parse(const char *json, size_t length)
{
	char error_msg[json_error_max];
	json_value *obj =
		json_parse_ex(&(json_settings){ 0 }, json, length, error_msg);
	if (obj == NULL) {
		LOGE_F("failed parsing json: %s", error_msg);
	}
	return (struct jutil_value *)obj;
}

void jutil_free(struct jutil_value *value)
{
	json_value *v = (json_value *)value;
	json_value_free(v);
}

bool jutil_walk_object(
	void *ud, const struct jutil_value *value, jutil_walk_object_cb cb)
{
	const json_value *restrict v = (const json_value *)value;
	if (v == NULL || v->type != json_object) {
		return false;
	}

	for (unsigned int i = 0; i < v->u.object.length; i++) {
		if (!cb(ud, v->u.object.values[i].name,
			v->u.object.values[i].name_length,
			(struct jutil_value *)v->u.object.values[i].value)) {
			return false;
		}
	}
	return true;
}

bool jutil_walk_array(
	void *ud, const struct jutil_value *value, jutil_walk_array_cb cb)
{
	const json_value *restrict v = (const json_value *)value;
	if (v == NULL || v->type != json_array) {
		return false;
	}

	for (unsigned int i = 0; i < v->u.array.length; i++) {
		if (!cb(ud, (struct jutil_value *)v->u.array.values[i])) {
			return false;
		}
	}
	return true;
}

bool jutil_get_bool(const struct jutil_value *value, bool *b)
{
	const json_value *v = (const json_value *)value;
	if (v->type != json_boolean) {
		return false;
	}
	if (b != NULL) {
		*b = !!(v->u.boolean);
	}
	return true;
}

bool jutil_get_int(const struct jutil_value *value, int *i)
{
	const json_value *v = (const json_value *)value;
	if (v->type != json_integer) {
		return false;
	}
	if (v->u.integer < INT_MIN && INT_MAX < v->u.integer) {
		return false;
	}
	if (i != NULL) {
		*i = (int)v->u.integer;
	}
	return true;
}

const char *jutil_get_string(const struct jutil_value *value, size_t *len)
{
	const json_value *v = (const json_value *)value;
	if (v->type != json_string) {
		LOGE_F("unexpected json object type: %d", v->type);
		return NULL;
	}
	if (len != NULL) {
		*len = v->u.string.length;
	}
	return v->u.string.ptr;
}

char *jutil_strdup(const struct jutil_value *value)
{
	size_t n = 0;
	const char *s = jutil_get_string(value, &n);
	if (s == NULL) {
		return NULL;
	}
	return strndup(s, n);
}
