/* kcptun-libev (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "jsonutil.h"
#include "utils/slog.h"

#include "cJSON.h"

#include <string.h>

struct jutil_value;

struct jutil_value *jutil_parse(const char *json, size_t length)
{
	cJSON *obj = cJSON_ParseWithLength(json, length);
	return (struct jutil_value *)obj;
}

void jutil_free(struct jutil_value *value)
{
	cJSON_Delete((cJSON *)value);
}

bool jutil_walk_object(
	void *ud, const struct jutil_value *value, jutil_walk_object_cb cb)
{
	const cJSON *restrict v = (const cJSON *)value;
	if (!cJSON_IsObject(v)) {
		return false;
	}
	for (const cJSON *o = v->child; o != NULL; o = o->next) {
		if (!cb(ud, o->string, (struct jutil_value *)o)) {
			return false;
		}
	}
	return true;
}

bool jutil_walk_array(
	void *ud, const struct jutil_value *value, jutil_walk_array_cb cb)
{
	const cJSON *restrict v = (const cJSON *)value;
	if (!cJSON_IsArray(v)) {
		return false;
	}
	for (const cJSON *o = v->child; o != NULL; o = o->next) {
		if (!cb(ud, (struct jutil_value *)o)) {
			return false;
		}
	}
	return true;
}

bool jutil_get_bool(const struct jutil_value *value, bool *b)
{
	const cJSON *restrict v = (const cJSON *)value;
	if (!cJSON_IsBool(v)) {
		return false;
	}
	if (b != NULL) {
		*b = cJSON_IsTrue(v);
	}
	return true;
}

bool jutil_get_int(const struct jutil_value *value, int *i)
{
	const cJSON *restrict v = (const cJSON *)value;
	if (!cJSON_IsNumber(v)) {
		return false;
	}
	if (i != NULL) {
		*i = v->valueint;
	}
	return true;
}

char *jutil_get_string(const struct jutil_value *value)
{
	const cJSON *restrict v = (const cJSON *)value;
	if (!cJSON_IsString(v)) {
		LOGE_F("unexpected json object type: %d", v->type);
		return NULL;
	}
	return strdup(v->valuestring);
}
