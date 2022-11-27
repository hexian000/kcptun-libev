#include "jsonutil.h"
#include "util.h"

#include "json/json.h"

#define b64_malloc(ptr) malloc(ptr)
#define b64_realloc(ptr, size) realloc(ptr, size)
#include "b64/b64.h"

#include <string.h>

static void *jsonutil_malloc(size_t n, int zero, void *user_data)
{
	(void)user_data;
	void *p = malloc(n);
	if (p && zero) {
		memset(p, 0, n);
	}
	return p;
}

static void jsonutil_free(void *p, void *user_data)
{
	(void)user_data;
	free(p);
}

json_value *parse_json(const json_char *json, size_t length)
{
	json_settings settings = {
		.mem_alloc = &jsonutil_malloc,
		.mem_free = &jsonutil_free,
		.user_data = NULL,
	};
	char error_msg[json_error_max];
	json_value *obj = json_parse_ex(&settings, json, length, error_msg);
	if (obj == NULL) {
		LOGE_F("failed parsing json: %s", error_msg);
	}
	return obj;
}

bool walk_json_object(void *ud, const json_value *obj, walk_json_object_cb cb)
{
	if (obj == NULL || obj->type != json_object) {
		return false;
	}

	for (unsigned int i = 0; i < obj->u.object.length; i++) {
		if (!cb(ud, &obj->u.object.values[i])) {
			return false;
		}
	}
	return true;
}

bool walk_json_array(void *ud, const json_value *obj, walk_json_array_cb cb)
{
	if (obj == NULL || obj->type != json_array) {
		return false;
	}

	for (unsigned int i = 0; i < obj->u.array.length; i++) {
		if (!cb(ud, obj->u.array.values[i])) {
			return false;
		}
	}
	return true;
}

bool parse_bool_json(bool *b, const json_value *v)
{
	if (v->type != json_boolean) {
		return false;
	}
	*b = v->u.boolean != 0;
	return true;
}

bool parse_int_json(int *i, const json_value *v)
{
	if (v->type != json_integer) {
		return false;
	}
	*i = (int)v->u.integer;
	return true;
}

char *parse_string_json(const json_value *value)
{
	if (value->type != json_string) {
		LOGE_F("unexpected json object type: %d", value->type);
		return NULL;
	}
	return util_strndup(value->u.string.ptr, value->u.string.length);
}

unsigned char *parse_b64_json(const json_value *value, size_t *restrict outlen)
{
	if (value->type != json_string) {
		LOGE_F("unexpected json object type: %d", value->type);
		return 0;
	}
	unsigned char *b = b64_decode_ex(
		value->u.string.ptr, value->u.string.length, outlen);
	if (b == NULL) {
		return NULL;
	}
	unsigned char *data = malloc(*outlen);
	memcpy(data, b, *outlen);
	free(b);
	return data;
}
