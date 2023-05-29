/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef JSONUTIL_H
#define JSONUTIL_H

#include "json/json.h"

#include <stdbool.h>
#include <stddef.h>

json_value *parse_json(const json_char *json, size_t length);

typedef bool (*walk_json_object_cb)(void *, const json_object_entry *);
bool walk_json_object(void *ud, const json_value *obj, walk_json_object_cb cb);

typedef bool (*walk_json_array_cb)(void *, const json_value *);
bool walk_json_array(void *ud, const json_value *obj, walk_json_array_cb cb);

bool parse_bool_json(bool *b, const json_value *v);

bool parse_int_json(int *i, const json_value *v);

char *parse_string_json(const json_value *value);

#endif /* JSONUTIL_H */
