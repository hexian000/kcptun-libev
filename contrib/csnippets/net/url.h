/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef NET_URL_H
#define NET_URL_H

#include <stdbool.h>
#include <stddef.h>

struct url {
	char *scheme;
	char *userinfo;
	char *host;
	char *path; /* escaped */
	char *query; /* escaped */
	char *fragment;
	char *defacto;
};

/**
 * @brief Escape a path segment for URL.
 * @param buf [OUT] Out buffer.
 * @param buf_size Buffer size in bytes.
 * @return Number of bytes written to buffer.
 */
size_t url_escape_path(char *buf, size_t buf_size, const char *path);

/**
 * @brief Escape a query component for URL.
 * @param buf [OUT] Out buffer.
 * @param buf_size Buffer size in bytes.
 * @return Number of bytes written to buffer.
 */
size_t url_escape_query(char *buf, size_t buf_size, const char *query);

/**
 * @brief Build a URL string from structured data.
 * @param buf [OUT] Out buffer.
 * @param buf_size Buffer size in bytes.
 * @return Number of bytes written to buffer.
 * @see struct url
 */
size_t url_build(char *buf, size_t buf_size, const struct url *url);

/**
 * @brief Parse a URL string into structured data.
 * @details No allocations, the raw URL string is destructed.
 * @param raw Raw URL string.
 * @return true if successful.
 * @see struct url
 */
bool url_parse(char *raw, struct url *url);

/**
 * @brief Parse a URL path into segments.
 * @param path [INOUT] Pointer to URL path string, will be moved to next segment.
 * The raw path string will be destructed.
 * @param segment [OUT] Unescaped URL path segment string.
 * @return true if successful.
 * @note Stop iterating if *path == NULL.
 */
bool url_path_segment(char **path, char **segment);

/**
 * @brief Parse a URL query into components.
 * @param query [INOUT] Pointer to URL query string, will be moved to next component.
 * The raw query string will be destructed.
 * @param key [OUT] Unescaped URL query key string.
 * @param value [OUT] Unescaped URL query value string.
 * @return true if successful.
 * @note Stop iterating if *query == NULL.
 */
bool url_query_component(char **query, char **key, char **value);

/**
 * @brief Unescape a full URL path string in-place.
 * @details Useful if you don't want to extract path segments.
 * @param path [INOUT] URL path string.
 * @return true if successful.
 */
bool url_unescape_path(char *path);

/**
 * @brief Unescape a full URL query string in-place.
 * @param path [INOUT] URL query string.
 * @details Useful if you don't want to extract query components.
 * @return true if successful.
 */
bool url_unescape_query(char *query);

#endif /* NET_URL_H */
