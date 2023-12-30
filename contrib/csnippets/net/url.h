/* csnippets (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef NET_URL_H
#define NET_URL_H

#include <stdbool.h>
#include <stddef.h>

/**
 * @defgroup url
 * @brief RFC 3986: Uniform Resource Identifier (URI)
 * @{
 */

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
 * @param[out] buf Out buffer.
 * @param buf_size Buffer size in bytes.
 * @return Number of bytes written to buffer.
 */
size_t url_escape_path(char *buf, size_t buf_size, const char *path);

/**
 * @brief Escape a query component for URL.
 * @param[out] buf Out buffer.
 * @param buf_size Buffer size in bytes.
 * @return Number of bytes written to buffer.
 */
size_t url_escape_query(char *buf, size_t buf_size, const char *query);

/**
 * @brief Build a URL string from structured data.
 * @param[out] buf Out buffer.
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
 * @details The escaped path string will be destructed.
 * @param[inout] path Pointer to URL path string, will be moved to next segment.
 * @param[out] segment Unescaped URL path segment string.
 * @return true if successful.
 * @note Stop iterating if `*path == NULL` or previous call returned false.
 */
bool url_path_segment(char **path, char **segment);

/**
 * @brief Parse a URL query into components.
 * @details The escaped query string will be destructed.
 * @param[inout] query Pointer to URL query string, will be moved to next component.
 * @param[out] key Unescaped URL query key string.
 * @param[out] value Unescaped URL query value string.
 * @return true if successful.
 * @note Stop iterating if `*query == NULL` or previous call returned false.
 */
bool url_query_component(char **query, char **key, char **value);

/**
 * @brief Unescape a full URL path string in-place.
 * @details The escaped path string will be destructed.
 * This is an alternative to url_path_segment that does not split the path into segments.
 * @param[inout] path URL path string.
 * @return true if successful.
 */
bool url_unescape_path(char *path);

/**
 * @brief Unescape a full URL query string in-place.
 * @details The escaped query string will be destructed.
 * This is an alternative to url_query_component that does not split the query into components.
 * @param[inout] path URL query string.
 * @details Useful if you don't want to extract query components.
 * @return true if successful.
 */
bool url_unescape_query(char *query);

/** @} */

#endif /* NET_URL_H */
