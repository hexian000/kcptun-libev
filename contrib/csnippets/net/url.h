/* csnippets (c) 2019-2025 He Xian <hexian000@outlook.com>
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
	char *userinfo; /* escaped */
	char *host;
	char *path; /* escaped */
	char *query; /* escaped */
	char *fragment;
	char *defacto;
};

struct url_query_component {
	char *key, *value;
};

/**
 * @brief Escape username and password to be safely used in URL.
 * @param[out] buf Out buffer.
 * @param buf_size Buffer size in bytes.
 * @param[in] username Username.
 * @param[in] password Password, can be NULL.
 * @return Number of bytes written to buffer.
 */
size_t
url_escape_userinfo(char *buf, size_t buf_size, char *username, char *password);

/**
 * @brief Escape a path string to be safely used in URL.
 * @param[out] buf Out buffer.
 * @param buf_size Buffer size in bytes.
 * @param[in] path The full path string like "/s1/s2/s3".
 * @return Number of bytes written to buffer.
 */
size_t url_escape_path(char *buf, size_t buf_size, const char *path);

/**
 * @brief Escape a query string to be safely used in URL.
 * @param[out] buf Out buffer.
 * @param buf_size Buffer size in bytes.
 * @param[in] query The full query string like "k1=v1&k2=v1".
 * @return Number of bytes written to buffer.
 */
size_t url_escape_query(char *buf, size_t buf_size, const char *query);

/**
 * @brief Escape a path segment to be safely used in URL.
 * @param[out] buf Out buffer.
 * @param buf_size Buffer size in bytes.
 * @param[in] segment The path segment.
 * @return Number of bytes written to buffer.
 */
size_t url_escape_path_segment(char *buf, size_t buf_size, const char *segment);

/**
 * @brief Escape a query component to be safely used in URL.
 * @param[out] buf Out buffer.
 * @param buf_size Buffer size in bytes.
 * @param[in] component The query component key or value.
 * @return Number of bytes written to buffer.
 */
size_t
url_escape_query_component(char *buf, size_t buf_size, const char *component);

/**
 * @brief Build a URL string from structured data.
 * @param[out] buf Out buffer.
 * @param buf_size Buffer size in bytes.
 * @param[in] url URL struct.
 * @return Number of bytes written to buffer.
 * @see struct url
 */
size_t url_build(char *buf, size_t buf_size, const struct url *url);

/**
 * @brief Parse a URL string into structured data.
 * @details No allocations, the raw URL string is destructed.
 * @param[inout] raw Raw URL string.
 * @param[out] url URL struct.
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
 * @param[out] comp Unescaped URL query component.
 * @return true if successful.
 * @note Stop iterating if `*query == NULL` or previous call returned false.
 */
bool url_query_component(char **query, struct url_query_component *comp);

/**
 * @brief Unescape a userinfo string in-place.
 * @details No allocations, the raw userinfo string is destructed.
 * @param raw[inout] Raw userinfo string.
 * @param username[out] The unescaped username.
 * @param password[out] The unescaped password.
 * @return true if successful.
 * @see struct url
 */
bool url_unescape_userinfo(char *raw, char **username, char **password);

/**
 * @brief Unescape a URL path string in-place.
 * @details The escaped path string will be destructed.
 * This is an alternative to url_path_segment that does not split the path into segments.
 * @param[inout] path URL path string.
 * @return true if successful.
 */
bool url_unescape_path(char *path);

/**
 * @brief Unescape a URL query string in-place.
 * @details The escaped query string will be destructed.
 * This is an alternative to url_query_component that does not split the query into components.
 * @param[inout] query URL query string.
 * @details Useful if you don't want to extract query components.
 * @return true if successful.
 */
bool url_unescape_query(char *query);

/** @} */

#endif /* NET_URL_H */
