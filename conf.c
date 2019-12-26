#include "conf.h"
#include "util.h"

#include "json/json.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct config conf;

#define MAX_CONF_SIZE 65536

typedef bool (*walk_json_object_cb)(struct config *, const json_object_entry *);
static bool walk_json_object(struct config *conf, const json_value *obj,
			     walk_json_object_cb cb)
{
	if (obj == NULL || obj->type != json_object) {
		return false;
	}

	for (unsigned int i = 0; i < obj->u.object.length; i++) {
		if (!cb(conf, &obj->u.object.values[i])) {
			return false;
		}
	}
	return true;
}

typedef bool (*walk_json_array_cb)(struct config *, const json_value *);
static bool walk_json_array(struct config *conf, const json_value *obj,
			    walk_json_array_cb cb)
{
	if (obj == NULL || obj->type != json_array) {
		return false;
	}

	for (unsigned int i = 0; i < obj->u.array.length; i++) {
		if (!cb(conf, obj->u.array.values[i])) {
			return false;
		}
	}
	return true;
}

static json_value *parse_json(const char *file)
{
	json_value *obj = NULL;
	char *buf = NULL;

	FILE *f = fopen(file, "r");
	if (f == NULL) {
		LOG_PERROR("cannot open config file");
		goto cleanup;
	}

	fseek(f, 0, SEEK_END);
	long len = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (len < 0) {
		LOG_PERROR("cannot seek config file");
		goto cleanup;
	}

	if (len >= MAX_CONF_SIZE) {
		LOG_E("too large config file");
		goto cleanup;
	}

	buf = util_malloc(len + 1);
	if (buf == NULL) {
		LOG_WTF("out of memory");
		goto cleanup;
	}

	size_t nread = fread(buf, sizeof(char), len, f);
	if (!nread) {
		LOG_E("failed to read the config file");
		goto cleanup;
	}
	fclose(f);
	f = NULL;

	buf[nread] = '\0'; // end of string

	json_settings settings = { 0 };
	{
		char error_buf[512];
		obj = json_parse_ex(&settings, buf, len, error_buf);
		if (obj == NULL) {
			LOGF_E("failed parsing json: %s", error_buf);
			goto cleanup;
		}
	}

cleanup:
	if (f != NULL) {
		fclose(f);
	}
	if (buf != NULL) {
		util_free(buf);
	}
	return obj;
}

static bool parse_bool_json(bool *b, const json_value *v)
{
	if (v->type != json_boolean) {
		return false;
	}
	*b = !!(v->u.boolean);
	return true;
}

static bool parse_int_json(int *i, const json_value *v)
{
	if (v->type != json_integer) {
		return false;
	}
	*i = (int)v->u.integer;
	return true;
}

static char *parse_string_json(const json_value *value)
{
	if (value->type != json_string) {
		LOGF_E("unexpected json object type: %d", value->type);
		return NULL;
	}
	size_t n = value->u.string.length + 1;
	char *str = util_malloc(n);
	strncpy(str, value->u.string.ptr, n);
	return str;
}

static inline bool parse_ipv4(const char *str, struct endpoint *ep,
			      uint16_t port)
{
	struct sockaddr_in sa = { 0 };
	socklen_t len = sizeof(sa);
	if (inet_pton(AF_INET, str, &(sa.sin_addr)) == 1) {
		sa.sin_family = AF_INET;
		sa.sin_port = htons(port);
		*ep = (struct endpoint){
			.sa = util_malloc(len),
			.len = len,
		};
		UTIL_ASSERT(ep->sa);
		memcpy(ep->sa, &sa, len);
		return true;
	}
	return false;
}

static inline bool parse_ipv6(const char *str, struct endpoint *ep,
			      uint16_t port)
{
	struct sockaddr_in6 sa = { 0 };
	socklen_t len = sizeof(sa);
	if (inet_pton(AF_INET6, str, &(sa.sin6_addr)) == 1) {
		sa.sin6_family = AF_INET6;
		sa.sin6_port = htons(port);
		*ep = (struct endpoint){
			.sa = util_malloc(len),
			.len = len,
		};
		UTIL_ASSERT(ep->sa);
		memcpy(ep->sa, &sa, len);
		return true;
	}
	return false;
}

static inline bool parse_endpoint(char *str, struct endpoint *ep)
{
	char *p = strrchr(str, ':');
	if (p == NULL) {
		LOGF_E("\":\" is missing in address: %s", str);
		return false;
	}
	*p = '\0';
	p++;
	/* parse port */
	uint16_t port;
	{
		char *end = NULL;
		unsigned n = strtoul(p, &end, 10);
		if (p == end || n == 0 || n > UINT16_MAX) {
			LOGF_E("invalid port: \"%s\"", p);
			return false;
		}
		port = (uint16_t)n;
	}

	bool ok = parse_ipv4(str, ep, port) || parse_ipv6(str, ep, port);
	if (!ok) {
		LOGF_E("failed to parse address: \"%s\"", str);
		return false;
	}
	return true;
}

static bool parse_endpoint_json(const json_value *v, struct endpoint *ep)
{
	char *addr_str = parse_string_json(v);
	if (addr_str == NULL) {
		return false;
	}
	bool ok = parse_endpoint(addr_str, ep);
	util_free(addr_str);
	if (!ok) {
		return false;
	}
	return true;
}

static bool listen_list_cb(struct config *conf, const json_value *v)
{
	struct endpoint ep;
	bool ok = parse_endpoint_json(v, &ep);
	if (!ok) {
		return false;
	}
	conf->addr_listen[conf->n_listen++] = ep;
	return true;
}

static bool kcp_scope_cb(struct config *conf, const json_object_entry *entry)
{
	const char *name = entry->name;
	const json_value *value = entry->value;
	if (strcmp(name, "mtu") == 0) {
		return parse_int_json(&conf->kcp_mtu, value);
	}
	if (strcmp(name, "sndwnd") == 0) {
		return parse_int_json(&conf->kcp_sndwnd, value);
	}
	if (strcmp(name, "rcvwnd") == 0) {
		return parse_int_json(&conf->kcp_rcvwnd, value);
	}
	if (strcmp(name, "nodelay") == 0) {
		return parse_int_json(&conf->kcp_nodelay, value);
	}
	if (strcmp(name, "interval") == 0) {
		return parse_int_json(&conf->kcp_interval, value);
	}
	if (strcmp(name, "resend") == 0) {
		return parse_int_json(&conf->kcp_resend, value);
	}
	if (strcmp(name, "nc") == 0) {
		return parse_int_json(&conf->kcp_nc, value);
	}
	LOGF_E("unknown config key: \"kcp.%s\"", name);
	return false;
}

static bool main_scope_cb(struct config *conf, const json_object_entry *entry)
{
	const char *name = entry->name;
	const json_value *value = entry->value;
	if (strcmp(name, "listen") == 0) {
		if (value->type != json_array) {
			return false;
		}
		unsigned int n = value->u.array.length;
		conf->n_listen = 0;
		conf->addr_listen = util_malloc(n * sizeof(struct endpoint));
		UTIL_ASSERT(conf->addr_listen);
		bool ok = walk_json_array(conf, value, listen_list_cb);
		if (!ok) {
			util_free(conf->addr_listen);
		}
		return ok;
	}
	if (strcmp(name, "connect") == 0) {
		return parse_endpoint_json(value, &(conf->addr_connect));
	}
	if (strcmp(name, "udp_bind") == 0) {
		return parse_endpoint_json(value, &(conf->addr_udp_bind));
	}
	if (strcmp(name, "udp_connect") == 0) {
		return parse_endpoint_json(value, &(conf->addr_udp_connect));
	}
	if (strcmp(name, "kcp") == 0) {
		return walk_json_object(conf, value, kcp_scope_cb);
	}
	if (strcmp(name, "password") == 0) {
		conf->password = parse_string_json(value);
		return conf->password != NULL;
	}
	if (strcmp(name, "linger") == 0) {
		return parse_int_json(&conf->linger, value);
	}
	if (strcmp(name, "timeout") == 0) {
		return parse_int_json(&conf->timeout, value);
	}
	if (strcmp(name, "keepalive") == 0) {
		return parse_int_json(&conf->keepalive, value);
	}
	if (strcmp(name, "loglevel") == 0) {
		int l;
		if (!parse_int_json(&l, value)) {
			return false;
		}
		if (l < LOG_LEVEL_SILENCE || l > LOG_LEVEL_VERBOSE) {
			LOGF_E("log level out of range: %d - %d",
			       LOG_LEVEL_SILENCE, LOG_LEVEL_VERBOSE);
			return false;
		}
		log_level = l;
		return true;
	}
	if (strcmp(name, "reuseport") == 0) {
		return parse_bool_json(&conf->reuseport, value);
	}
	LOGF_E("unknown config key: \"%s\"", name);
	return false;
}

static inline struct config conf_default()
{
	return (struct config){
		.n_listen = 0,
		.addr_listen = NULL,
		.addr_connect = { 0 },
		.addr_udp_bind = { 0 },
		.addr_udp_connect = { 0 },
		.kcp_mtu = 1300,
		.kcp_sndwnd = 1024,
		.kcp_rcvwnd = 1024,
		.kcp_nodelay = 1,
		.kcp_interval = 50,
		.kcp_resend = 0,
		.kcp_nc = 1,
		.password = NULL,
		.timeout = -1,
		.linger = -1,
		.keepalive = -1,
		.reuseport = false,
	};
}

static inline bool conf_check(struct config *restrict conf)
{
	UNUSED(conf);
	/* TODO: more check */
	return true;
}

struct config *conf_read(const char *file)
{
	struct config *conf = util_malloc(sizeof(struct config));
	UTIL_ASSERT(conf);
	*conf = conf_default();
	json_value *obj = parse_json(file);
	if (obj == NULL) {
		conf_free(conf);
		return NULL;
	}
	if (!walk_json_object(conf, obj, main_scope_cb)) {
		LOG_E("invalid config file");
		conf_free(conf);
		json_value_free(obj);
		return NULL;
	}
	json_value_free(obj);
	if (!conf_check(conf)) {
		conf_free(conf);
		return NULL;
	}
	return conf;
}

void conf_free(struct config *conf)
{
	if (conf->addr_listen != NULL) {
		for (size_t i = 0; i < conf->n_listen; i++) {
			UTIL_SAFE_FREE(conf->addr_listen[i].sa);
		}
		conf->n_listen = 0;
		util_free(conf->addr_listen);
	}
	UTIL_SAFE_FREE(conf->addr_connect.sa);
	UTIL_SAFE_FREE(conf->addr_udp_bind.sa);
	UTIL_SAFE_FREE(conf->addr_udp_connect.sa);
	UTIL_SAFE_FREE(conf->password);
	util_free(conf);
}
