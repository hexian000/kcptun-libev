#include "conf.h"
#include "aead.h"
#include "slog.h"
#include "util.h"

#include "json/json.h"
#include "b64/b64.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX_CONF_SIZE 65536

typedef bool (*walk_json_object_cb)(struct config *, const json_object_entry *);
static bool walk_json_object(
	struct config *conf, const json_value *obj, walk_json_object_cb cb)
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
static bool walk_json_array(
	struct config *conf, const json_value *obj, walk_json_array_cb cb)
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
		LOGE("too large config file");
		goto cleanup;
	}

	buf = util_malloc(len + 1);
	if (buf == NULL) {
		LOGF("parse_json: out of memory");
		goto cleanup;
	}

	size_t nread = fread(buf, sizeof(char), len, f);
	if (!nread) {
		LOGE("failed to read the config file");
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
			LOGE_F("failed parsing json: %s", error_buf);
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
	*b = v->u.boolean != 0;
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
		LOGE_F("unexpected json object type: %d", value->type);
		return NULL;
	}
	size_t n = value->u.string.length + 1;
	char *str = util_malloc(n);
	strncpy(str, value->u.string.ptr, n);
	return str;
}

static inline struct sockaddr_in *parse_ipv4(const char *str, uint16_t port)
{
	struct sockaddr_in sa = { 0 };
	if (inet_pton(AF_INET, str, &(sa.sin_addr)) == 1) {
		sa.sin_family = AF_INET;
		sa.sin_port = htons(port);
		struct sockaddr_in *p = must_malloc(sizeof(sa));
		*p = sa;
		return p;
	}
	return NULL;
}

static inline struct sockaddr_in6 *parse_ipv6(const char *str, uint16_t port)
{
	size_t n = strlen(str);
	if (n > 41) {
		return NULL;
	}
	char s[40] = { 0 };
	if (str[0] == '[' && str[n - 1] == ']') {
		memcpy(s, str + 1, n - 2);
		str = s;
	}
	struct sockaddr_in6 sa = { 0 };
	if (inet_pton(AF_INET6, str, &(sa.sin6_addr)) == 1) {
		sa.sin6_family = AF_INET6;
		sa.sin6_port = htons(port);
		struct sockaddr_in6 *p = must_malloc(sizeof(sa));
		*p = sa;
		return p;
	}
	return NULL;
}

static inline struct sockaddr *parse_endpoint(char *str)
{
	char *p = strrchr(str, ':');
	if (p == NULL) {
		LOGE_F("\":\" is missing in address: %s", str);
		return NULL;
	}
	*p = '\0';
	p++;
	/* parse port */
	uint16_t port;
	{
		char *end = NULL;
		unsigned n = strtoul(p, &end, 10);
		if (p == end || n == 0 || n > UINT16_MAX) {
			LOGE_F("invalid port: \"%s\"", p);
			return NULL;
		}
		port = (uint16_t)n;
	}

	struct sockaddr *sa = (struct sockaddr *)parse_ipv4(str, port);
	if (sa) {
		return sa;
	}
	sa = (struct sockaddr *)parse_ipv6(str, port);
	if (sa) {
		return sa;
	}
	LOGE_F("failed to parse address: \"%s\"", str);
	return NULL;
}

static struct sockaddr *parse_endpoint_json(const json_value *v)
{
	char *addr_str = parse_string_json(v);
	if (addr_str == NULL) {
		return false;
	}
	struct sockaddr *sa = parse_endpoint(addr_str);
	util_free(addr_str);
	return sa;
}

static bool listen_list_cb(struct config *conf, const json_value *v)
{
	struct sockaddr *sa = parse_endpoint_json(v);
	if (!sa) {
		return false;
	}
	conf->addr_listen[conf->n_listen++] = sa;
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
	LOGE_F("unknown config key: \"kcp.%s\"", name);
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
		conf->addr_listen = util_malloc(n * sizeof(struct sockaddr *));
		UTIL_ASSERT(conf->addr_listen);
		bool ok = walk_json_array(conf, value, listen_list_cb);
		if (!ok) {
			util_free(conf->addr_listen);
		}
		return ok;
	}
	if (strcmp(name, "connect") == 0) {
		struct sockaddr *sa = parse_endpoint_json(value);
		return (conf->addr_connect = sa) != NULL;
	}
	if (strcmp(name, "udp_bind") == 0) {
		struct sockaddr *sa = parse_endpoint_json(value);
		return (conf->addr_udp_bind = sa) != NULL;
	}
	if (strcmp(name, "udp_connect") == 0) {
		struct sockaddr *sa = parse_endpoint_json(value);
		return (conf->addr_udp_connect = sa) != NULL;
	}
	if (strcmp(name, "kcp") == 0) {
		return walk_json_object(conf, value, kcp_scope_cb);
	}
#if WITH_CRYPTO
	if (strcmp(name, "password") == 0) {
		/* prefer psk */
		if (conf->psk == NULL) {
			conf->password = parse_string_json(value);
		}
		return conf->password != NULL;
	}
	if (strcmp(name, "psk") == 0) {
		char *pskstr = parse_string_json(value);
		if (pskstr == NULL) {
			return false;
		}
		const size_t len = strlen(pskstr);
		const size_t key_size = crypto_key_size();
		size_t outlen;
		unsigned char *psk = b64_decode_ex(pskstr, len, &outlen);
		memset(pskstr, 0, len);
		util_free(pskstr);
		if (outlen != key_size) {
			LOGE("invalid psk");
			free(psk);
			return false;
		}
		conf->psk = must_malloc(key_size);
		memcpy(conf->psk, psk, key_size);
		memset(psk, 0, outlen);
		free(psk);
		UTIL_SAFE_FREE(conf->password);
		return true;
	}
#endif /* WITH_CRYPTO */
	if (strcmp(name, "linger") == 0) {
		return parse_int_json(&conf->linger, value);
	}
	if (strcmp(name, "timeout") == 0) {
		return parse_int_json(&conf->timeout, value);
	}
	if (strcmp(name, "keepalive") == 0) {
		return parse_int_json(&conf->keepalive, value);
	}
	if (strcmp(name, "time_wait") == 0) {
		return parse_int_json(&conf->time_wait, value);
	}
	if (strcmp(name, "loglevel") == 0) {
		int l;
		if (!parse_int_json(&l, value)) {
			return false;
		}
		if (l < LOG_LEVEL_VERBOSE || l > LOG_LEVEL_SILENCE) {
			LOGE_F("log level out of range: %d - %d",
			       LOG_LEVEL_VERBOSE, LOG_LEVEL_SILENCE);
			return false;
		}
		conf->log_level = l;
		return true;
	}
	if (strcmp(name, "reuseport") == 0) {
		return parse_bool_json(&conf->reuseport, value);
	}
	LOGE_F("unknown config key: \"%s\"", name);
	return false;
}

static inline struct config conf_default()
{
	return (struct config){
		.n_listen = 0,
		.addr_listen = NULL,
		.addr_connect = NULL,
		.addr_udp_bind = NULL,
		.addr_udp_connect = NULL,
		.kcp_mtu = 1372,
		.kcp_sndwnd = 2048,
		.kcp_rcvwnd = 2048,
		.kcp_nodelay = 1,
		.kcp_interval = 10,
		.kcp_resend = 0,
		.kcp_nc = 1,
		.password = NULL,
		.psk = NULL,
		.timeout = -1,
		.linger = -1,
		.keepalive = -1,
		.time_wait = -1,
		.reuseport = false,
		.log_level = LOG_LEVEL_INFO,
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
		LOGE("invalid config file");
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
			UTIL_SAFE_FREE(conf->addr_listen[i]);
		}
		conf->n_listen = 0;
		util_free(conf->addr_listen);
	}
	UTIL_SAFE_FREE(conf->addr_connect);
	UTIL_SAFE_FREE(conf->addr_udp_bind);
	UTIL_SAFE_FREE(conf->addr_udp_connect);
	UTIL_SAFE_FREE(conf->password);
	if (conf->psk) {
		/* allocated by library */
		free(conf->psk);
	}
	util_free(conf);
}
