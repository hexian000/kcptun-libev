#include "conf.h"
#include "aead.h"
#include "slog.h"
#include "util.h"
#include "sockutil.h"
#include "jsonutil.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX_CONF_SIZE 65536

static json_value *parse_json(const char *file)
{
	json_value *obj = NULL;
	char *buf = NULL;

	FILE *f = fopen(file, "r");
	if (f == NULL) {
		LOGE_PERROR("cannot open config file");
		goto cleanup;
	}

	fseek(f, 0, SEEK_END);
	long len = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (len < 0) {
		LOGE_PERROR("cannot seek config file");
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

static bool kcp_scope_cb(void *ud, const json_object_entry *entry)
{
	struct config *restrict conf = ud;
	const char *name = entry->name;
	const json_value *value = entry->value;
	if (strcmp(name, "mtu") == 0) {
		int mtu;
		if (!parse_int_json(&mtu, value)) {
			return false;
		}
		if (mtu < 300 || mtu > 1500) {
			LOGE_F("kcp.mtu out of range: %d - %d", 300, 1500);
			return false;
		}
		conf->kcp_mtu = (size_t)mtu;
		return true;
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
	LOGW_F("unknown config: \"kcp.%s\"", name);
	return true;
}

static bool tcp_scope_cb(void *ud, const json_object_entry *entry)
{
	struct config *restrict conf = ud;
	const char *name = entry->name;
	const json_value *value = entry->value;
	if (strcmp(name, "reuseport") == 0) {
		return parse_bool_json(&conf->tcp_reuseport, value);
	}
	if (strcmp(name, "keepalive") == 0) {
		return parse_bool_json(&conf->tcp_keepalive, value);
	}
	if (strcmp(name, "nodelay") == 0) {
		return parse_bool_json(&conf->tcp_nodelay, value);
	}
	if (strcmp(name, "sndbuf") == 0) {
		return parse_int_json(&conf->tcp_sndbuf, value);
	}
	if (strcmp(name, "rcvbuf") == 0) {
		return parse_int_json(&conf->tcp_rcvbuf, value);
	}
	LOGW_F("unknown config: \"tcp.%s\"", name);
	return true;
}

static bool udp_scope_cb(void *ud, const json_object_entry *entry)
{
	struct config *restrict conf = ud;
	const char *name = entry->name;
	const json_value *value = entry->value;
	if (strcmp(name, "reuseport") == 0) {
		return parse_bool_json(&conf->udp_reuseport, value);
	}
	if (strcmp(name, "sndbuf") == 0) {
		return parse_int_json(&conf->udp_sndbuf, value);
	}
	if (strcmp(name, "rcvbuf") == 0) {
		return parse_int_json(&conf->udp_rcvbuf, value);
	}
	LOGW_F("unknown config: \"udp.%s\"", name);
	return true;
}

static bool main_scope_cb(void *ud, const json_object_entry *entry)
{
	struct config *restrict conf = ud;
	const char *name = entry->name;
	const json_value *value = entry->value;
	if (strcmp(name, "kcp") == 0) {
		return walk_json_object(conf, value, kcp_scope_cb);
	}
	if (strcmp(name, "udp") == 0) {
		return walk_json_object(conf, value, udp_scope_cb);
	}
	if (strcmp(name, "tcp") == 0) {
		return walk_json_object(conf, value, tcp_scope_cb);
	}
	if (strcmp(name, "listen") == 0) {
		char *str = parse_string_json(value);
		return (conf->listen.str = str) != NULL;
	}
	if (strcmp(name, "connect") == 0) {
		char *str = parse_string_json(value);
		return (conf->connect.str = str) != NULL;
	}
	if (strcmp(name, "udp_bind") == 0) {
		char *str = parse_string_json(value);
		return (conf->udp_bind.str = str) != NULL;
	}
	if (strcmp(name, "udp_connect") == 0) {
		char *str = parse_string_json(value);
		return (conf->udp_connect.str = str) != NULL;
	}
#if WITH_CRYPTO
	if (strcmp(name, "method") == 0) {
		conf->method = parse_string_json(value);
		return conf->method != NULL;
	}
	if (strcmp(name, "password") == 0) {
		conf->password = parse_string_json(value);
		return conf->password != NULL;
	}
	if (strcmp(name, "psk") == 0) {
		conf->psk = parse_b64_json(value, &conf->psklen);
		return conf->psk != NULL;
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
	if (strcmp(name, "udp_bind") == 0) {
		char *str = parse_string_json(value);
		return (conf->udp_bind.str = str) != NULL;
	}
	LOGW_F("unknown config: \"%s\"", name);
	return true;
}

const char *runmode_str(const int mode)
{
	static const char *str[] = {
		[MODE_SERVER] = "server",
		[MODE_PEER] = "peer",
	};
	UTIL_ASSERT(mode >= 0);
	UTIL_ASSERT((size_t)mode < (sizeof(str) / sizeof(str[0])));
	return str[mode];
}

static char *splithostport(const char *addr, char **hostname, char **service)
{
	char *str = clonestr(addr);
	if (str == NULL) {
		return NULL;
	}
	char *port = strrchr(str, ':');
	if (port == NULL) {
		util_free(str);
		return NULL;
	}
	*port = '\0';
	port++;

	char *host = str;
	if (host[0] == '\0') {
		/* default address */
		host = "::";
	} else if (host[0] == '[' && port[-2] == ']') {
		/* remove brackets */
		host++;
		port[-2] = '\0';
	}

	if (hostname != NULL) {
		*hostname = host;
	}
	if (service != NULL) {
		*service = port;
	}
	return str;
}

static bool resolve_netaddr(struct netaddr *restrict addr, const int socktype)
{
	if (addr->str == NULL) {
		/* there's nothing to do */
		return true;
	}
	char *hostname = NULL;
	char *service = NULL;
	char *str = splithostport(addr->str, &hostname, &service);
	if (str == NULL) {
		LOGE_F("failed resolving address: %s", addr->str);
		return false;
	}
	struct sockaddr *sa = resolve(hostname, service, socktype);
	if (sa == NULL) {
		util_free(str);
		return false;
	}
	util_free(str);
	UTIL_SAFE_FREE(addr->sa);
	addr->sa = sa;
	if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		if (strcmp(addr->str, addr_str) != 0) {
			LOGD_F("resolve: \"%s\" is %s", addr->str, addr_str);
		}
	}
	return true;
}

void conf_resolve(struct config *conf)
{
	resolve_netaddr(&conf->listen, SOCK_STREAM);
	resolve_netaddr(&conf->connect, SOCK_STREAM);
	resolve_netaddr(&conf->udp_bind, SOCK_DGRAM);
	resolve_netaddr(&conf->udp_connect, SOCK_DGRAM);
}

static struct config conf_default()
{
	return (struct config){
		.kcp_mtu = 1400,
		.kcp_sndwnd = 2048,
		.kcp_rcvwnd = 2048,
		.kcp_nodelay = 2,
		.kcp_interval = 50,
		.kcp_resend = 3,
		.kcp_nc = 1,
		.password = NULL,
		.psk = NULL,
		.timeout = -1,
		.linger = -1,
		.keepalive = -1,
		.time_wait = -1,
		.tcp_reuseport = false,
		.tcp_keepalive = false,
		.tcp_nodelay = true,
		.udp_reuseport = false,
		.log_level = LOG_LEVEL_INFO,
	};
}

static bool conf_check(struct config *restrict conf)
{
	/* 1. network address check */
	conf_resolve(conf);
	const struct sockaddr *sa = NULL;
	if (conf->udp_bind.sa != NULL) {
		sa = conf->udp_bind.sa;
	}
	if (conf->udp_connect.sa != NULL) {
		if (sa != NULL) {
			if (conf->udp_connect.sa->sa_family != sa->sa_family) {
				LOGE("config: udp address must be in same network");
				return false;
			}
		} else {
			sa = conf->udp_connect.sa;
		}
	}
	if (sa == NULL) {
		LOGF("config: udp address is missing");
		return false;
	}
	conf->udp_af = sa->sa_family;
	if (conf->udp_connect.str == NULL) {
		conf->mode = MODE_SERVER;
	} else if (conf->listen.str != NULL) {
		conf->mode = MODE_PEER;
	} else {
		LOGF("config: no forward could be provided (are you missing some address field?)");
		return false;
	}

	/* 2. crypto check */
	if (conf->psk != NULL && conf->password != NULL) {
		LOGF("config: psk and password cannot be specified at the same time");
		return false;
	}
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

static void netaddr_safe_free(struct netaddr *restrict addr)
{
	if (addr == NULL) {
		return;
	}
	UTIL_SAFE_FREE(addr->str);
	UTIL_SAFE_FREE(addr->sa);
}

void conf_free(struct config *conf)
{
	netaddr_safe_free(&conf->listen);
	netaddr_safe_free(&conf->connect);
	netaddr_safe_free(&conf->udp_bind);
	netaddr_safe_free(&conf->udp_connect);
	UTIL_SAFE_FREE(conf->method);
	UTIL_SAFE_FREE(conf->password);
	UTIL_SAFE_FREE(conf->psk);
	util_free(conf);
}
