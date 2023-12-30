/* kcptun-libev (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"
#include "utils/slog.h"
#include "util.h"
#include "jsonutil.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define MAX_CONF_SIZE 65536

static struct jutil_value *conf_parse(const char *filename)
{
	FILE *f = fopen(filename, "r");
	if (f == NULL) {
		const int err = errno;
		LOGE_F("unable to open config file: %s", strerror(err));
		return NULL;
	}
	if (fseek(f, 0, SEEK_END)) {
		const int err = errno;
		LOGE_F("unable to seek config file: %s", strerror(err));
		fclose(f);
		return NULL;
	}
	const long len = ftell(f);
	if (len < 0) {
		const int err = errno;
		LOGE_F("unable to tell config file length: %s", strerror(err));
		fclose(f);
		return NULL;
	}
	if (len >= MAX_CONF_SIZE) {
		LOGE("config file is too large");
		fclose(f);
		return NULL;
	}
	if (fseek(f, 0, SEEK_SET)) {
		const int err = errno;
		LOGE_F("unable to seek config file: %s", strerror(err));
		fclose(f);
		return NULL;
	}
	char *buf = malloc(len + 1); /* null terminator */
	if (buf == NULL) {
		LOGF("conf_parse: out of memory");
		fclose(f);
		return NULL;
	}
	const size_t nread = fread(buf, sizeof(char), (size_t)len, f);
	fclose(f);
	if (nread != (size_t)len) {
		LOGE("unable to read the config file");
		free(buf);
		return NULL;
	}
	buf[nread] = '\0';
	struct jutil_value *obj = jutil_parse(buf, nread);
	free(buf);
	if (obj == NULL) {
		LOGF("conf_parse: json parse failed");
		return NULL;
	}
	return obj;
}

#define NAME_EQUAL(c) CONSTSTREQUAL(name, namelen, c)

static bool kcp_scope_cb(
	void *ud, const char *name, const size_t namelen,
	const struct jutil_value *value)
{
	struct config *restrict conf = ud;
	if (NAME_EQUAL("mtu")) {
		return jutil_get_int(value, &conf->kcp_mtu);
	} else if (NAME_EQUAL("sndwnd")) {
		return jutil_get_int(value, &conf->kcp_sndwnd);
	} else if (NAME_EQUAL("rcvwnd")) {
		return jutil_get_int(value, &conf->kcp_rcvwnd);
	} else if (NAME_EQUAL("nodelay")) {
		return jutil_get_int(value, &conf->kcp_nodelay);
	} else if (NAME_EQUAL("interval")) {
		return jutil_get_int(value, &conf->kcp_interval);
	} else if (NAME_EQUAL("resend")) {
		return jutil_get_int(value, &conf->kcp_resend);
	} else if (NAME_EQUAL("nc")) {
		return jutil_get_int(value, &conf->kcp_nc);
	} else if (NAME_EQUAL("flush")) {
		return jutil_get_int(value, &conf->kcp_flush);
	}
	LOGW_F("unknown config: \"kcp.%s\"", name);
	return true;
}

static bool tcp_scope_cb(
	void *ud, const char *name, const size_t namelen,
	const struct jutil_value *value)
{
	struct config *restrict conf = ud;
	if (NAME_EQUAL("reuseport")) {
		return jutil_get_bool(value, &conf->tcp_reuseport);
	} else if (NAME_EQUAL("keepalive")) {
		return jutil_get_bool(value, &conf->tcp_keepalive);
	} else if (NAME_EQUAL("nodelay")) {
		return jutil_get_bool(value, &conf->tcp_nodelay);
	} else if (NAME_EQUAL("sndbuf")) {
		return jutil_get_int(value, &conf->tcp_sndbuf);
	} else if (NAME_EQUAL("rcvbuf")) {
		return jutil_get_int(value, &conf->tcp_rcvbuf);
	}
	LOGW_F("unknown config: \"tcp.%s\"", name);
	return true;
}

static bool udp_scope_cb(
	void *ud, const char *name, const size_t namelen,
	const struct jutil_value *value)
{
	struct config *restrict conf = ud;
	if (NAME_EQUAL("sndbuf")) {
		return jutil_get_int(value, &conf->udp_sndbuf);
	} else if (NAME_EQUAL("rcvbuf")) {
		return jutil_get_int(value, &conf->udp_rcvbuf);
	}
	LOGW_F("unknown config: \"udp.%s\"", name);
	return true;
}

static bool main_scope_cb(
	void *ud, const char *name, const size_t namelen,
	const struct jutil_value *value)
{
	struct config *restrict conf = ud;
	if (NAME_EQUAL("kcp")) {
		return jutil_walk_object(conf, value, kcp_scope_cb);
	} else if (NAME_EQUAL("udp")) {
		return jutil_walk_object(conf, value, udp_scope_cb);
	} else if (NAME_EQUAL("tcp")) {
		return jutil_walk_object(conf, value, tcp_scope_cb);
	} else if (NAME_EQUAL("listen")) {
		conf->listen = jutil_strdup(value);
		return conf->listen != NULL;
	} else if (NAME_EQUAL("connect")) {
		conf->connect = jutil_strdup(value);
		return conf->connect != NULL;
	} else if (NAME_EQUAL("kcp_bind")) {
		conf->kcp_bind = jutil_strdup(value);
		return conf->kcp_bind != NULL;
	} else if (NAME_EQUAL("kcp_connect")) {
		conf->kcp_connect = jutil_strdup(value);
		return conf->kcp_connect != NULL;
	} else if (NAME_EQUAL("http_listen")) {
		conf->http_listen = jutil_strdup(value);
		return conf->http_listen != NULL;
	} else if (NAME_EQUAL("netdev")) {
		conf->netdev = jutil_strdup(value);
		return conf->netdev != NULL;
	}
#if WITH_CRYPTO
	else if (NAME_EQUAL("method")) {
		conf->method = jutil_strdup(value);
		return conf->method != NULL;
	} else if (NAME_EQUAL("password")) {
		conf->password = jutil_strdup(value);
		return conf->password != NULL;
	} else if (NAME_EQUAL("psk")) {
		conf->psk = jutil_strdup(value);
		return conf->psk != NULL;
	}
#endif /* WITH_CRYPTO */
#if WITH_OBFS
	else if (NAME_EQUAL("obfs")) {
		conf->obfs = jutil_strdup(value);
		return conf->obfs != NULL;
	}
#endif /* WITH_OBFS */
	else if (NAME_EQUAL("linger")) {
		return jutil_get_int(value, &conf->linger);
	} else if (NAME_EQUAL("timeout")) {
		return jutil_get_int(value, &conf->timeout);
	} else if (NAME_EQUAL("keepalive")) {
		return jutil_get_int(value, &conf->keepalive);
	} else if (NAME_EQUAL("time_wait")) {
		return jutil_get_int(value, &conf->time_wait);
	} else if (NAME_EQUAL("loglevel")) {
		return jutil_get_int(value, &conf->log_level);
	} else if (NAME_EQUAL("user")) {
		conf->user = jutil_strdup(value);
		return conf->user != NULL;
	}
	LOGW_F("unknown config: \"%s\"", name);
	return true;
}

#undef NAME_EQUAL

const char *runmode_str(const int mode)
{
	static const char *str[] = {
		[MODE_SERVER] = "server",
		[MODE_CLIENT] = "client",
	};
	assert(mode >= 0);
	assert((size_t)mode < ARRAY_SIZE(str));
	return str[mode];
}

static struct config conf_default(void)
{
	return (struct config){
		.kcp_mtu = 1400,
		.kcp_sndwnd = 256,
		.kcp_rcvwnd = 256,
		.kcp_nodelay = 1,
		.kcp_interval = 50,
		.kcp_resend = 0,
		.kcp_nc = 1,
		.kcp_flush = 1,
		.timeout = 600,
		.linger = 30,
		.keepalive = 25,
		.time_wait = 120,
		.tcp_reuseport = false,
		.tcp_keepalive = false,
		.tcp_nodelay = true,
		.log_level = LOG_LEVEL_NOTICE,
	};
}

static bool range_check_int(
	const char *key, const int value, const int lbound, const int ubound)
{
	if (value < lbound || value > ubound) {
		LOGE_F("%s is out of range (%d - %d)", key, lbound, ubound);
		return false;
	}
	return true;
}

#define RANGE_CHECK(key, value, lbound, ubound)                                \
	_Generic(value, int : range_check_int)(key, value, lbound, ubound)

static bool conf_check(struct config *restrict conf)
{
	/* 1. network address check */
	int mode = 0;
	if (conf->kcp_bind != NULL && conf->connect != NULL) {
		mode |= MODE_SERVER;
	}
	if (conf->listen != NULL && conf->kcp_connect != NULL) {
		mode |= MODE_CLIENT;
	}
	if (mode != MODE_SERVER && mode != MODE_CLIENT) {
		LOGE("config: no forward could be provided (are you missing some address field?)");
		return false;
	}
	conf->mode = mode;

#if WITH_CRYPTO
	/* 2. crypto check */
	if (conf->psk != NULL && conf->password != NULL) {
		LOGF("config: psk and password cannot be specified at the same time");
		return false;
	}
#endif

	/* 3. range check */
	const bool range_ok =
		RANGE_CHECK("kcp.mtu", conf->kcp_mtu, 300, 1500) &&
		RANGE_CHECK("kcp.sndwnd", conf->kcp_sndwnd, 16, 65536) &&
		RANGE_CHECK("kcp.rcvwnd", conf->kcp_rcvwnd, 16, 65536) &&
		RANGE_CHECK("kcp.nodelay", conf->kcp_nodelay, 0, 2) &&
		RANGE_CHECK("kcp.interval", conf->kcp_interval, 10, 500) &&
		RANGE_CHECK("kcp.resend", conf->kcp_resend, 0, 100) &&
		RANGE_CHECK("kcp.nc", conf->kcp_nc, 0, 1) &&
		RANGE_CHECK("kcp.flush", conf->kcp_flush, 0, 2) &&
		RANGE_CHECK("timeout", conf->timeout, 60, 86400) &&
		RANGE_CHECK("linger", conf->linger, 5, 600) &&
		RANGE_CHECK("keepalive", conf->keepalive, 0, 600) &&
		RANGE_CHECK("time_wait", conf->time_wait, 5, 3600) &&
		RANGE_CHECK(
			"log_level", conf->log_level, LOG_LEVEL_SILENCE,
			LOG_LEVEL_VERBOSE);
	if (!range_ok) {
		return false;
	}

	if ((conf->tcp_sndbuf != 0 && conf->tcp_sndbuf < 4096) ||
	    (conf->tcp_rcvbuf != 0 && conf->tcp_rcvbuf < 4096)) {
		LOGW("config: probably too small tcp buffer");
	}
	if ((conf->udp_sndbuf != 0 && conf->udp_sndbuf < 4096) ||
	    (conf->udp_rcvbuf != 0 && conf->udp_rcvbuf < 4096)) {
		LOGW("config: probably too small udp buffer");
	}
	return true;
}

struct config *conf_read(const char *filename)
{
	struct config *conf = malloc(sizeof(struct config));
	if (conf == NULL) {
		return NULL;
	}
	*conf = conf_default();
	struct jutil_value *root = conf_parse(filename);
	if (root == NULL) {
		conf_free(conf);
		return NULL;
	}
	if (!jutil_walk_object(conf, root, main_scope_cb)) {
		LOGE("invalid config file");
		conf_free(conf);
		jutil_free(root);
		return NULL;
	}
	jutil_free(root);
	if (!conf_check(conf)) {
		conf_free(conf);
		return NULL;
	}
	return conf;
}

void conf_free(struct config *conf)
{
	UTIL_SAFE_FREE(conf->listen);
	UTIL_SAFE_FREE(conf->connect);
	UTIL_SAFE_FREE(conf->kcp_bind);
	UTIL_SAFE_FREE(conf->kcp_connect);
	UTIL_SAFE_FREE(conf->http_listen);
	UTIL_SAFE_FREE(conf->netdev);
	UTIL_SAFE_FREE(conf->user);
#if WITH_CRYPTO
	UTIL_SAFE_FREE(conf->method);
	UTIL_SAFE_FREE(conf->password);
	UTIL_SAFE_FREE(conf->psk);
#endif
#if WITH_OBFS
	UTIL_SAFE_FREE(conf->obfs);
#endif
	free(conf);
}
