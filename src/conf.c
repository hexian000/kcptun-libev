/* kcptun-libev (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"

#include "jsonutil.h"
#include "util.h"

#include "utils/slog.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CONF_SIZE 65536

static struct jutil_value *conf_parse(const char *filename)
{
	FILE *f = fopen(filename, "r");
	if (f == NULL) {
		LOGE_F("unable to open config file: %s", strerror(errno));
		return NULL;
	}
	if (fseek(f, 0, SEEK_END)) {
		LOGE_F("unable to seek config file: %s", strerror(errno));
		(void)fclose(f);
		return NULL;
	}
	const long len = ftell(f);
	if (len < 0) {
		LOGE_F("unable to tell config file length: %s",
		       strerror(errno));
		(void)fclose(f);
		return NULL;
	}
	if (len >= MAX_CONF_SIZE) {
		LOGE("config file is too large");
		(void)fclose(f);
		return NULL;
	}
	if (fseek(f, 0, SEEK_SET)) {
		LOGE_F("unable to seek config file: %s", strerror(errno));
		(void)fclose(f);
		return NULL;
	}
	char *buf = malloc(len + 1); /* null terminator */
	if (buf == NULL) {
		LOGF("conf_parse: out of memory");
		(void)fclose(f);
		return NULL;
	}
	const size_t nread = fread(buf, sizeof(char), (size_t)len, f);
	(void)fclose(f);
	if (nread != (size_t)len) {
		LOGE("unable to read the config file");
		free(buf);
		return NULL;
	}
	buf[nread] = '\0';
	struct jutil_value *obj = jutil_parse(buf, nread);
	free(buf);
	if (obj == NULL) {
		LOGF("conf_parse: failed parsing json");
		return NULL;
	}
	return obj;
}

static bool
kcp_scope_cb(void *ud, const char *key, const struct jutil_value *value)
{
	struct config *restrict conf = ud;
	if (strcmp(key, "mtu") == 0) {
		return jutil_get_int(value, &conf->kcp_mtu);
	}
	if (strcmp(key, "sndwnd") == 0) {
		return jutil_get_int(value, &conf->kcp_sndwnd);
	}
	if (strcmp(key, "rcvwnd") == 0) {
		return jutil_get_int(value, &conf->kcp_rcvwnd);
	}
	if (strcmp(key, "nodelay") == 0) {
		return jutil_get_int(value, &conf->kcp_nodelay);
	}
	if (strcmp(key, "interval") == 0) {
		return jutil_get_int(value, &conf->kcp_interval);
	}
	if (strcmp(key, "resend") == 0) {
		return jutil_get_int(value, &conf->kcp_resend);
	}
	if (strcmp(key, "nc") == 0) {
		return jutil_get_int(value, &conf->kcp_nc);
	}
	if (strcmp(key, "flush") == 0) {
		return jutil_get_int(value, &conf->kcp_flush);
	}
	LOGW_F("unknown config: \"kcp.%s\"", key);
	return true;
}

static bool
tcp_scope_cb(void *ud, const char *key, const struct jutil_value *value)
{
	struct config *restrict conf = ud;
	if (strcmp(key, "reuseport") == 0) {
		return jutil_get_bool(value, &conf->tcp_reuseport);
	}
	if (strcmp(key, "keepalive") == 0) {
		return jutil_get_bool(value, &conf->tcp_keepalive);
	}
	if (strcmp(key, "nodelay") == 0) {
		return jutil_get_bool(value, &conf->tcp_nodelay);
	}
	if (strcmp(key, "sndbuf") == 0) {
		return jutil_get_int(value, &conf->tcp_sndbuf);
	}
	if (strcmp(key, "rcvbuf") == 0) {
		return jutil_get_int(value, &conf->tcp_rcvbuf);
	}
	LOGW_F("unknown config: \"tcp.%s\"", key);
	return true;
}

static bool
udp_scope_cb(void *ud, const char *key, const struct jutil_value *value)
{
	struct config *restrict conf = ud;
	if (strcmp(key, "reuseport") == 0) {
		return jutil_get_bool(value, &conf->udp_reuseport);
	}
	if (strcmp(key, "sndbuf") == 0) {
		return jutil_get_int(value, &conf->udp_sndbuf);
	}
	if (strcmp(key, "rcvbuf") == 0) {
		return jutil_get_int(value, &conf->udp_rcvbuf);
	}
	LOGW_F("unknown config: \"udp.%s\"", key);
	return true;
}

static bool
main_scope_cb(void *ud, const char *key, const struct jutil_value *value)
{
	struct config *restrict conf = ud;
	if (strcmp(key, "kcp") == 0) {
		return jutil_walk_object(conf, value, kcp_scope_cb);
	}
	if (strcmp(key, "udp") == 0) {
		return jutil_walk_object(conf, value, udp_scope_cb);
	}
	if (strcmp(key, "tcp") == 0) {
		return jutil_walk_object(conf, value, tcp_scope_cb);
	}
	if (strcmp(key, "listen") == 0) {
		conf->listen = jutil_get_string(value);
		return conf->listen != NULL;
	}
	if (strcmp(key, "connect") == 0) {
		conf->connect = jutil_get_string(value);
		return conf->connect != NULL;
	}
	if (strcmp(key, "kcp_bind") == 0) {
		conf->kcp_bind = jutil_get_string(value);
		return conf->kcp_bind != NULL;
	}
	if (strcmp(key, "kcp_connect") == 0) {
		conf->kcp_connect = jutil_get_string(value);
		return conf->kcp_connect != NULL;
	}
	if (strcmp(key, "rendezvous_server") == 0) {
		conf->rendezvous_server = jutil_get_string(value);
		return conf->rendezvous_server != NULL;
	}
	if (strcmp(key, "http_listen") == 0) {
		conf->http_listen = jutil_get_string(value);
		return conf->http_listen != NULL;
	}
	if (strcmp(key, "netdev") == 0) {
		conf->netdev = jutil_get_string(value);
		return conf->netdev != NULL;
	}
#if WITH_CRYPTO
	if (strcmp(key, "method") == 0) {
		conf->method = jutil_get_string(value);
		return conf->method != NULL;
	}
	if (strcmp(key, "password") == 0) {
		conf->password = jutil_get_string(value);
		return conf->password != NULL;
	}
	if (strcmp(key, "psk") == 0) {
		conf->psk = jutil_get_string(value);
		return conf->psk != NULL;
	}
#endif /* WITH_CRYPTO */
#if WITH_OBFS
	if (strcmp(key, "obfs") == 0) {
		conf->obfs = jutil_get_string(value);
		return conf->obfs != NULL;
	}
#endif /* WITH_OBFS */
	if (strcmp(key, "linger") == 0) {
		return jutil_get_int(value, &conf->linger);
	}
	if (strcmp(key, "timeout") == 0) {
		return jutil_get_int(value, &conf->timeout);
	}
	if (strcmp(key, "keepalive") == 0) {
		return jutil_get_int(value, &conf->keepalive);
	}
	if (strcmp(key, "time_wait") == 0) {
		return jutil_get_int(value, &conf->time_wait);
	}
	if (strcmp(key, "loglevel") == 0) {
		return jutil_get_int(value, &conf->log_level);
	}
	if (strcmp(key, "user") == 0) {
		conf->user = jutil_get_string(value);
		return conf->user != NULL;
	}
	LOGW_F("unknown config: `%s'", key);
	return true;
}

#undef NAME_EQUAL

const char *conf_modestr(const struct config *restrict conf)
{
	if (conf->mode & MODE_SERVER) {
		return "server";
	}
	if (conf->mode & MODE_CLIENT) {
		return "client";
	}
	return "rendezvous server";
}

static struct config conf_default(void)
{
	return (struct config){
		.kcp_mtu = 1400,
		.kcp_sndwnd = 256,
		.kcp_rcvwnd = 256,
		.kcp_nodelay = 1,
		.kcp_interval = 100,
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
		.udp_reuseport = false,
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
	if (conf->connect != NULL) {
		mode |= MODE_SERVER;
	}
	if (conf->listen != NULL) {
		mode |= MODE_CLIENT;
	}
	if (conf->rendezvous_server != NULL) {
		mode |= MODE_RENDEZVOUS;
	}
	if ((mode & (MODE_SERVER | MODE_CLIENT)) ==
	    (MODE_SERVER | MODE_CLIENT)) {
		LOGE("config: can't be both client and server at the same time");
		return false;
	}
	if ((mode & MODE_RENDEZVOUS) != 0) {
		if (conf->keepalive <= 0) {
			LOGE("config: keepalive can't be disabled in rendezvous mode");
			return false;
		}
		if (conf->keepalive > 25) {
			LOGW_F("config: keepalive %d may be too long for rendezvous mode",
			       conf->keepalive);
		}
	}
	if (((mode & (MODE_RENDEZVOUS | MODE_SERVER)) == MODE_SERVER &&
	     conf->kcp_bind == NULL) ||
	    ((mode & (MODE_RENDEZVOUS | MODE_CLIENT)) == MODE_CLIENT &&
	     conf->kcp_connect == NULL) ||
	    ((mode & (MODE_SERVER | MODE_CLIENT)) == 0 &&
	     conf->kcp_bind == NULL)) {
		LOGE("config: no service could be provided (are you missing some address field?)");
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
			LOG_LEVEL_VERYVERBOSE);
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
	UTIL_SAFE_FREE(conf->rendezvous_server);
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
