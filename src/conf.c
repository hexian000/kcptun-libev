/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"

#include "conf_schema.gen.h"
#include "util.h"

#include "utils/slog.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Read the entire file at path into a heap-allocated, NUL-terminated buffer.
 * Returns the buffer and sets *out_len to the byte count (excluding NUL).
 * The caller must free() the returned pointer.  Returns NULL on error. */
static char *read_alloc(const char *path, size_t *out_len)
{
	FILE *f = fopen(path, "r");
	if (f == NULL) {
		return NULL;
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		(void)fclose(f);
		return NULL;
	}
	const long pos = ftell(f);
	if (pos < 0) {
		(void)fclose(f);
		return NULL;
	}
	if (fseek(f, 0, SEEK_SET) != 0) {
		(void)fclose(f);
		return NULL;
	}
	const size_t cap = (size_t)pos;
	char *buf = malloc(cap + 1);
	if (buf == NULL) {
		(void)fclose(f);
		return NULL;
	}
	const size_t n = fread(buf, 1, cap, f);
	(void)fclose(f);
	if (n == 0 && cap > 0) {
		free(buf);
		return NULL;
	}
	buf[n] = '\0';
	*out_len = n;
	return buf;
}

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
	_Generic(value, int: range_check_int)(key, value, lbound, ubound)

static bool conf_check(struct config *restrict conf)
{
	/* 0. basic check */
	if (conf->service_idlen > 256) {
		LOGE("config: service_id too long");
		return false;
	}

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
	if (((mode & (MODE_SERVER | MODE_RENDEZVOUS)) == MODE_SERVER &&
	     conf->kcp_bind == NULL) ||
	    ((mode & (MODE_CLIENT | MODE_RENDEZVOUS)) == MODE_CLIENT &&
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

/* strndup a parsed zero-copy string field into a freshly-allocated buffer.
 * Returns false and goes to oom on allocation failure. */
#define COPY_STRING(dst, key)                                                  \
	do {                                                                   \
		if ((parsed.key.str) != NULL) {                                \
			(dst) = strndup(parsed.key.str, parsed.key.len);       \
			if ((dst) == NULL) {                                   \
				goto oom;                                      \
			}                                                      \
		}                                                              \
	} while (0)

struct config *conf_read(const char *path)
{
	struct config *conf = malloc(sizeof(struct config));
	if (conf == NULL) {
		LOGOOM();
		return NULL;
	}
	*conf = (struct config){ 0 };

	size_t buflen = 0;
	char *buf = read_alloc(path, &buflen);
	if (buf == NULL) {
		LOGE_F("conf: failed to read \"%s\"", path);
		conf_free(conf);
		return NULL;
	}

	struct json_conf parsed = { 0 };
	if (!json_unmarshal_conf(&parsed, buf, buflen)) {
		LOGE_F("conf: failed to parse \"%s\"", path);
		free(buf);
		conf_free(conf);
		return NULL;
	}

	/* copy strings (strndup since the json buffer is freed below) */
	COPY_STRING(conf->listen, listen);
	COPY_STRING(conf->connect, connect);
	COPY_STRING(conf->kcp_bind, kcp_bind);
	COPY_STRING(conf->kcp_connect, kcp_connect);
	COPY_STRING(conf->rendezvous_server, rendezvous_server);
	if (parsed.service_id.str != NULL) {
		conf->service_id =
			strndup(parsed.service_id.str, parsed.service_id.len);
		if (conf->service_id == NULL) {
			goto oom;
		}
		conf->service_idlen = parsed.service_id.len;
	}
	COPY_STRING(conf->http_listen, http_listen);
	COPY_STRING(conf->netdev, netdev);
	COPY_STRING(conf->log, log);
	COPY_STRING(conf->user, user);
#if WITH_CRYPTO
	COPY_STRING(conf->method, method);
	COPY_STRING(conf->password, password);
	COPY_STRING(conf->psk, psk);
#endif /* WITH_CRYPTO */
#if WITH_OBFS
	COPY_STRING(conf->obfs, obfs);
#endif /* WITH_OBFS */

	/* copy kcp settings */
	{
		const struct json_conf_kcp *k = &parsed.kcp;
		conf->kcp_mtu = (int)k->mtu;
		conf->kcp_sndwnd = (int)k->sndwnd;
		conf->kcp_rcvwnd = (int)k->rcvwnd;
		conf->kcp_nodelay = (int)k->nodelay;
		conf->kcp_interval = (int)k->interval;
		conf->kcp_resend = (int)k->resend;
		conf->kcp_nc = (int)k->nc;
		conf->kcp_flush = (int)k->flush;
	}

	/* copy tcp settings */
	{
		const struct json_conf_tcp *t = &parsed.tcp;
		conf->tcp_reuseport = t->reuseport;
		conf->tcp_keepalive = t->keepalive;
		conf->tcp_nodelay = t->nodelay;
		conf->tcp_sndbuf = (int)t->sndbuf;
		conf->tcp_rcvbuf = (int)t->rcvbuf;
	}

	/* copy udp settings */
	{
		const struct json_conf_udp *u = &parsed.udp;
		conf->udp_reuseport = u->reuseport;
		conf->udp_sndbuf = (int)u->sndbuf;
		conf->udp_rcvbuf = (int)u->rcvbuf;
	}

	/* copy top-level integer settings */
	conf->timeout = (int)parsed.timeout;
	conf->linger = (int)parsed.linger;
	conf->keepalive = (int)parsed.keepalive;
	conf->time_wait = (int)parsed.time_wait;
	conf->log_level = (int)parsed.loglevel;

	json_free_conf(&parsed);
	free(buf);

	if (!conf_check(conf)) {
		conf_free(conf);
		return NULL;
	}
	return conf;
oom:
	LOGOOM();
	json_free_conf(&parsed);
	free(buf);
	conf_free(conf);
	return NULL;
}

void conf_free(struct config *conf)
{
	UTIL_SAFE_FREE(conf->listen);
	UTIL_SAFE_FREE(conf->connect);
	UTIL_SAFE_FREE(conf->kcp_bind);
	UTIL_SAFE_FREE(conf->kcp_connect);
	UTIL_SAFE_FREE(conf->rendezvous_server);
	UTIL_SAFE_FREE(conf->service_id);
	UTIL_SAFE_FREE(conf->http_listen);
	UTIL_SAFE_FREE(conf->netdev);
	UTIL_SAFE_FREE(conf->log);
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
