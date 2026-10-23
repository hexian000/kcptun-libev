/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"

#include "conf_presence.gen.h"
#include "conf_schema.gen.h"
#include "util.h"

#include "codec/json.h"
#include "utils/slog.h"

#if WITH_CRYPTO
#include <sodium.h>
#endif

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIN_SOCKBUF_SIZE 4096

static bool conf_check(struct config *restrict conf)
{
	/* 0. basic check */
	if (conf->service_idlen > SERVICE_ID_MAX_LENGTH) {
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
	if (conf->method != NULL && conf->psk == NULL &&
	    conf->password == NULL) {
		LOGE("config: method requires psk or password");
		return false;
	}
	if (conf->psk != NULL && conf->password != NULL) {
		LOGE("config: psk and password cannot be specified at the same time");
		return false;
	}
#endif /* WITH_CRYPTO */

	/* 3. buffer-size sanity check; the numeric ranges of every scalar
	   field are enforced at parse time by the JSON schema constraints
	   compiled into json_unmarshal_conf, so no range check is repeated here */
	if ((conf->tcp_sndbuf > 0 && conf->tcp_sndbuf < MIN_SOCKBUF_SIZE) ||
	    (conf->tcp_rcvbuf > 0 && conf->tcp_rcvbuf < MIN_SOCKBUF_SIZE)) {
		LOGW("config: probably too small tcp buffer");
	}
	if ((conf->udp_sndbuf > 0 && conf->udp_sndbuf < MIN_SOCKBUF_SIZE) ||
	    (conf->udp_rcvbuf > 0 && conf->udp_rcvbuf < MIN_SOCKBUF_SIZE)) {
		LOGW("config: probably too small udp buffer");
	}
	return true;
}

/* Narrow an unsigned schema field to int, clamping instead of relying on
 * implementation-defined wraparound. Every field's schema maximum is far below
 * INT_MAX and enforced at parse time, so the clamp is an unreachable backstop. */
static int narrow_uint_to_int(const unsigned value)
{
	return value > (unsigned)INT_MAX ? INT_MAX : (int)value;
}

/* Duplicate a parsed zero-copy string field (not NUL-terminated) into a
 * freshly-allocated, NUL-terminated buffer. A JSON string may hold a literal
 * NUL (a decoded escape) that strndup would silently truncate; reject that
 * rather than corrupt the value with no diagnostic. Leaves *dst untouched when
 * the field is absent. Returns false on error (already logged). */
static bool dup_field(
	char **restrict dst, const char *restrict key,
	const struct json_string *restrict src)
{
	if (src->str == NULL) {
		return true;
	}
	if (memchr(src->str, '\0', src->len) != NULL) {
		LOGE_F("config: \"%s\" contains an embedded NUL byte", key);
		return false;
	}
	char *s = strndup(src->str, src->len);
	if (s == NULL) {
		LOGOOM();
		return false;
	}
	*dst = s;
	return true;
}

#define COPY_STRING(dst, key)                                                  \
	do {                                                                   \
		if (!dup_field(&(dst), #key, &parsed->key)) {                  \
			return false;                                          \
		}                                                              \
	} while (0)

/* Copy the parsed fields into conf. The parsed buffer is freed by the caller,
 * so strings are duplicated. Returns false on error. */
static bool conf_apply(
	struct config *restrict conf, const struct json_conf *restrict parsed)
{
#if !WITH_CRYPTO
	if (parsed->method.str != NULL || parsed->password.str != NULL ||
	    parsed->psk.str != NULL) {
		LOGE("config: crypto settings are unavailable in this build");
		return false;
	}
#endif /* !WITH_CRYPTO */
#if !WITH_OBFS
	if (parsed->obfs.str != NULL) {
		LOGE("config: obfs is unavailable in this build");
		return false;
	}
#endif /* !WITH_OBFS */

	COPY_STRING(conf->listen, listen);
	COPY_STRING(conf->connect, connect);
	COPY_STRING(conf->kcp_bind, kcp_bind);
	COPY_STRING(conf->kcp_connect, kcp_connect);
	COPY_STRING(conf->rendezvous_server, rendezvous_server);
	COPY_STRING(conf->service_id, service_id);
	if (conf->service_id != NULL) {
		conf->service_idlen = parsed->service_id.len;
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
		const struct json_conf_kcp *k = &parsed->kcp;
		conf->kcp_mtu = narrow_uint_to_int(k->mtu);
		conf->kcp_sndwnd = narrow_uint_to_int(k->sndwnd);
		conf->kcp_rcvwnd = narrow_uint_to_int(k->rcvwnd);
		conf->kcp_nodelay = narrow_uint_to_int(k->nodelay);
		conf->kcp_interval = narrow_uint_to_int(k->interval);
		conf->kcp_resend = narrow_uint_to_int(k->resend);
		conf->kcp_nc = narrow_uint_to_int(k->nc);
		conf->kcp_flush = narrow_uint_to_int(k->flush);
	}

	/* copy tcp settings */
	{
		const struct json_conf_tcp *t = &parsed->tcp;
		conf->tcp_reuseport = t->reuseport;
		conf->tcp_keepalive = t->keepalive;
		conf->tcp_nodelay = t->nodelay;
		conf->tcp_sndbuf = narrow_uint_to_int(t->sndbuf);
		conf->tcp_rcvbuf = narrow_uint_to_int(t->rcvbuf);
	}

	/* copy udp settings */
	{
		const struct json_conf_udp *u = &parsed->udp;
		conf->udp_reuseport = u->reuseport;
		conf->udp_sndbuf = narrow_uint_to_int(u->sndbuf);
		conf->udp_rcvbuf = narrow_uint_to_int(u->rcvbuf);
	}

	/* copy top-level integer settings */
	conf->max_services = narrow_uint_to_int(parsed->max_services);
	conf->timeout = narrow_uint_to_int(parsed->timeout);
	conf->linger = narrow_uint_to_int(parsed->linger);
	conf->keepalive = narrow_uint_to_int(parsed->keepalive);
	conf->time_wait = narrow_uint_to_int(parsed->time_wait);
	conf->log_level = narrow_uint_to_int(parsed->loglevel);
	return true;
}

#undef COPY_STRING

/* The view borrows the explicit input and generated defaults. Missing
 * strings remain NULL so they do not enable a transport or crypto mode. */
static struct json_conf
conf_merge(const struct json_conf *defaults, const struct present_conf *input)
{
	struct json_conf parsed = *defaults;
#define COPY_FIELD(dst, src, field)                                            \
	do {                                                                   \
		if ((src).has_##field) {                                       \
			(dst).field = (src).field;                             \
		}                                                              \
	} while (0)
#define COPY_STRING(dst, src, field)                                           \
	((dst).field =                                                         \
		 (src).has_##field ? (src).field : (struct json_string){ 0 })
	COPY_STRING(parsed, (*input), connect);
	COPY_STRING(parsed, (*input), http_listen);
	COPY_FIELD(parsed.kcp, (*input).kcp, flush);
	COPY_FIELD(parsed.kcp, (*input).kcp, interval);
	COPY_FIELD(parsed.kcp, (*input).kcp, mtu);
	COPY_FIELD(parsed.kcp, (*input).kcp, nc);
	COPY_FIELD(parsed.kcp, (*input).kcp, nodelay);
	COPY_FIELD(parsed.kcp, (*input).kcp, rcvwnd);
	COPY_FIELD(parsed.kcp, (*input).kcp, resend);
	COPY_FIELD(parsed.kcp, (*input).kcp, sndwnd);
	COPY_STRING(parsed, (*input), kcp_bind);
	COPY_STRING(parsed, (*input), kcp_connect);
	COPY_FIELD(parsed, (*input), keepalive);
	COPY_FIELD(parsed, (*input), linger);
	COPY_STRING(parsed, (*input), listen);
	COPY_STRING(parsed, (*input), log);
	COPY_FIELD(parsed, (*input), loglevel);
	COPY_FIELD(parsed, (*input), max_services);
	COPY_STRING(parsed, (*input), method);
	COPY_STRING(parsed, (*input), netdev);
	COPY_STRING(parsed, (*input), obfs);
	COPY_STRING(parsed, (*input), password);
	COPY_STRING(parsed, (*input), psk);
	COPY_STRING(parsed, (*input), rendezvous_server);
	COPY_STRING(parsed, (*input), service_id);
	COPY_FIELD(parsed.tcp, (*input).tcp, keepalive);
	COPY_FIELD(parsed.tcp, (*input).tcp, nodelay);
	COPY_FIELD(parsed.tcp, (*input).tcp, rcvbuf);
	COPY_FIELD(parsed.tcp, (*input).tcp, reuseport);
	COPY_FIELD(parsed.tcp, (*input).tcp, sndbuf);
	COPY_FIELD(parsed, (*input), time_wait);
	COPY_FIELD(parsed, (*input), timeout);
	COPY_FIELD(parsed.udp, (*input).udp, rcvbuf);
	COPY_FIELD(parsed.udp, (*input).udp, reuseport);
	COPY_FIELD(parsed.udp, (*input).udp, sndbuf);
	COPY_STRING(parsed, (*input), user);
#undef COPY_STRING
#undef COPY_FIELD
	return parsed;
}

/* Read the entire file at path into a heap-allocated, NUL-terminated buffer.
 * Returns the buffer and sets *out_len to the byte count (excluding NUL).
 * The caller must free() the returned pointer.  Returns NULL on error. */
static char *read_alloc(const char *path, size_t *out_len)
{
	FILE *f = fopen(path, "r");
	if (f == NULL) {
		const int err = errno;
		LOGE_F("config: failed to open `%s': %s", path, strerror(err));
		return NULL;
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		const int err = errno;
		LOGE_F("config: failed to seek `%s': %s", path, strerror(err));
		(void)fclose(f);
		return NULL;
	}
	const long pos = ftell(f);
	if (pos < 0) {
		const int err = errno;
		LOGE_F("config: failed to tell `%s': %s", path, strerror(err));
		(void)fclose(f);
		return NULL;
	}
	if (fseek(f, 0, SEEK_SET) != 0) {
		const int err = errno;
		LOGE_F("config: failed to seek `%s': %s", path, strerror(err));
		(void)fclose(f);
		return NULL;
	}
	const size_t cap = (size_t)pos;
	char *buf = malloc(cap + 1);
	if (buf == NULL) {
		LOGOOM();
		(void)fclose(f);
		return NULL;
	}
	buf[cap] = '\0';
	const size_t n = fread(buf, 1, cap, f);
	(void)fclose(f);
	if (n != cap) {
		LOGE_F("config: short read on `%s' (%zu/%zu bytes)", path, n,
		       cap);
		free(buf);
		return NULL;
	}
	*out_len = n;
	return buf;
}

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
		/* read_alloc() already logged the specific reason */
		conf_free(conf);
		return NULL;
	}

	struct present_conf input = { 0 };
	if (!present_unmarshal_conf(&input, buf, buflen)) {
		LOGE_F("config: failed to parse `%s'", path);
		free(buf);
		conf_free(conf);
		return NULL;
	}
	char empty[] = "{}";
	struct json_conf defaults = { 0 };
	if (!json_unmarshal_conf(&defaults, empty, sizeof(empty) - 1)) {
		LOGOOM();
		present_free_conf(&input);
		free(buf);
		conf_free(conf);
		return NULL;
	}
	const struct json_conf parsed = conf_merge(&defaults, &input);
	const bool ok = conf_apply(conf, &parsed);
	json_free_conf(&defaults);
	present_free_conf(&input);
	free(buf);
	if (!ok) {
		conf_free(conf);
		return NULL;
	}

	if (!conf_check(conf)) {
		conf_free(conf);
		return NULL;
	}
	return conf;
}

const char *conf_modestr(const struct config *restrict conf)
{
	if (conf->mode & MODE_SERVER) {
		return "server";
	}
	if (conf->mode & MODE_CLIENT) {
		return "client";
	}
	if (conf->mode & MODE_RENDEZVOUS) {
		return "rendezvous peer";
	}
	return "rendezvous server";
}

void conf_free(struct config *conf)
{
	if (conf == NULL) {
		return;
	}
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
	if (conf->password != NULL) {
		sodium_memzero(conf->password, strlen(conf->password));
	}
	if (conf->psk != NULL) {
		sodium_memzero(conf->psk, strlen(conf->psk));
	}
	UTIL_SAFE_FREE(conf->password);
	UTIL_SAFE_FREE(conf->psk);
#endif /* WITH_CRYPTO */
#if WITH_OBFS
	UTIL_SAFE_FREE(conf->obfs);
#endif
	free(conf);
}
