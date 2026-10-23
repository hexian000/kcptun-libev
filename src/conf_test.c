/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#if defined(TEST_NO_CRYPTO)
#undef WITH_CRYPTO
#define WITH_CRYPTO 0
#endif
#if defined(TEST_NO_CRYPTO) || defined(TEST_NO_OBFS)
#undef WITH_OBFS
#define WITH_OBFS 0
#endif

#include "conf.h"

#include "conf.c"

#include "utils/debug.h"
#include "utils/slog.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static char captured[2048];
static size_t captured_len;

static void capture(void *user, const unsigned char *buf, size_t len)
{
	(void)user;
	(void)fwrite(buf, 1, len, stderr);
	const size_t room = sizeof(captured) - captured_len - 1;
	if (len > room) {
		len = room;
	}
	memcpy(captured + captured_len, buf, len);
	captured_len += len;
	captured[captured_len] = '\0';
}

static void check_config(
	const char *path, const char *fields, bool accepted,
	const char *diagnostic)
{
	FILE *file = fopen(path, "w");
	CHECK(file != NULL);
	CHECK(fprintf(file, "{\"kcp_bind\":\"127.0.0.1:0\"%s}", fields) > 0);
	CHECK(fclose(file) == 0);
	captured_len = 0;
	captured[0] = '\0';
	struct config *conf = conf_read(path);
	CHECKMSGF(
		(conf != NULL) == accepted, "config %s: expected %s", fields,
		accepted ? "acceptance" : "rejection");
	if (diagnostic != NULL) {
		CHECK(strstr(captured, diagnostic) != NULL);
	}
	conf_free(conf);
}

static void check_presence_defaults(const char *path)
{
	FILE *file = fopen(path, "w");
	CHECK(file != NULL);
	CHECK(fputs("{\"kcp_bind\":\"127.0.0.1:0\",\"kcp\":{\"interval\":50},"
		    "\"tcp\":{\"nodelay\":false}}",
		    file) >= 0);
	CHECK(fclose(file) == 0);
	struct config *conf = conf_read(path);
	CHECK(conf != NULL);
	CHECK(conf->connect == NULL && conf->listen == NULL);
	CHECK(conf->rendezvous_server == NULL);
	CHECK(conf->http_listen == NULL && conf->service_id == NULL);
	CHECK(conf->netdev == NULL && conf->log == NULL && conf->user == NULL);
#if WITH_CRYPTO
	CHECK(conf->method == NULL && conf->password == NULL &&
	      conf->psk == NULL);
#endif
#if WITH_OBFS
	CHECK(conf->obfs == NULL);
#endif
	CHECK(conf->kcp_interval == 50);
	CHECK(conf->kcp_mtu == 1400 && conf->kcp_sndwnd == 256);
	CHECK(!conf->tcp_nodelay);
	CHECK(conf->timeout == 600 && conf->keepalive == 25);
	conf_free(conf);
}

int main(int argc, char **argv)
{
	CHECK(argc == 2);
	slog_setlevel(LOG_LEVEL_DEBUG);
	slog_setoutput(SLOG_OUTPUT_WRITER, capture, (void *)NULL);
	const char *crypto_error =
		WITH_CRYPTO ? NULL :
			      "crypto settings are unavailable in this build";
	const char *obfs_error =
		WITH_OBFS ? NULL : "obfs is unavailable in this build";
	check_config(argv[1], "", true, NULL);
	check_presence_defaults(argv[1]);
	check_config(argv[1], ",\"unknown\":\"ignored\"", true, NULL);
	check_config(
		argv[1], ",\"method\":\"xchacha20poly1305_ietf\"", false,
		WITH_CRYPTO ? "method requires psk or password" : crypto_error);
	check_config(
		argv[1], ",\"method\":\"\"", false,
		WITH_CRYPTO ? "method requires psk or password" : crypto_error);
	const char *crypto_fields[] = {
		",\"method\":\"xchacha20poly1305_ietf\",\"password\":\"secret\"",
		",\"password\":\"secret\"",
		",\"psk\":\"key\"",
		",\"password\":\"\"",
		",\"psk\":\"\"",
	};
	for (size_t i = 0; i < sizeof(crypto_fields) / sizeof(crypto_fields[0]);
	     i++) {
		check_config(
			argv[1], crypto_fields[i], WITH_CRYPTO, crypto_error);
	}
	check_config(argv[1], ",\"obfs\":\"dpi/tcp\"", WITH_OBFS, obfs_error);
	check_config(argv[1], ",\"obfs\":\"\"", WITH_OBFS, obfs_error);
	check_config(argv[1], "", true, NULL);
	CHECK(remove(argv[1]) == 0);
	return 0;
}
