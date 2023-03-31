/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "util.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "utils/minmax.h"
#include "utils/mcache.h"
#include "aead.h"
#include "pktqueue.h"
#include "kcp/ikcp.h"

#include <unistd.h>
#include <pwd.h>
#if _BSD_SOURCE || _GNU_SOURCE
#include <grp.h>
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define b64_malloc(ptr) malloc(ptr)
#define b64_realloc(ptr, size) realloc(ptr, size)
#include "b64/b64.h"

uint32_t tstamp2ms(const ev_tstamp t)
{
	return (uint32_t)fmod(t * 1e+3, UINT32_MAX + 1.0);
}

struct mcache *msgpool;

void init(void)
{
	const size_t size =
		MAX(sizeof(struct IKCPSEG) + MAX_PACKET_SIZE,
		    sizeof(struct msgframe));
	msgpool = mcache_new(256, size);
	CHECKOOM(msgpool);
	ikcp_segment_pool = msgpool;
}

void uninit(void)
{
	mcache_free(msgpool);
}

void drop_privileges(const char *user)
{
	if (getuid() != 0) {
		return;
	}
	if (user == NULL) {
		LOGW("running as root, please consider set \"user\" field in config");
		return;
	}
	if (chdir("/") != 0) {
		const int err = errno;
		LOGW_F("chdir: %s", strerror(err));
	}
	struct passwd *restrict pwd = getpwnam(user);
	if (pwd == NULL) {
		LOGW_F("su: user \"%s\" does not exist ", user);
		return;
	}
	if (pwd->pw_uid == 0) {
		return;
	}
	LOGI_F("su: user=%s uid=%jd gid=%jd", user, (intmax_t)pwd->pw_uid,
	       (intmax_t)pwd->pw_gid);
#if _BSD_SOURCE || _GNU_SOURCE
	if (setgroups(0, NULL) != 0) {
		const int err = errno;
		LOGW_F("unable to drop supplementary group privileges: %s",
		       strerror(err));
	}
#endif
	if (setgid(pwd->pw_gid) != 0 || setegid(pwd->pw_gid) != 0) {
		const int err = errno;
		LOGW_F("unable to drop group privileges: %s", strerror(err));
	}
	if (setuid(pwd->pw_uid) != 0 || seteuid(pwd->pw_uid) != 0) {
		const int err = errno;
		LOGW_F("unable to drop user privileges: %s", strerror(err));
	}
}

#if WITH_CRYPTO
void genpsk(const char *method)
{
	struct aead *crypto = aead_create(method);
	if (crypto == NULL) {
		LOGW_F("unsupported crypto method: %s", method);
		aead_list_methods();
		exit(EXIT_FAILURE);
	}
	unsigned char *key = malloc(crypto->key_size);
	CHECKOOM(key);
	aead_keygen(crypto, key);
	char *keystr = b64_encode(key, crypto->key_size);
	printf("%s\n", keystr);
	free(key);
	free(keystr);
	aead_free(crypto);
}
#endif
