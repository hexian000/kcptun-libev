/* kcptun-libev (c) 2019-2022 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "util.h"
#include "utils/slog.h"
#include "utils/mcache.h"
#include "aead.h"
#include "pktqueue.h"

#include "kcp/ikcp.h"

#include <stddef.h>

#define b64_malloc(ptr) malloc(ptr)
#define b64_realloc(ptr, size) realloc(ptr, size)
#include "b64/b64.h"

#include <unistd.h>
#include <pwd.h>
#if _BSD_SOURCE || _GNU_SOURCE
#include <grp.h>
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>

void print_bin(const void *b, const size_t n)
{
#ifdef NDEBUG
	UNUSED(b);
	UNUSED(n);
#else
	fprintf(stderr, "[%zu] ", n);
	for (size_t i = 0; i < n; i++) {
		fprintf(stderr, "%02" PRIX8, ((const uint8_t *)b)[i]);
	}
	fprintf(stderr, "\n");
	fflush(stderr);
#endif /* NDEBUG */
}

char *util_strndup(const char *str, size_t n)
{
	if (str == NULL) {
		return NULL;
	}
	char *s = malloc(n + 1);
	if (s == NULL) {
		return NULL;
	}
	memcpy(s, str, n);
	s[n] = 0;
	return s;
}

char *util_strdup(const char *str)
{
	if (str == NULL) {
		return NULL;
	}
	return util_strndup(str, strlen(str));
}

/* Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs" */
static inline uint32_t xorshift32(uint32_t x)
{
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return x;
}

uint32_t rand32(void)
{
	static uint32_t x = UINT32_C(0);
	if (x == UINT32_C(0)) {
		x = time(NULL);
	}
	x = xorshift32(x);
	return x;
}

uint32_t tstamp2ms(const ev_tstamp t)
{
	return (uint32_t)fmod(t * 1e+3, UINT32_MAX + 1.0);
}

static void *ev_realloc(void *p, long n)
{
	return realloc(p, n);
}

struct mcache msgpool;

void init(void)
{
	ev_set_allocator(&ev_realloc);
	size_t size = sizeof(struct IKCPSEG) + MAX_PACKET_SIZE;
	if (size < sizeof(struct msgframe)) {
		size = sizeof(struct msgframe);
	}
	msgpool = mcache_new(256, size);
	CHECKOOM(msgpool.p);
	ikcp_segment_pool = &msgpool;
}

void uninit(void)
{
	mcache_free(&msgpool);
}

bool getuserid(const char *name, uid_t *userid, gid_t *groupid)
{
	struct passwd *restrict pwd = getpwnam(name);
	if (pwd == NULL) {
		const int err = errno;
		LOGW_F("getpwnam: %s", strerror(err));
		return false;
	}
	*userid = pwd->pw_uid;
	*groupid = pwd->pw_gid;
	return true;
}

void drop_privileges(const char *user)
{
	if (getuid() != 0) {
		return;
	}
	if (user == NULL) {
		LOGW("running as root, please consider set \"user\" field in config ");
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
	unsigned char *key = must_malloc(crypto->key_size);
	aead_keygen(crypto, key);
	char *keystr = b64_encode(key, crypto->key_size);
	printf("%s\n", keystr);
	free(key);
	free(keystr);
	aead_free(crypto);
}
#endif
