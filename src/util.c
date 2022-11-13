#include "util.h"
#include "aead.h"

#include "kcp/ikcp.h"
#include "slog.h"

#define b64_malloc(ptr) util_malloc(ptr)
#define b64_realloc(ptr, size) util_realloc(ptr, size)
#include "b64/b64.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#if _BSD_SOURCE || _GNU_SOURCE
#include <grp.h>
#endif

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
	char *s = util_malloc(n + 1);
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

static void *kcp_malloc(size_t n)
{
	return util_malloc(n);
}

static void kcp_free(void *p)
{
	util_free(p);
}

static void *ev_realloc(void *p, long n)
{
	return util_realloc(p, n);
}

void init(void)
{
	ev_set_allocator(&ev_realloc);
	ikcp_allocator(&kcp_malloc, &kcp_free);
}

bool getuserid(const char *name, uid_t *userid, gid_t *groupid)
{
	struct passwd *restrict pwd = getpwnam(name);
	if (pwd == NULL) {
		LOGW_PERROR("getpwnam");
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
		LOGW_PERROR("chdir");
	}
	struct passwd *restrict pwd = getpwnam(user);
	if (pwd == NULL) {
		LOGW_F("su: user \"%s\" does not exist ", user);
		return;
	}
	if (pwd->pw_uid == 0) {
		return;
	}
	LOGD_F("su: user=%s uid=%jd gid=%jd", user, (intmax_t)pwd->pw_uid,
	       (intmax_t)pwd->pw_gid);
#if _BSD_SOURCE || _GNU_SOURCE
	if (setgroups(0, NULL) != 0) {
		LOGW_PERROR("unable to drop supplementary group privileges");
	}
#endif
	if (setgid(pwd->pw_gid) != 0 || setegid(pwd->pw_gid) != 0) {
		LOGW_PERROR("unable to drop group privileges");
	}
	if (setuid(pwd->pw_uid) != 0 || seteuid(pwd->pw_uid) != 0) {
		LOGW_PERROR("unable to drop user privileges");
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
	util_free(key);
	util_free(keystr);
	aead_free(crypto);
}
#endif
