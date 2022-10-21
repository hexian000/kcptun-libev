#include "aead.h"
#include "slog.h"
#include "util.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if WITH_SODIUM

#include <sodium.h>

static bool sodium_init_done = false;

static bool aead_init(void)
{
	if (sodium_init_done) {
		return true;
	}
	const int ret = sodium_init();
	if (ret != 0) {
		LOGE_F("sodium_init failed: %d", ret);
		return false;
	}
	sodium_init_done = true;
	return true;
}

static int
kdf(const size_t key_size, unsigned char *restrict key,
    const char *restrict password)
{
	const char salt_str[] = "kcptun-libev";
	unsigned char salt[crypto_pwhash_argon2id_SALTBYTES];
	int r = crypto_generichash(
		salt, crypto_pwhash_argon2id_SALTBYTES,
		(unsigned char *)salt_str, strlen(salt_str), NULL, 0);
	if (r) {
		return r;
	}
	r = crypto_pwhash_argon2id(
		(unsigned char *)key, key_size, password, strlen(password),
		salt, crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE,
		crypto_pwhash_argon2id_MEMLIMIT_MIN,
		crypto_pwhash_argon2id_ALG_ARGON2ID13);
	return r;
}

struct aead_impl {
	void (*keygen)(unsigned char *);

	int (*seal)(
		unsigned char *c, unsigned long long *clen_p,
		const unsigned char *m, unsigned long long mlen,
		const unsigned char *ad, unsigned long long adlen,
		const unsigned char *nsec, const unsigned char *npub,
		const unsigned char *k);

	int (*open)(
		unsigned char *m, unsigned long long *mlen_p,
		unsigned char *nsec, const unsigned char *c,
		unsigned long long clen, const unsigned char *ad,
		unsigned long long adlen, const unsigned char *npub,
		const unsigned char *k);

	unsigned char *key;
};

size_t aead_seal(
	struct aead *restrict aead, unsigned char *dst, size_t dst_size,
	const unsigned char *nonce, const unsigned char *plain,
	size_t plain_size, const unsigned char *tag, size_t tag_size)
{
	assert(dst_size >= plain_size + aead->overhead);
	struct aead_impl *restrict impl = aead->impl;
	unsigned long long r_len = dst_size;
	int r = impl->seal(
		dst, &r_len, plain, plain_size, tag, tag_size, NULL, nonce,
		impl->key);
	if (r != 0) {
		LOGV_F("aead_seal: %d", r);
		return 0;
	}
	return r_len;
}

size_t aead_open(
	struct aead *restrict aead, unsigned char *dst, size_t dst_size,
	const unsigned char *nonce, const unsigned char *cipher,
	size_t cipher_size, const unsigned char *tag, size_t tag_size)
{
	assert(dst_size + aead->overhead >= cipher_size);
	struct aead_impl *restrict impl = aead->impl;
	unsigned long long r_len = dst_size;
	int r = impl->open(
		dst, &r_len, NULL, cipher, cipher_size, tag, tag_size, nonce,
		impl->key);
	if (r != 0) {
		LOGV_F("aead_open: %d", r);
		return 0;
	}
	return r_len;
}

enum aead_method {
	method_chacha20poly1305_ietf,
	method_xchacha20poly1305_ietf,
	method_aes256gcm,
	method_MAX,
};

static inline char *strmethod(const enum aead_method m)
{
	switch (m) {
	case method_chacha20poly1305_ietf:
		return "chacha20poly1305_ietf";
	case method_xchacha20poly1305_ietf:
		return "xchacha20poly1305_ietf";
	case method_aes256gcm:
		return "aes256gcm";
	default:
		break;
	}
	return NULL;
}

void aead_list_methods(void)
{
	fprintf(stderr, "methods available:\n");
	for (int i = 0; i < method_MAX; i++) {
		fprintf(stderr, "  %s\n", strmethod(i));
	}
}

struct aead *aead_create(const char *method)
{
	if (!aead_init()) {
		return NULL;
	}
	enum aead_method m;
	size_t nonce_size, overhead, key_size;
	if (strcmp(method, strmethod(method_chacha20poly1305_ietf)) == 0) {
		m = method_chacha20poly1305_ietf;
		nonce_size = crypto_aead_chacha20poly1305_ietf_npubbytes();
		overhead = crypto_aead_chacha20poly1305_ietf_abytes();
		key_size = crypto_aead_chacha20poly1305_ietf_keybytes();
	} else if (strcmp(method, strmethod(method_xchacha20poly1305_ietf)) == 0) {
		m = method_xchacha20poly1305_ietf;
		nonce_size = crypto_aead_xchacha20poly1305_ietf_npubbytes();
		overhead = crypto_aead_xchacha20poly1305_ietf_abytes();
		key_size = crypto_aead_xchacha20poly1305_ietf_keybytes();
	} else if (strcmp(method, strmethod(method_aes256gcm)) == 0) {
		m = method_aes256gcm;
		nonce_size = crypto_aead_aes256gcm_npubbytes();
		overhead = crypto_aead_aes256gcm_abytes();
		key_size = crypto_aead_aes256gcm_keybytes();
	} else {
		LOGW_F("unsupported crypto method: %s", method);
		aead_list_methods();
		return NULL;
	}
	struct aead *aead = util_malloc(sizeof(struct aead));
	if (aead == NULL) {
		return NULL;
	}
	*(size_t *)&aead->nonce_size = nonce_size;
	*(size_t *)&aead->overhead = overhead;
	*(size_t *)&aead->key_size = key_size;
	aead->impl = util_malloc(sizeof(struct aead_impl));
	if (aead->impl == NULL) {
		aead_free(aead);
		return NULL;
	}
	unsigned char *key = sodium_malloc(key_size);
	if (key == NULL) {
		LOGE("failed allocating secure memory");
		aead_free(aead);
		return NULL;
	}
	if (!sodium_mlock(key, key_size)) {
		LOGE("failed locking secure memory");
		aead_free(aead);
		return NULL;
	}
	switch (m) {
	case method_chacha20poly1305_ietf: {
		*(enum noncegen_method *)&aead->noncegen_method =
			noncegen_counter;
		*aead->impl = (struct aead_impl){
			.key = key,
			.keygen = &crypto_aead_chacha20poly1305_ietf_keygen,
			.seal = &crypto_aead_chacha20poly1305_ietf_encrypt,
			.open = &crypto_aead_chacha20poly1305_ietf_decrypt,
		};
	} break;
	case method_xchacha20poly1305_ietf: {
		*(enum noncegen_method *)&aead->noncegen_method =
			noncegen_random;
		*aead->impl = (struct aead_impl){
			.key = key,
			.keygen = &crypto_aead_xchacha20poly1305_ietf_keygen,
			.seal = &crypto_aead_xchacha20poly1305_ietf_encrypt,
			.open = &crypto_aead_xchacha20poly1305_ietf_decrypt,
		};
	} break;
	case method_aes256gcm: {
		*(enum noncegen_method *)&aead->noncegen_method =
			noncegen_counter;
		*aead->impl = (struct aead_impl){
			.key = key,
			.keygen = &crypto_aead_aes256gcm_keygen,
			.seal = &crypto_aead_aes256gcm_encrypt,
			.open = &crypto_aead_aes256gcm_decrypt,
		};
	} break;
	default:
		abort();
	}
	return aead;
}

static void aead_free_key(struct aead_impl *impl, const size_t key_size)
{
	if (impl == NULL) {
		return;
	}
	if (impl->key != NULL) {
		(void)sodium_munlock(impl->key, key_size);
		sodium_free(impl->key);
		impl->key = NULL;
	}
}

void aead_password(struct aead *restrict aead, char *password)
{
	kdf(aead->key_size, aead->impl->key, password);
	memset(password, 0, strlen(password));
}

void aead_psk(struct aead *restrict aead, unsigned char *psk)
{
	memcpy(aead->impl->key, psk, aead->key_size);
	memset(psk, 0, aead->key_size);
}

void aead_keygen(struct aead *restrict aead, unsigned char *key)
{
	aead->impl->keygen(key);
}

void aead_free(struct aead *restrict aead)
{
	aead_free_key(aead->impl, aead->key_size);
	UTIL_SAFE_FREE(aead->impl);
	util_free(aead);
}

#endif
