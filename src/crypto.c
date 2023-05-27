/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "crypto.h"
#include "utils/slog.h"
#include "utils/check.h"
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
	static const char salt_str[] = "kcptun-libev";
	unsigned char salt[crypto_pwhash_argon2id_SALTBYTES];
	int r = crypto_generichash(
		salt, crypto_pwhash_argon2id_SALTBYTES,
		(unsigned char *)salt_str, sizeof(salt_str) - 1, NULL, 0);
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

struct crypto_impl {
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

size_t crypto_seal(
	struct crypto *restrict crypto, unsigned char *dst, size_t dst_size,
	const unsigned char *nonce, const unsigned char *plain,
	size_t plain_size, const unsigned char *tag, size_t tag_size)
{
	assert(dst_size >= plain_size + crypto->overhead);
	struct crypto_impl *restrict impl = crypto->impl;
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

size_t crypto_open(
	struct crypto *restrict crypto, unsigned char *dst, size_t dst_size,
	const unsigned char *nonce, const unsigned char *cipher,
	size_t cipher_size, const unsigned char *tag, size_t tag_size)
{
	assert(dst_size + crypto->overhead >= cipher_size);
	struct crypto_impl *restrict impl = crypto->impl;
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

enum crypto_method {
	method_xchacha20poly1305_ietf,
	method_chacha20poly1305_ietf,
	method_aes256gcm,
	method_MAX,
};

static inline char *strmethod(const enum crypto_method m)
{
	switch (m) {
	case method_xchacha20poly1305_ietf:
		return "xchacha20poly1305_ietf";
	case method_chacha20poly1305_ietf:
		return "chacha20poly1305_ietf";
	case method_aes256gcm:
		return "aes256gcm";
	default:
		break;
	}
	return NULL;
}

void crypto_list_methods(void)
{
	fprintf(stderr, "supported methods:\n");
	for (int i = 0; i < method_MAX; i++) {
		fprintf(stderr, "  %s\n", strmethod(i));
	}
}

struct crypto *crypto_new(const char *method)
{
	if (!aead_init()) {
		return NULL;
	}
	enum crypto_method m;
	size_t nonce_size, overhead, key_size;
	if (strcmp(method, strmethod(method_xchacha20poly1305_ietf)) == 0) {
		m = method_xchacha20poly1305_ietf;
		nonce_size = crypto_aead_xchacha20poly1305_ietf_npubbytes();
		overhead = crypto_aead_xchacha20poly1305_ietf_abytes();
		key_size = crypto_aead_xchacha20poly1305_ietf_keybytes();
	} else if (strcmp(method, strmethod(method_chacha20poly1305_ietf)) == 0) {
		m = method_chacha20poly1305_ietf;
		nonce_size = crypto_aead_chacha20poly1305_ietf_npubbytes();
		overhead = crypto_aead_chacha20poly1305_ietf_abytes();
		key_size = crypto_aead_chacha20poly1305_ietf_keybytes();
	} else if (strcmp(method, strmethod(method_aes256gcm)) == 0) {
		m = method_aes256gcm;
		nonce_size = crypto_aead_aes256gcm_npubbytes();
		overhead = crypto_aead_aes256gcm_abytes();
		key_size = crypto_aead_aes256gcm_keybytes();
	} else {
		LOGW_F("unsupported crypto method: %s", method);
		crypto_list_methods();
		return NULL;
	}
	struct crypto *crypto = malloc(sizeof(struct crypto));
	if (crypto == NULL) {
		return NULL;
	}
	*(size_t *)&crypto->nonce_size = nonce_size;
	*(size_t *)&crypto->overhead = overhead;
	*(size_t *)&crypto->key_size = key_size;
	crypto->impl = malloc(sizeof(struct crypto_impl));
	if (crypto->impl == NULL) {
		crypto_free(crypto);
		return NULL;
	}
	unsigned char *key = sodium_malloc(key_size);
	if (key == NULL) {
		LOGE("failed allocating secure memory");
		crypto_free(crypto);
		return NULL;
	}
	if (sodium_mlock(key, key_size)) {
		LOGW("failed locking secure memory");
	}
	switch (m) {
	case method_xchacha20poly1305_ietf: {
		*(enum noncegen_method *)&crypto->noncegen_method =
			noncegen_random;
		*crypto->impl = (struct crypto_impl){
			.key = key,
			.keygen = &crypto_aead_xchacha20poly1305_ietf_keygen,
			.seal = &crypto_aead_xchacha20poly1305_ietf_encrypt,
			.open = &crypto_aead_xchacha20poly1305_ietf_decrypt,
		};
	} break;
	case method_chacha20poly1305_ietf: {
		*(enum noncegen_method *)&crypto->noncegen_method =
			noncegen_counter;
		*crypto->impl = (struct crypto_impl){
			.key = key,
			.keygen = &crypto_aead_chacha20poly1305_ietf_keygen,
			.seal = &crypto_aead_chacha20poly1305_ietf_encrypt,
			.open = &crypto_aead_chacha20poly1305_ietf_decrypt,
		};
	} break;
	case method_aes256gcm: {
		*(enum noncegen_method *)&crypto->noncegen_method =
			noncegen_counter;
		*crypto->impl = (struct crypto_impl){
			.key = key,
			.keygen = &crypto_aead_aes256gcm_keygen,
			.seal = &crypto_aead_aes256gcm_encrypt,
			.open = &crypto_aead_aes256gcm_decrypt,
		};
	} break;
	default:
		FAIL();
	}
	return crypto;
}

static void aead_free_key(struct crypto_impl *impl, const size_t key_size)
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

void crypto_password(struct crypto *restrict crypto, char *password)
{
	kdf(crypto->key_size, crypto->impl->key, password);
	memset(password, 0, strlen(password));
}

void crypto_psk(struct crypto *restrict crypto, unsigned char *psk)
{
	memcpy(crypto->impl->key, psk, crypto->key_size);
	memset(psk, 0, crypto->key_size);
}

void crypto_keygen(struct crypto *restrict crypto, unsigned char *key)
{
	crypto->impl->keygen(key);
}

void crypto_free(struct crypto *restrict crypto)
{
	aead_free_key(crypto->impl, crypto->key_size);
	UTIL_SAFE_FREE(crypto->impl);
	free(crypto);
}

#endif
