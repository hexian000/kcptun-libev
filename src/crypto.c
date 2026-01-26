/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "crypto.h"

#include "nonce.h"
#include "util.h"

#include "utils/arraysize.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if WITH_SODIUM

#include <sodium.h>

static const char crypto_tag[] = "kcptun-libev";
#define CRYPTO_TAG_SIZE (sizeof crypto_tag)

void crypto_init(void)
{
	const int ret = sodium_init();
	if (ret != 0) {
		FAILMSGF("sodium_init failed: %d", ret);
	}
	LOGD_F("libsodium: %s", sodium_version_string());
}

uint32_t crypto_rand32(void)
{
	return randombytes_random();
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
	if (r != 0) {
		return r;
	}
	r = crypto_pwhash_argon2id(
		key, key_size, password, strlen(password), salt,
		crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE,
		crypto_pwhash_argon2id_MEMLIMIT_MIN,
		crypto_pwhash_argon2id_ALG_ARGON2ID13);
	return r;
}

struct crypto_impl {
	void (*keygen)(unsigned char *k);

	int (*seal)(
		unsigned char *c, unsigned char *mac, const unsigned char *m,
		unsigned long long mlen, const unsigned char *n,
		const unsigned char *k);

	int (*open)(
		unsigned char *m, const unsigned char *c,
		const unsigned char *mac, unsigned long long clen,
		const unsigned char *n, const unsigned char *k);

	int (*aead_seal)(
		unsigned char *c, unsigned long long *clen_p,
		const unsigned char *m, unsigned long long mlen,
		const unsigned char *ad, unsigned long long adlen,
		const unsigned char *nsec, const unsigned char *npub,
		const unsigned char *k);

	int (*aead_open)(
		unsigned char *m, unsigned long long *mlen_p,
		unsigned char *nsec, const unsigned char *c,
		unsigned long long clen, const unsigned char *ad,
		unsigned long long adlen, const unsigned char *npub,
		const unsigned char *k);

	unsigned char *key;
};

size_t crypto_seal(
	const struct crypto *restrict crypto, unsigned char *dst,
	const size_t dst_size, const unsigned char *nonce,
	const unsigned char *plain, const size_t plain_size)
{
	if (dst_size < plain_size + crypto->overhead) {
		LOGW_F("crypto_seal: insufficient crypto buffer %zu < %zu",
		       dst_size, plain_size + crypto->overhead);
		return 0;
	}
	const struct crypto_impl *restrict impl = crypto->impl;
	if (impl->seal != NULL) {
		unsigned char *mac = dst + plain_size;
		const int r = impl->seal(
			dst, mac, plain, plain_size, nonce, impl->key);
		if (r != 0) {
			LOGE_F("crypto_seal: error %d", r);
			return 0;
		}
		return plain_size + crypto->overhead;
	}
	unsigned long long r_len = dst_size;
	const int r = impl->aead_seal(
		dst, &r_len, plain, plain_size,
		(const unsigned char *)crypto_tag, CRYPTO_TAG_SIZE, NULL, nonce,
		impl->key);
	if (r != 0) {
		LOGE_F("crypto_seal: aead error %d", r);
		return 0;
	}
	return r_len;
}

size_t crypto_open(
	const struct crypto *restrict crypto, unsigned char *dst,
	const size_t dst_size, const unsigned char *nonce,
	const unsigned char *cipher, const size_t cipher_size)
{
	if (dst_size + crypto->overhead < cipher_size) {
		LOGW("crypto_seal: insufficient crypto buffer");
		return 0;
	}
	const struct crypto_impl *restrict impl = crypto->impl;
	if (impl->open != NULL) {
		if (cipher_size < crypto->overhead) {
			LOGV_F("crypto_open: short cipher %zu, overhead %zu",
			       cipher_size, crypto->overhead);
			return 0;
		}
		const size_t plain_size = cipher_size - crypto->overhead;
		const unsigned char *mac = cipher + plain_size;
		const int r = impl->open(
			dst, cipher, mac, plain_size, nonce, impl->key);
		if (r != 0) {
			LOG_BIN_F(
				VERYVERBOSE, cipher, cipher_size, 0,
				"crypto_open: error %d", r);
			return 0;
		}
		return plain_size;
	}
	unsigned long long r_len = dst_size;
	const int r = impl->aead_open(
		dst, &r_len, NULL, cipher, cipher_size,
		(const unsigned char *)crypto_tag, CRYPTO_TAG_SIZE, nonce,
		impl->key);
	if (r != 0) {
		LOG_BIN_F(
			VERYVERBOSE, cipher, cipher_size, 0,
			"crypto_open: aead error %d", r);
		return 0;
	}
	return r_len;
}

enum crypto_methods {
	method_xchacha20poly1305_ietf,
	method_xsalsa20poly1305,
	method_chacha20poly1305_ietf,
	method_aes256gcm,
};

static const char *method_names[] = {
	[method_xchacha20poly1305_ietf] = "xchacha20poly1305_ietf",
	[method_xsalsa20poly1305] = "xsalsa20poly1305",
	[method_chacha20poly1305_ietf] = "chacha20poly1305_ietf",
	[method_aes256gcm] = "aes256gcm",
};

void crypto_list_methods(void)
{
	(void)fprintf(stderr, "  supported methods:\n");
	for (size_t i = 0; i < ARRAY_SIZE(method_names); i++) {
		(void)fprintf(stderr, "  - %s\n", method_names[i]);
	}
	(void)fflush(stderr);
}

struct crypto *crypto_new(const char *method)
{
	enum crypto_methods m;
	size_t nonce_size, overhead, key_size;
	if (strcmp(method, method_names[method_xchacha20poly1305_ietf]) == 0) {
		m = method_xchacha20poly1305_ietf;
		nonce_size = crypto_aead_xchacha20poly1305_ietf_npubbytes();
		overhead = crypto_aead_xchacha20poly1305_ietf_abytes();
		key_size = crypto_aead_xchacha20poly1305_ietf_keybytes();
	} else if (strcmp(method, method_names[method_xsalsa20poly1305]) == 0) {
		m = method_xsalsa20poly1305;
		nonce_size = crypto_secretbox_xsalsa20poly1305_noncebytes();
		overhead = crypto_secretbox_xsalsa20poly1305_macbytes();
		key_size = crypto_secretbox_xsalsa20poly1305_keybytes();
	} else if (strcmp(method, method_names[method_chacha20poly1305_ietf]) == 0) {
		m = method_chacha20poly1305_ietf;
		nonce_size = crypto_aead_chacha20poly1305_ietf_npubbytes();
		overhead = crypto_aead_chacha20poly1305_ietf_abytes();
		key_size = crypto_aead_chacha20poly1305_ietf_keybytes();
	} else if (strcmp(method, method_names[method_aes256gcm]) == 0) {
		m = method_aes256gcm;
		if (!crypto_aead_aes256gcm_is_available()) {
			LOGE_F("%s is not supported by current hardware",
			       method_names[m]);
			return NULL;
		}
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
		LOGOOM();
		return NULL;
	}
	*(size_t *)&crypto->nonce_size = nonce_size;
	*(size_t *)&crypto->overhead = overhead;
	*(size_t *)&crypto->key_size = key_size;
	crypto->impl = malloc(sizeof(struct crypto_impl));
	if (crypto->impl == NULL) {
		LOGOOM();
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
			.aead_seal =
				&crypto_aead_xchacha20poly1305_ietf_encrypt,
			.aead_open =
				&crypto_aead_xchacha20poly1305_ietf_decrypt,
		};
	} break;
	case method_xsalsa20poly1305: {
		*(enum noncegen_method *)&crypto->noncegen_method =
			noncegen_random;
		*crypto->impl = (struct crypto_impl){
			.key = key,
			.keygen = &crypto_stream_xsalsa20_keygen,
			.seal = &crypto_secretbox_detached,
			.open = &crypto_secretbox_open_detached,
		};
	} break;
	case method_chacha20poly1305_ietf: {
		*(enum noncegen_method *)&crypto->noncegen_method =
			noncegen_counter;
		*crypto->impl = (struct crypto_impl){
			.key = key,
			.keygen = &crypto_aead_chacha20poly1305_ietf_keygen,
			.aead_seal = &crypto_aead_chacha20poly1305_ietf_encrypt,
			.aead_open = &crypto_aead_chacha20poly1305_ietf_decrypt,
		};
	} break;
	case method_aes256gcm: {
		*(enum noncegen_method *)&crypto->noncegen_method =
			noncegen_counter;
		*crypto->impl = (struct crypto_impl){
			.key = key,
			.keygen = &crypto_aead_aes256gcm_keygen,
			.aead_seal = &crypto_aead_aes256gcm_encrypt,
			.aead_open = &crypto_aead_aes256gcm_decrypt,
		};
	} break;
	default:
		FAILMSGF("invalid crypto method: %d", method);
	}
	return crypto;
}

bool crypto_password(struct crypto *restrict crypto, char *password)
{
	if (kdf(crypto->key_size, crypto->impl->key, password) != 0) {
		LOGOOM();
		return false;
	}
	sodium_memzero(password, strlen(password));
	return true;
}

bool crypto_b64psk(struct crypto *restrict crypto, char *psk)
{
	const char *b64_end = NULL;
	const size_t b64_len = strlen(psk);
	size_t len;
	const int ret = sodium_base642bin(
		crypto->impl->key, crypto->key_size, psk, b64_len, NULL, &len,
		&b64_end, sodium_base64_VARIANT_ORIGINAL);
	if (ret != 0) {
		LOGE_F("base64 decode failed: %d", ret);
		return false;
	}
	if ((ptrdiff_t)b64_len != (b64_end - psk) || len != crypto->key_size) {
		LOGE("psk length error");
		return false;
	}
	sodium_memzero(psk, b64_len);
	return true;
}

bool crypto_keygen(
	const struct crypto *restrict crypto, char *b64, const size_t b64_len)
{
	unsigned char *key = crypto->impl->key;
	const size_t key_size = crypto->key_size;
	if (b64_len < sodium_base64_encoded_len(
			      key_size, sodium_base64_VARIANT_ORIGINAL)) {
		return false;
	}
	crypto->impl->keygen(key);
	(void)sodium_bin2base64(
		b64, b64_len, key, key_size, sodium_base64_VARIANT_ORIGINAL);
	return true;
}

static void crypto_impl_free(struct crypto *restrict crypto)
{
	struct crypto_impl *restrict impl = crypto->impl;
	if (impl == NULL) {
		return;
	}
	if (impl->key != NULL) {
		(void)sodium_munlock(impl->key, crypto->key_size);
		sodium_free(impl->key);
		impl->key = NULL;
	}
	UTIL_SAFE_FREE(crypto->impl);
}

void crypto_free(struct crypto *restrict crypto)
{
	if (crypto == NULL) {
		return;
	}
	crypto_impl_free(crypto);
	free(crypto);
}

#endif
