/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "crypto.h"

#include "nonce.h"
#include "util.h"

#include "meta/arraysize.h"
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

void crypto_init(void)
{
	const int ret = sodium_init();
	if (ret < 0) {
		FAILMSGF("sodium_init failed: %d", ret);
	}
	LOGD_F("libsodium: %s", sodium_version_string());
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

struct crypto_method {
	const char *name;
	enum noncegen_method noncegen_method;
	size_t (*nonce_size)(void);
	size_t (*overhead)(void);
	size_t (*key_size)(void);
	int (*is_available)(void); /* NULL if always available */
	struct crypto_impl impl; /* .key is NULL; filled in by crypto_new */
};

static const struct crypto_method methods[] = {
	{
		.name = "xchacha20poly1305_ietf",
		.noncegen_method = noncegen_random,
		.nonce_size = &crypto_aead_xchacha20poly1305_ietf_npubbytes,
		.overhead = &crypto_aead_xchacha20poly1305_ietf_abytes,
		.key_size = &crypto_aead_xchacha20poly1305_ietf_keybytes,
		.impl = {
			.keygen = &crypto_aead_xchacha20poly1305_ietf_keygen,
			.aead_seal =
				&crypto_aead_xchacha20poly1305_ietf_encrypt,
			.aead_open =
				&crypto_aead_xchacha20poly1305_ietf_decrypt,
		},
	},
	{
		.name = "xsalsa20poly1305",
		.noncegen_method = noncegen_random,
		.nonce_size = &crypto_secretbox_xsalsa20poly1305_noncebytes,
		.overhead = &crypto_secretbox_xsalsa20poly1305_macbytes,
		.key_size = &crypto_secretbox_xsalsa20poly1305_keybytes,
		.impl = {
			.keygen = &crypto_secretbox_xsalsa20poly1305_keygen,
			.seal = &crypto_secretbox_detached,
			.open = &crypto_secretbox_open_detached,
		},
	},
	{
		.name = "chacha20poly1305_ietf",
		.noncegen_method = noncegen_counter,
		.nonce_size = &crypto_aead_chacha20poly1305_ietf_npubbytes,
		.overhead = &crypto_aead_chacha20poly1305_ietf_abytes,
		.key_size = &crypto_aead_chacha20poly1305_ietf_keybytes,
		.impl = {
			.keygen = &crypto_aead_chacha20poly1305_ietf_keygen,
			.aead_seal = &crypto_aead_chacha20poly1305_ietf_encrypt,
			.aead_open = &crypto_aead_chacha20poly1305_ietf_decrypt,
		},
	},
	{
		.name = "aes256gcm",
		.noncegen_method = noncegen_counter,
		.nonce_size = &crypto_aead_aes256gcm_npubbytes,
		.overhead = &crypto_aead_aes256gcm_abytes,
		.key_size = &crypto_aead_aes256gcm_keybytes,
		.is_available = &crypto_aead_aes256gcm_is_available,
		.impl = {
			.keygen = &crypto_aead_aes256gcm_keygen,
			.aead_seal = &crypto_aead_aes256gcm_encrypt,
			.aead_open = &crypto_aead_aes256gcm_decrypt,
		},
	},
};

struct crypto *crypto_new(const char *method)
{
	const struct crypto_method *m = NULL;
	for (size_t i = 0; i < ARRAY_SIZE(methods); i++) {
		if (strcmp(method, methods[i].name) == 0) {
			m = &methods[i];
			break;
		}
	}
	if (m == NULL) {
		LOGE_F("unsupported crypto method: %s", method);
		crypto_list_methods();
		return NULL;
	}
	if (m->is_available != NULL && !m->is_available()) {
		LOGE_F("%s is not supported by current hardware", m->name);
		return NULL;
	}
	const size_t nonce_size = m->nonce_size();
	const size_t overhead = m->overhead();
	const size_t key_size = m->key_size();
	struct crypto *crypto = malloc(sizeof(struct crypto));
	if (crypto == NULL) {
		LOGOOM();
		return NULL;
	}
	const struct crypto init = {
		.noncegen_method = m->noncegen_method,
		.nonce_size = nonce_size,
		.overhead = overhead,
		.key_size = key_size,
		.impl = NULL,
	};
	memcpy(crypto, &init, sizeof(init));
	crypto->impl = malloc(sizeof(struct crypto_impl));
	if (crypto->impl == NULL) {
		LOGOOM();
		crypto_free(crypto);
		return NULL;
	}
	*crypto->impl = (struct crypto_impl){ 0 };
	unsigned char *key = sodium_malloc(key_size);
	if (key == NULL) {
		LOGE("crypto: failed to allocate secure memory");
		crypto_free(crypto);
		return NULL;
	}
	if (sodium_mlock(key, key_size)) {
		LOGW("crypto: failed to lock secure memory");
	}
	*crypto->impl = m->impl;
	crypto->impl->key = key;
	return crypto;
}

static int
kdf(const size_t key_size, unsigned char *restrict key,
    const char *restrict password)
{
	static const char salt_str[] = "kcptun-libev";
	unsigned char salt[crypto_pwhash_argon2id_SALTBYTES];
	int r = crypto_generichash(
		salt, crypto_pwhash_argon2id_SALTBYTES,
		(const unsigned char *)salt_str, sizeof(salt_str) - 1, NULL, 0);
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

bool crypto_password(struct crypto *restrict crypto, char *password)
{
	const int ret = kdf(crypto->key_size, crypto->impl->key, password);
	sodium_memzero(password, strlen(password));
	if (ret != 0) {
		LOGOOM();
		return false;
	}
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
		LOGE_F("crypto: psk base64 decode failed: %d", ret);
		sodium_memzero(psk, b64_len);
		return false;
	}
	if ((ptrdiff_t)b64_len != (b64_end - psk) || len != crypto->key_size) {
		LOGE("crypto: invalid psk length");
		sodium_memzero(psk, b64_len);
		return false;
	}
	sodium_memzero(psk, b64_len);
	return true;
}

static void free_impl(struct crypto *restrict crypto)
{
	struct crypto_impl *restrict impl = crypto->impl;
	if (impl == NULL) {
		return;
	}
	if (impl->key != NULL) {
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
	free_impl(crypto);
	free(crypto);
}

uint32_t crypto_rand32(void)
{
	return randombytes_random();
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

static const char crypto_tag[] = "kcptun-libev";
#define CRYPTO_TAG_SIZE (sizeof crypto_tag)

size_t crypto_seal(
	const struct crypto *restrict crypto, unsigned char *dst,
	const size_t dst_size, const unsigned char *restrict nonce,
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
	/* r_len is purely an output parameter; the size check above already
	 * bounds the write */
	unsigned long long r_len = 0;
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
	const size_t dst_size, const unsigned char *restrict nonce,
	const unsigned char *cipher, const size_t cipher_size)
{
	if (dst_size + crypto->overhead < cipher_size) {
		LOGW_F("crypto_open: insufficient crypto buffer %zu + %zu < %zu",
		       dst_size, crypto->overhead, cipher_size);
		return 0;
	}
	if (cipher_size <= crypto->overhead) {
		LOGV_F("crypto_open: short cipher %zu, overhead %zu",
		       cipher_size, crypto->overhead);
		return 0;
	}
	const struct crypto_impl *restrict impl = crypto->impl;
	if (impl->open != NULL) {
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
	/* r_len is purely an output parameter; the size checks above already
	 * bound the write */
	unsigned long long r_len = 0;
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

bool crypto_pad(unsigned char *data, const size_t len, const size_t npad)
{
	if (npad > UINT8_MAX) {
		return false;
	}
	const unsigned char v = (unsigned char)npad;
	for (size_t i = 0; i < npad; i++) {
		data[len + i] = v;
	}
	return true;
}

void crypto_list_methods(void)
{
	(void)fprintf(stderr, "  supported methods:\n");
	for (size_t i = 0; i < ARRAY_SIZE(methods); i++) {
		(void)fprintf(stderr, "  - %s\n", methods[i].name);
	}
	(void)fflush(stderr);
}

#endif /* WITH_SODIUM */
