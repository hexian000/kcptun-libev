#include "aead.h"
#include "util.h"

#include <sodium.h>

#include <assert.h>

struct aead {
	char *key;
};

void crypto_random_read(char *buf, size_t buf_size)
{
	randombytes_buf(buf, buf_size);
}

const size_t key_size = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;

static inline int kdf(char *restrict key, const char *restrict password)
{
	char salt_str[] = "kcptun-libev";
	const size_t salt_size = crypto_pwhash_argon2id_SALTBYTES;
	unsigned char salt[salt_size];
	int r = crypto_generichash(salt, salt_size, (unsigned char *)salt_str,
				   strlen(salt_str), NULL, 0);
	if (r) {
		return r;
	}
	r = crypto_pwhash_argon2id((unsigned char *)key, key_size, password,
				   strlen(password), salt,
				   crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE,
				   crypto_pwhash_argon2id_MEMLIMIT_MIN,
				   crypto_pwhash_argon2id_ALG_ARGON2ID13);
	return r;
}

size_t aead_nonce_size(struct aead *restrict aead)
{
	UNUSED(aead);
	return crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
}

size_t aead_overhead(struct aead *restrict aead)
{
	UNUSED(aead);
	return crypto_aead_xchacha20poly1305_ietf_ABYTES;
}

size_t aead_seal(struct aead *aead, char *dst, size_t dst_size,
		 const char *nonce, const char *plain, size_t plain_size,
		 const char *tag, size_t tag_size)
{
	assert(dst_size >= plain_size + aead_overhead(aead));
	unsigned long long r_len = dst_size;
	int r = crypto_aead_xchacha20poly1305_ietf_encrypt(
		(unsigned char *)dst, &r_len, (const unsigned char *)plain,
		plain_size, (const unsigned char *)tag, tag_size, NULL,
		(const unsigned char *)nonce, (const unsigned char *)aead->key);
	if (r != 0) {
		LOGF_E("crypto_aead_xchacha20poly1305_ietf_encrypt: %d", r);
		return 0;
	}
	return r_len;
}

size_t aead_open(struct aead *aead, char *dst, size_t dst_size,
		 const char *nonce, const char *cipher, size_t cipher_size,
		 const char *tag, size_t tag_size)
{
	assert(dst_size + aead_overhead(aead) >= cipher_size);
	unsigned long long r_len = dst_size;
	int r = crypto_aead_xchacha20poly1305_ietf_decrypt(
		(unsigned char *)dst, &r_len, NULL,
		(const unsigned char *)cipher, cipher_size,
		(const unsigned char *)tag, tag_size,
		(const unsigned char *)nonce, (const unsigned char *)aead->key);
	if (r != 0) {
		LOGF_E("crypto_aead_xchacha20poly1305_ietf_decrypt: %d", r);
		return 0;
	}
	return r_len;
}

struct aead *aead_create(char *restrict password)
{
	if (password == NULL || strlen(password) == 0) {
		LOG_I("no encryption enabled");
		return NULL;
	}

	if (sodium_init() != 0) {
		LOG_E("sodium_init failed");
		return NULL;
	}
	struct aead *aead = util_malloc(sizeof(struct aead));
	if (aead == NULL) {
		return NULL;
	}
	char *key = sodium_malloc(key_size);
	if (key == NULL) {
		return NULL;
	}
	sodium_mlock(key, key_size);
	*aead = (struct aead){
		.key = key,
	};
	LOG_I("key derivation...");
	int r = kdf(key, password);
	if (r) {
		LOGF_WTF("key derivation failed: %d", r);
	}
	memset(password, 0, strlen(password));
	return aead;
}

void aead_destroy(struct aead *restrict aead)
{
	if (aead->key != NULL) {
		sodium_memzero(aead->key, key_size);
		sodium_munlock(aead->key, key_size);
		sodium_free(aead->key);
		aead->key = NULL;
	}
	util_free(aead);
}
