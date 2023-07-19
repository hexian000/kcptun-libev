/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* crypto interface */
struct crypto_impl;

enum noncegen_method {
	noncegen_counter,
	noncegen_random,
};

struct crypto {
	const enum noncegen_method noncegen_method;
	const size_t nonce_size;
	const size_t overhead;
	const size_t key_size;
	struct crypto_impl *impl;
};

struct crypto *crypto_new(const char *method);
bool crypto_password(struct crypto *, char *password);
bool crypto_b64psk(struct crypto *, char *b64);
void crypto_free(struct crypto *);

uint32_t crypto_rand32(void);
bool crypto_keygen(struct crypto *, char *b64, size_t b64_len);

size_t crypto_seal(
	struct crypto *, unsigned char *dst, size_t dst_size,
	const unsigned char *nonce, const unsigned char *plain,
	size_t plain_size);
size_t crypto_open(
	struct crypto *, unsigned char *dst, size_t dst_size,
	const unsigned char *nonce, const unsigned char *cipher,
	size_t cipher_size);

void crypto_list_methods(void);

#endif /* CRYPTO_H */
