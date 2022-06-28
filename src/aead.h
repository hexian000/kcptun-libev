#ifndef AEAD_H
#define AEAD_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

size_t crypto_nonce_size();
size_t crypto_overhead();
size_t crypto_key_size();
void crypto_gen_key(unsigned char *key);

/* AEAD interface */
struct aead;

void aead_keygen(unsigned char *k);

void aead_init();

struct aead *aead_create_pw(char *password);
struct aead *aead_create(unsigned char *psk);
void aead_destroy(struct aead *);

size_t aead_seal(
	struct aead *, unsigned char *dst, size_t dst_size,
	const unsigned char *nonce, const unsigned char *plain,
	size_t plain_size, const unsigned char *tag, size_t tag_size);
size_t aead_open(
	struct aead *, unsigned char *dst, size_t dst_size,
	const unsigned char *nonce, const unsigned char *cipher,
	size_t cipher_size, const unsigned char *tag, size_t tag_size);

#endif /* AEAD_H */
