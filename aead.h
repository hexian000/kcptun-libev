#ifndef AEAD_H
#define AEAD_H

#include <stddef.h>

/* AEAD interface */
struct aead;

void crypto_random_read(char *buf, size_t buf_size);

struct aead *aead_create(char *password);
void aead_destroy(struct aead *);

size_t aead_nonce_size(struct aead *);
size_t aead_overhead(struct aead *);

size_t aead_seal(struct aead *, char *dst, size_t dst_size, const char *nonce,
		 const char *plain, size_t plain_size, const char *tag,
		 size_t tag_size);
size_t aead_open(struct aead *, char *dst, size_t dst_size, const char *nonce,
		 const char *cipher, size_t cipher_size, const char *tag,
		 size_t tag_size);

#endif /* AEAD_H */
