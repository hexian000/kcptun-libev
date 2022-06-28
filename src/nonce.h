#ifndef NONCE_H
#define NONCE_H

#include "libbloom/bloom.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ppbloom {
	struct bloom bloom[2];
	size_t bloom_count[2];
	size_t entries;
	uint8_t current;
};

struct noncegen {
	struct ppbloom ppbloom;
	uint32_t src[4];
	unsigned char *nonce_buf;
	size_t nonce_len;
};

struct noncegen *noncegen_create(size_t nonce_len);
const unsigned char *noncegen_next(struct noncegen *g);
bool noncegen_verify(struct noncegen *g, const unsigned char *nonce);
void noncegen_free(struct noncegen *g);

#endif /* NONCE_H */
