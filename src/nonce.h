/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef NONCE_H
#define NONCE_H

#include "crypto.h"
#include "utils/buffer.h"
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
	enum noncegen_method method;
	struct ppbloom ppbloom;
	struct {
		BUFFER_HDR;
		unsigned char data[32];
	} buf;
};

struct noncegen *
noncegen_create(enum noncegen_method method, size_t nonce_len, bool strict);
void noncegen_init(struct noncegen *g);
const unsigned char *noncegen_next(struct noncegen *g);
bool noncegen_verify(struct noncegen *g, const unsigned char *nonce);
void noncegen_free(struct noncegen *g);

#endif /* NONCE_H */
