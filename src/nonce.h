/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef NONCE_H
#define NONCE_H

#include "utils/buffer.h"

#include "bloom.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NONCE_MAX_LENGTH (32)

struct ppbloom {
	struct bloom bloom[2];
	size_t bloom_count[2];
	size_t entries;
	uint8_t current;
};

enum noncegen_method {
	noncegen_counter,
	noncegen_random,
};

struct noncegen {
	enum noncegen_method method;
	const unsigned char *(*next_fn)(struct noncegen *g);
	struct ppbloom ppbloom;
	struct {
		BUFFER_HDR;
		unsigned char data[NONCE_MAX_LENGTH];
	} buf;
};

struct noncegen *
noncegen_new(enum noncegen_method method, size_t nonce_len, bool strict);
void noncegen_init(struct noncegen *g);
void noncegen_free(struct noncegen *g);

const unsigned char *noncegen_next(struct noncegen *g);
bool noncegen_verify(struct noncegen *g, const unsigned char *nonce);

#endif /* NONCE_H */
