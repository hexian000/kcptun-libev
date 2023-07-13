/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "nonce.h"

#if WITH_SODIUM
#include "utils/buffer.h"
#include "utils/check.h"
#include "crypto.h"

#include <sodium.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

static bool
ppbloom_check_add(struct ppbloom *restrict b, const void *buffer, size_t len)
{
	const uint8_t i = b->current & UINT8_C(1);
	const uint8_t j = i ^ UINT8_C(1);
	const bool ret = bloom_add(&b->bloom[i], buffer, (int)len) != 0 ||
			 bloom_check(&b->bloom[j], buffer, (int)len) != 0;
	b->bloom_count[i]++;
	if (b->bloom_count[i] >= b->entries) {
		bloom_reset(&b->bloom[j]);
		b->bloom_count[j] = 0;
		b->current = j;
	}
	return ret;
}

struct noncegen *noncegen_create(
	const enum noncegen_method method, const size_t nonce_len,
	const bool strict)
{
	struct noncegen *restrict g = malloc(sizeof(struct noncegen));
	if (g == NULL) {
		LOGOOM();
		return NULL;
	}

	const size_t entries = strict ? 1u << 20u : 1u << 14u;
	const double error = strict ? 0x1p-20 : 0x1p-30;
	g->method = method;
	g->ppbloom = (struct ppbloom){
		.bloom_count = { 0, 0 },
		.current = 0,
		.entries = entries,
	};
	BUF_INIT(g->buf, sizeof(g->buf.data));
	CHECKMSG(nonce_len <= g->buf.cap, "nonce too long");
	g->buf.len = nonce_len;
	if (bloom_init(&g->ppbloom.bloom[0], (int)entries, error)) {
		noncegen_free(g);
		return NULL;
	}
	if (bloom_init(&g->ppbloom.bloom[1], (int)entries, error)) {
		noncegen_free(g);
		return NULL;
	}
	noncegen_init(g);
	return g;
}

void noncegen_init(struct noncegen *restrict g)
{
	/* use random base of nonce counter to (probably) avoid nonce reuse from different peers */
	if (g->method == noncegen_counter) {
		randombytes_buf(g->buf.data, g->buf.len);
	}
}

static void noncegen_fill_counter(struct noncegen *restrict g)
{
	sodium_increment(g->buf.data, g->buf.len);
}

static void noncegen_fill_random(struct noncegen *restrict g)
{
	randombytes_buf(g->buf.data, g->buf.len);
}

const unsigned char *noncegen_next(struct noncegen *restrict g)
{
	switch (g->method) {
	case noncegen_random:
		noncegen_fill_random(g);
		break;
	case noncegen_counter:
		noncegen_fill_counter(g);
		break;
	}
	return g->buf.data;
}

bool noncegen_verify(struct noncegen *g, const unsigned char *nonce)
{
	return !ppbloom_check_add(&g->ppbloom, nonce, g->buf.len);
}

void noncegen_free(struct noncegen *g)
{
	if (g == NULL) {
		return;
	}
	bloom_free(&g->ppbloom.bloom[0]);
	bloom_free(&g->ppbloom.bloom[1]);
	free(g);
}

#endif /* WITH_SODIUM */
