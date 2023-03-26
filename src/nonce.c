/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "nonce.h"

#if WITH_SODIUM
#include "utils/arraysize.h"
#include "utils/serialize.h"
#include "algo/xorshift.h"
#include "aead.h"
#include "util.h"

#include <stddef.h>
#include <stdint.h>

#include <sodium.h>

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
	const bool server)
{
	struct noncegen *restrict g = malloc(sizeof(struct noncegen));
	if (g == NULL) {
		return NULL;
	}

	const size_t entries = server ? 1u << 20u : 1u << 14u;
	const double error = server ? 0x1p-20 : 0x1p-30;
	*g = (struct noncegen){
		.method = method,
		.ppbloom =
			(struct ppbloom){
				.bloom_count = { 0, 0 },
				.current = 0,
				.entries = entries,
			},
		.nonce_buf = malloc(nonce_len),
		.nonce_len = nonce_len,
	};
	if (g->nonce_buf == NULL) {
		noncegen_free(g);
		return NULL;
	}
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
		randombytes_buf(g->src, sizeof(g->src));
	}
}

static void noncegen_fill_counter(struct noncegen *restrict g)
{
	for (size_t i = 0; i < ARRAY_SIZE(g->src); i++) {
		if (g->src[i] != UINT32_MAX) {
			g->src[i]++;
			break;
		}
		g->src[i] = 0;
	}
	size_t n = g->nonce_len / sizeof(uint32_t);
	if (n > ARRAY_SIZE(g->src)) {
		n = ARRAY_SIZE(g->src);
	}
	for (size_t i = 0; i < n; i++) {
		write_uint32(g->nonce_buf + i * sizeof(uint32_t), g->src[i]);
	}
	for (size_t i = n * sizeof(uint32_t); i < g->nonce_len; i++) {
		g->nonce_buf[i] = (unsigned char)rand32();
	}
}

/* higher packet entropy */
static void noncegen_fill_random(struct noncegen *restrict g)
{
	randombytes_buf(g->nonce_buf, g->nonce_len);
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
	return g->nonce_buf;
}

bool noncegen_verify(struct noncegen *g, const unsigned char *nonce)
{
	return !ppbloom_check_add(&g->ppbloom, nonce, g->nonce_len);
}

void noncegen_free(struct noncegen *g)
{
	if (g == NULL) {
		return;
	}
	bloom_free(&g->ppbloom.bloom[0]);
	bloom_free(&g->ppbloom.bloom[1]);
	UTIL_SAFE_FREE(g->nonce_buf);
	free(g);
}

#endif /* WITH_SODIUM */
