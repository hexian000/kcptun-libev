#include "nonce.h"
#include "aead.h"
#include "serialize.h"
#include "util.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#if WITH_CRYPTO

static bool
ppbloom_check_add(struct ppbloom *restrict b, const void *buffer, size_t len)
{
	const uint8_t i = b->current & UINT8_C(1);
	const uint8_t j = i ^ UINT8_C(1);
	const bool ret = bloom_add(&b->bloom[i], buffer, len) != 0 ||
			 bloom_check(&b->bloom[j], buffer, len) != 0;
	b->bloom_count[i]++;
	if (b->bloom_count[i] >= b->entries) {
		bloom_reset(&b->bloom[j]);
		b->bloom_count[j] = 0;
		b->current = j;
	}
	return ret;
}

struct noncegen *noncegen_create(size_t nonce_len)
{
	struct noncegen *restrict g = util_malloc(sizeof(struct noncegen));
	if (g == NULL) {
		return NULL;
	}

	const size_t entries = (size_t)1 << 20u;
	const double error = 0x1p-20;
	*g = (struct noncegen){
		.ppbloom =
			(struct ppbloom){
				.bloom_count = { 0, 0 },
				.current = 0,
				.entries = entries,
			},
		.nonce_buf = util_malloc(nonce_len),
		.nonce_len = nonce_len,
	};
	if (g->nonce_buf == NULL) {
		noncegen_free(g);
		return NULL;
	}
	if (bloom_init(&g->ppbloom.bloom[0], entries, error)) {
		noncegen_free(g);
		return NULL;
	}
	if (bloom_init(&g->ppbloom.bloom[1], entries, error)) {
		noncegen_free(g);
		return NULL;
	}
	noncegen_init(g);
	return g;
}

void noncegen_init(struct noncegen *g)
{
	/* use random base of nonce counter to (probably) avoid nonce reuse from different peers */
	for (size_t i = 0; i < countof(g->src); i++) {
		g->src[i] = rand32();
	}
}

const unsigned char *noncegen_next(struct noncegen *restrict g)
{
	for (size_t i = 0; i < countof(g->src); i++) {
		if (g->src[i] != UINT32_MAX) {
			g->src[i]++;
			break;
		}
		g->src[i] = 0;
	}
	size_t n = g->nonce_len / sizeof(uint32_t);
	if (n > countof(g->src)) {
		n = countof(g->src);
	}
	for (size_t i = 0; i < n; i++) {
		write_uint32(g->nonce_buf + i * sizeof(uint32_t), g->src[i]);
	}
	for (size_t i = n * sizeof(uint32_t); i < g->nonce_len; i++) {
		g->nonce_buf[i] = (unsigned char)rand32();
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
	util_free(g);
}

#endif /* WITH_CRYPTO */
