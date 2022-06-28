#include "nonce.h"
#include "aead.h"
#include "serialize.h"
#include "util.h"

#include <stdint.h>
#include <stdlib.h>

#if WITH_CRYPTO

#include "murmur3/murmurhash3.h"

static bool
ppbloom_check_add(struct ppbloom *restrict b, const void *buffer, size_t len)
{
	uint8_t current = b->current;
	bool ret = !!bloom_add(&b->bloom[current], buffer, len);
	if (!ret) {
		ret |= !!bloom_check(
			&b->bloom[current ^ UINT8_C(1)], buffer, len);
	}
	b->bloom_count[current]++;
	if (b->bloom_count[current] >= b->entries) {
		b->current = current ^= UINT8_C(1);
		bloom_reset(&b->bloom[current]);
		b->bloom_count[current] = 0;
	}
	return ret;
}

struct noncegen *noncegen_create(size_t nonce_len)
{
	struct noncegen *restrict g = util_malloc(sizeof(struct noncegen));
	if (g == NULL) {
		return NULL;
	}

	const size_t entries = 1e6;
	const double error = 1e-15;
	const size_t n = entries / 2;
	*g = (struct noncegen){
		.ppbloom =
			(struct ppbloom){
				.bloom_count = { 0, 0 },
				.current = 0,
				.entries = n,
			},
		.nonce_buf = util_malloc(nonce_len),
		.nonce_len = nonce_len,
	};
	if (g->nonce_buf == NULL) {
		noncegen_free(g);
		return NULL;
	}
	if (bloom_init(&g->ppbloom.bloom[0], n, error)) {
		noncegen_free(g);
		return NULL;
	}
	if (bloom_init(&g->ppbloom.bloom[1], n, error)) {
		noncegen_free(g);
		return NULL;
	}
	for (size_t i = 0; i < sizeof(g->src) / sizeof(g->src[0]); i++) {
		g->src[i] = rand32();
	}
	return g;
}

const unsigned char *noncegen_next(struct noncegen *g)
{
	for (size_t i = 0; i < sizeof(g->src) / sizeof(g->src[0]); i++) {
		const uint32_t v = g->src[i];
		if ((g->src[i] = v + 1) != UINT32_C(0)) {
			break;
		}
	}
	const uint32_t n = g->nonce_len / sizeof(uint32_t);
	for (uint32_t i = 0; i < n; i++) {
		const uint32_t h =
			murmurhash3((void *)g->src, sizeof(g->src), i);
		write_uint32(g->nonce_buf + (i * sizeof(uint32_t)), h);
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
