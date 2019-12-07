#include "event_impl.h"

const char tag_client[] = "kcptun-libev-client";
const size_t tag_client_size = sizeof(tag_client);
const char tag_server[] = "kcptun-libev-server";
const size_t tag_server_size = sizeof(tag_server);

void udp_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct server *s = (struct server *)watcher->data;

	struct queue *q = s->udp.udp_output;
	size_t n;
	struct sockaddr to;
	char *buf = queue_pop_nocopy(q, &n, &to);
	if (buf == NULL) {
		ev_io_stop(loop, watcher);
		return;
	}

	const int fd = s->udp.fd;
	ssize_t r = sendto(fd, buf, n, 0, &to, sizeof(to));
	switch (r) {
	case -1: {
		LOG_PERROR("udp sendto");
		return;
	}
	default:
		assert(r >= 0);
	}
	if ((size_t)r < n) {
		LOG_W("udp_output short send");
	}
#if UDP_PER_PACKET_LOG
	{
		char addr_str[64];
		format_sa(&to, addr_str, sizeof(addr_str));
		LOGF_V("udp sendto: %s %zd bytes", addr_str, r);
	}
#endif
	assert((size_t)r == n);
	s->udp.last_sent = ev_now(loop);
	s->stats.udp_out += n;
}

int udp_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
	UNUSED(kcp);
	struct session *restrict session = (struct session *)user;
	size_t n = udp_send(session->server, session->udp_remote, buf, len);
	session->stats.udp_out += n;
	return n > 0 ? (int)n : -1;
}

static inline const char *get_crypto_tag(struct server *restrict s,
					 size_t *tag_size, bool is_seal)
{
	const bool use_client_tag = is_server(s) ^ is_seal;
	if (use_client_tag) {
		*tag_size = tag_client_size;
		return tag_client;
	}
	*tag_size = tag_server_size;
	return tag_server;
}

static inline char *udp_packet_open(struct server *restrict s, char *data,
				    size_t *size)
{
	struct aead *restrict crypto = s->crypto;
	size_t len = *size;
	const char *nonce = data;
	const size_t nonce_size = aead_nonce_size(crypto);
	const size_t overhead = aead_overhead(crypto);
	if (len <= nonce_size + overhead) {
		LOG_W("udp_packet_open short packet");
		return NULL;
	}
	char *buf = data + nonce_size;
	const size_t cipher_size = len - nonce_size;
	const size_t buf_size = s->udp.rbuf.cap - nonce_size;
	size_t tag_size;
	const char *tag = get_crypto_tag(s, &tag_size, false);
	len = aead_open(crypto, buf, buf_size, nonce, buf, cipher_size, tag,
			tag_size);
	if (len == 0) {
		LOG_W("AEAD failed to open packet");
		return NULL;
	}
	assert(len + overhead == cipher_size);
	*size = len;
	return buf;
}

char *udp_recv(struct server *restrict s, struct endpoint *ep, size_t *size)
{
	char *buf = s->udp.rbuf.data;
	size_t buf_size = s->udp.rbuf.cap;
	ssize_t n = recvfrom(s->udp.fd, buf, buf_size, 0, ep->sa, &(ep->len));
	switch (n) {
	case -1: {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return NULL;
		}
		LOG_PERROR("udp recvfrom error");
		return NULL;
	} break;
	case 0: {
		LOG_W("udp recvfrom empty packet");
		return NULL;
	} break;
	default: {
		assert(n > 0);
	} break;
	}
	s->stats.udp_in += n;
#if UDP_PER_PACKET_LOG
	{
		char addr_str[64];
		format_sa(ep->sa, addr_str, sizeof(addr_str));
		LOGF_V("udp packet from: %s %zd bytes", addr_str, n);
	}
#endif
	buf_size = (size_t)n;
	if (s->crypto != NULL) {
		buf = udp_packet_open(s, buf, &buf_size);
		if (buf == NULL) {
			return NULL;
		}
	}
	*size = buf_size;
	return buf;
}

/* get a proper buffer for in-place encryption */
char *get_udp_send_buf(struct server *restrict s, size_t *n)
{
	struct aead *restrict crypto = s->crypto;
	if (crypto != NULL) {
		const size_t nonce_size = aead_nonce_size(crypto);
		*n = s->udp.wbuf.cap - nonce_size;
		return s->udp.wbuf.data + nonce_size;
	}
	*n = s->udp.wbuf.cap;
	return s->udp.wbuf.data;
}

static inline char *udp_packet_seal(struct server *restrict s,
				    const char *plain, size_t *size)
{
	struct aead *restrict crypto = s->crypto;
	const size_t plain_size = *size;
	const size_t nonce_size = aead_nonce_size(crypto);
	char *data = s->udp.wbuf.data;
	char *nonce = data;
	crypto_random_read(nonce, nonce_size);
	const size_t dst_size = s->udp.wbuf.cap - nonce_size;
	char *dst = data + nonce_size;
	size_t tag_size;
	const char *tag = get_crypto_tag(s, &tag_size, true);
	size_t sealed_size = aead_seal(crypto, dst, dst_size, nonce, plain,
				       plain_size, tag, tag_size);
	assert(sealed_size == plain_size + aead_overhead(crypto));
	*size = nonce_size + sealed_size;
	return data;
}

size_t udp_send(struct server *restrict s, struct endpoint ep, const char *buf,
		size_t n)
{
	if (s->crypto != NULL) {
		buf = udp_packet_seal(s, buf, &n);
	}

	struct sockaddr addr = { 0 };
	memcpy(&addr, ep.sa, ep.len);
	bool ok = queue_push(s->udp.udp_output, buf, n, addr);
	if (!ok) {
		LOGF_W("udp queue is full, %zu bytes discarded", n);
	}
	return ok ? n : 0;
}
