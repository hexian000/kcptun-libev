/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#define main kcptun_main
#include "main.c"

#undef main

#include "conf.h"
#include "crypto.h"
#include "event.h"
#include "nonce.h"
#include "server.h"
#include "util.h"
#include "pktqueue.h"
#include "session.h"

#include "algo/hashtable.h"
#include "binary/serialize.h"
#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#if WITH_CRYPTO
#include <sodium.h>
#endif

#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int fail_alloc, allocations;
static int fail_socket, fail_bind, fail_connect, fail_options, fail_crypto;
static int fail_nonblock, fail_strdup, fail_getsockname;
static int sockets;
static int device_calls, fail_device_at;
static const char *bind_source = "127.0.0.1:0";
static size_t sent;

bool real_queue_send(struct server *s, struct msgframe *msg) __asm__(
	"__real_queue_send");
bool test_queue_send(struct server *s, struct msgframe *msg) __asm__(
	"__wrap_queue_send");
bool test_queue_send(struct server *s, struct msgframe *msg)
{
	sent++;
	return real_queue_send(s, msg);
}
static char captured[65536];
static size_t captured_len;

void *real_malloc(size_t n) __asm__("__real_malloc");
void *test_malloc(size_t n) __asm__("__wrap_malloc");
void *test_malloc(size_t n)
{
	allocations++;
	if (fail_alloc > 0 && allocations == fail_alloc) {
		return NULL;
	}
	return real_malloc(n);
}

char *real_strdup(const char *text) __asm__("__real_strdup");
char *test_strdup(const char *text) __asm__("__wrap_strdup");
char *test_strdup(const char *text)
{
	if (fail_strdup) {
		fail_strdup = 0;
		return NULL;
	}
	return real_strdup(text);
}

int real_socket_set_nonblock(int fd) __asm__("__real_socket_set_nonblock");
int test_socket_set_nonblock(int fd) __asm__("__wrap_socket_set_nonblock");
int test_socket_set_nonblock(int fd)
{
	if (fail_nonblock) {
		fail_nonblock = 0;
		return EINVAL;
	}
	return real_socket_set_nonblock(fd);
}

bool real_bind_netdev(int fd, const char *device) __asm__(
	"__real_socket_bind_netdev");
bool test_bind_netdev(int fd, const char *device) __asm__(
	"__wrap_socket_bind_netdev");
bool test_bind_netdev(int fd, const char *device)
{
	if (strcmp(device, "test-device") == 0) {
		return ++device_calls != fail_device_at;
	}
	return real_bind_netdev(fd, device);
}

int real_socket(int domain, int type, int protocol) __asm__("__real_socket");
int test_socket(int domain, int type, int protocol) __asm__("__wrap_socket");
int test_socket(int domain, int type, int protocol)
{
	if (fail_socket) {
		fail_socket = 0;
		errno = EMFILE;
		return -1;
	}
	const int fd = real_socket(domain, type, protocol);
	if (fd >= 0) {
		sockets++;
	}
	return fd;
}

int real_close(int fd) __asm__("__real_close");
int test_close(int fd) __asm__("__wrap_close");
int test_close(int fd)
{
	sockets--;
	return real_close(fd);
}

int real_bind(int fd, const struct sockaddr *addr, socklen_t len) __asm__(
	"__real_bind");
int test_bind(int fd, const struct sockaddr *addr, socklen_t len) __asm__(
	"__wrap_bind");
int test_bind(int fd, const struct sockaddr *addr, socklen_t len)
{
	if (fail_bind) {
		fail_bind = 0;
		errno = EADDRINUSE;
		return -1;
	}
	return real_bind(fd, addr, len);
}

int real_connect(int fd, const struct sockaddr *addr, socklen_t len) __asm__(
	"__real_connect");
int test_connect(int fd, const struct sockaddr *addr, socklen_t len) __asm__(
	"__wrap_connect");
int test_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	if (fail_connect) {
		fail_connect = 0;
		errno = ENETUNREACH;
		return -1;
	}
	return real_connect(fd, addr, len);
}

int real_setsockopt(
	int fd, int level, int name, const void *value,
	socklen_t len) __asm__("__real_setsockopt");
int test_setsockopt(
	int fd, int level, int name, const void *value,
	socklen_t len) __asm__("__wrap_setsockopt");
int test_setsockopt(
	int fd, int level, int name, const void *value, socklen_t len)
{
	if (fail_options) {
		fail_options = 0;
		errno = ENOBUFS;
		return -1;
	}
	return real_setsockopt(fd, level, name, value, len);
}

int real_getsockname(int fd, struct sockaddr *addr, socklen_t *len) __asm__(
	"__real_getsockname");
int test_getsockname(int fd, struct sockaddr *addr, socklen_t *len) __asm__(
	"__wrap_getsockname");
int test_getsockname(int fd, struct sockaddr *addr, socklen_t *len)
{
	if (fail_getsockname > 0) {
		fail_getsockname--;
		if (fail_getsockname == 0) {
			errno = EBADF;
			return -1;
		}
	}
	return real_getsockname(fd, addr, len);
}

#if WITH_CRYPTO
struct crypto *real_crypto_new(const char *method) __asm__("__real_crypto_new");
struct crypto *test_crypto_new(const char *method) __asm__("__wrap_crypto_new");
struct crypto *test_crypto_new(const char *method)
{
	if (fail_crypto) {
		fail_crypto = 0;
		return NULL;
	}
	return real_crypto_new(method);
}
#endif /* WITH_CRYPTO */

static void capture(void *user, const unsigned char *buf, size_t len)
{
	(void)user;
	(void)fwrite(buf, 1, len, stderr);
	const size_t room = sizeof(captured) - captured_len - 1;
	if (len > room) {
		len = room;
	}
	memcpy(captured + captured_len, buf, len);
	captured_len += len;
	captured[captured_len] = '\0';
}

static void write_config(const char *fields)
{
	CHECK(args.conf_path != NULL);
	FILE *file = fopen(args.conf_path, "w");
	CHECK(file != NULL);
	CHECK(fprintf(file, "{\"kcp_bind\":\"%s\",%s}", bind_source, fields) >
	      0);
	CHECK(fclose(file) == 0);
}

static struct server *start_server(const char *fields)
{
	write_config(fields);
	struct config *conf = conf_read(args.conf_path);
	CHECK(conf != NULL);
	struct server *s = server_new(ev_loop_new(0), conf);
	CHECK(s != NULL);
	CHECK(server_start(s));
	return s;
}

static void destroy_server(struct server *s)
{
	struct ev_loop *loop = s->loop;
	struct config *conf = (struct config *)s->conf;
	server_free(s);
	conf_free(conf);
	ev_loop_destroy(loop);
}

static void expect_rejected(struct server *s, const char *fields)
{
	write_config(fields);
	unsigned char before[sizeof(*s)];
	memcpy(before, s, sizeof(before));
	struct pktqueue *queue = s->pkt.queue;
	unsigned char before_queue[sizeof(*queue)];
	memcpy(before_queue, queue, sizeof(before_queue));
	const int before_sockets = sockets;
	const int before_level = slog_level_;
#if WITH_CRYPTO
	unsigned char nonce[sizeof(struct noncegen)];
	if (queue->noncegen != NULL) {
		memcpy(nonce, queue->noncegen, sizeof(nonce));
	}
#endif
	captured_len = 0;
	captured[0] = '\0';
	allocations = 0;
	reload_config(s);
	CHECK(memcmp((const unsigned char *)s, before, sizeof(before)) == 0);
	CHECK(memcmp((const unsigned char *)queue, before_queue,
		     sizeof(before_queue)) == 0);
	CHECK(sockets == before_sockets);
	CHECK(slog_level_ == before_level);
#if WITH_CRYPTO
	if (queue->noncegen != NULL) {
		CHECK(memcmp((const unsigned char *)queue->noncegen, nonce,
			     sizeof(nonce)) == 0);
	}
#endif
	CHECK(strstr(captured, "config successfully reloaded") == NULL);
	CHECK(strstr(captured, "config") != NULL);
}

static void reload_cases(void)
{
#if WITH_CRYPTO
	const char *security =
		"\"method\":\"xchacha20poly1305_ietf\",\"password\":\"unchanged\"";
	struct server *s = start_server(security);
	union sockaddr_max remote = { .in = { .sin_family = AF_INET,
					      .sin_port = 1 } };
	struct session *ss = session_new(s, &remote, 17);
	CHECK(ss != NULL);
	void *element = ss;
	s->sessions = table_set(s->sessions, &ss->hkey, &element);
	CHECK(element == NULL);
	unsigned char session[sizeof(*ss)];
	memcpy(session, ss, sizeof(session));
	const struct crypto *crypto = s->pkt.queue->crypto;
	struct noncegen *noncegen = s->pkt.queue->noncegen;
	unsigned char nonce[NONCE_MAX_LENGTH];
	randombytes_buf(nonce, crypto->nonce_size);
	CHECK(noncegen_verify(noncegen, nonce));
	const char *compatible =
		"\"method\":\"xchacha20poly1305_ietf\",\"password\":\"unchanged\",\"timeout\":900,\"max_services\":7";
	write_config(compatible);
	const int fd = s->pkt.fd;
	reload_config(s);
	CHECK(s->session_timeout == 900);
	CHECK(s->pkt.fd == fd);
	CHECK(s->pkt.queue->crypto == crypto &&
	      s->pkt.queue->noncegen == noncegen);
	CHECK(memcmp((const unsigned char *)ss, session, sizeof(session)) == 0);
	CHECK(!noncegen_verify(noncegen, nonce));
	/* A password and the PSK derived from it are the same effective key. */
	unsigned char salt[crypto_pwhash_argon2id_SALTBYTES];
	unsigned char effective[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
	CHECK(crypto_generichash(
		      salt, sizeof(salt), (const unsigned char *)"kcptun-libev",
		      11, NULL, 0) == 0);
	CHECK(crypto_pwhash_argon2id(
		      effective, sizeof(effective), "unchanged", 9, salt,
		      crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE,
		      crypto_pwhash_argon2id_MEMLIMIT_MIN,
		      crypto_pwhash_argon2id_ALG_ARGON2ID13) == 0);
	char psk[128], fields[256];
	(void)sodium_bin2base64(
		psk, sizeof(psk), effective, sizeof(effective),
		sodium_base64_VARIANT_ORIGINAL);
	CHECK(snprintf(
		      fields, sizeof(fields),
		      "\"method\":\"xchacha20poly1305_ietf\",\"psk\":\"%s\",\"timeout\":900",
		      psk) > 0);
	write_config(fields);
	reload_config(s);
	CHECK(s->session_timeout == 900 && s->pkt.queue->crypto == crypto);
	sodium_memzero(effective, sizeof(effective));
	sodium_memzero(psk, sizeof(psk));
	sodium_memzero(fields, sizeof(fields));

	expect_rejected(
		s,
		"\"method\":\"xchacha20poly1305_ietf\",\"password\":\"rotated\",\"timeout\":1200");
	expect_rejected(
		s,
		"\"method\":\"xchacha20poly1305_ietf\",\"password\":\"rotated\",\"timeout\":1200,\"log\":\"discard\"");
	expect_rejected(
		s,
		"\"method\":\"xsalsa20poly1305\",\"password\":\"unchanged\"");
	expect_rejected(s, "\"timeout\":1200");
	expect_rejected(
		s, "\"method\":\"xchacha20poly1305_ietf\",\"psk\":\"invalid\"");
	expect_rejected(
		s,
		"\"method\":\"xchacha20poly1305_ietf\",\"password\":\"unchanged\",\"http_listen\":\"127.0.0.1:0\"");
	expect_rejected(
		s,
		"\"method\":\"xchacha20poly1305_ietf\",\"password\":\"unchanged\",\"listen\":\"127.0.0.1:0\",\"kcp_connect\":\"127.0.0.1:9\"");
#if WITH_OBFS
	expect_rejected(
		s,
		"\"method\":\"xchacha20poly1305_ietf\",\"password\":\"unchanged\",\"obfs\":\"dpi/tcp\"");
#endif
	fail_crypto = 1;
	expect_rejected(s, compatible);
	CHECK(fail_crypto == 0);

	/* Every project malloc reached while preparing a compatible reload. */
	const char *logged =
		"\"method\":\"xchacha20poly1305_ietf\",\"password\":\"unchanged\",\"log\":\"stderr\"";
	write_config(logged);
	allocations = 0;
	reload_config(s);
	const int count = allocations;
	slog_setoutput(SLOG_OUTPUT_WRITER, capture, (void *)NULL);
	CHECK(count > 0);
	for (int n = 1; n <= count; n++) {
		fail_alloc = n;
		expect_rejected(s, logged);
	}
	fail_alloc = 0;
	CHECK(memcmp((const unsigned char *)ss, session, sizeof(session)) == 0);
	destroy_server(s);

	/* A PSK's plaintext is wiped at startup, but its effective key remains. */
	s = start_server(
		"\"method\":\"xchacha20poly1305_ietf\",\"psk\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"");
	write_config(
		"\"method\":\"xchacha20poly1305_ietf\",\"psk\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"timeout\":800");
	reload_config(s);
	CHECK(s->session_timeout == 800);
	destroy_server(s);
#endif /* WITH_CRYPTO */
	struct server *plain = start_server("\"timeout\":600");
#if WITH_CRYPTO
	expect_rejected(
		plain,
		"\"method\":\"xchacha20poly1305_ietf\",\"password\":\"unchanged\"");
#endif
	expect_rejected(plain, "\"timeout\":1");
	expect_rejected(plain, "\"connect\":\"invalid-address\"");
	expect_rejected(plain, "\"kcp_connect\":\"invalid-address\"");
	expect_rejected(plain, "\"netdev\":\"this-interface-does-not-exist\"");
	const char *transport =
		"\"kcp_connect\":\"127.0.0.1:9\",\"timeout\":900";
	fail_socket = 1;
	expect_rejected(plain, transport);
	CHECK(fail_socket == 0);
	fail_bind = 1;
	expect_rejected(plain, transport);
	CHECK(fail_bind == 0);
	fail_connect = 1;
	expect_rejected(plain, transport);
	CHECK(fail_connect == 0);
	fail_options = 1;
	expect_rejected(plain, transport);
	CHECK(fail_options == 0);
	fail_nonblock = 1;
	expect_rejected(plain, transport);
	CHECK(fail_nonblock == 0);
	fail_strdup = 1;
	expect_rejected(plain, "\"netdev\":\"lo\"");
	CHECK(fail_strdup == 0);
	write_config(transport);
	reload_config(plain);
	CHECK(plain->session_timeout == 900);
	CHECK(plain->pkt.connected);
	destroy_server(plain);
	plain = start_server("\"connect\":\"127.0.0.1:9\"");
	expect_rejected(plain, "\"connect\":\"invalid-address\"");
	destroy_server(plain);
	bind_source = "0.0.0.0:0";
	plain = start_server(
		"\"rendezvous_server\":\"127.0.0.1:9\",\"connect\":\"127.0.0.1:9\"");
	fail_connect = 1;
	expect_rejected(
		plain,
		"\"rendezvous_server\":\"127.0.0.1:10\",\"connect\":\"127.0.0.1:9\"");
	CHECK(fail_connect == 0);
	for (int n = 1; n <= 3; n++) {
		fail_getsockname = n;
		expect_rejected(
			plain,
			"\"rendezvous_server\":\"127.0.0.1:10\",\"connect\":\"127.0.0.1:9\"");
		CHECK(fail_getsockname == 0);
	}
	destroy_server(plain);
}

static void rendezvous_cases(void)
{
	const char *fields =
		"\"rendezvous_server\":\"127.0.0.1:9\",\"connect\":\"127.0.0.1:9\"";
	bind_source = "127.0.0.2:0";
	struct server *s = start_server(fields);
	union sockaddr_max local = { 0 };
	socklen_t len = sizeof(local);
	CHECK(getsockname(s->pkt.fd, &local.sa, &len) == 0);
	CHECK(sa_equals(&local.sa, &s->pkt.rendezvous_local.sa));
	CHECK(local.in.sin_addr.s_addr == htonl(0x7f000002));
	CHECK(local.in.sin_port != 0);
	destroy_server(s);

	bind_source = "0.0.0.0:0";
	s = start_server(fields);
	CHECK(s->pkt.rendezvous_local.in.sin_addr.s_addr ==
	      htonl(INADDR_LOOPBACK));
	len = sizeof(local);
	CHECK(getsockname(s->pkt.fd, &local.sa, &len) == 0);
	CHECK(s->pkt.rendezvous_local.in.sin_port == local.in.sin_port);
	device_calls = 0;
	fail_device_at = 2;
	expect_rejected(
		s,
		"\"netdev\":\"test-device\",\"rendezvous_server\":\"127.0.0.1:9\",\"connect\":\"127.0.0.1:9\"");
	CHECK(device_calls == 2);
	device_calls = fail_device_at = 0;
	destroy_server(s);
	const char *ipv6_fields =
		"\"rendezvous_server\":\"[::1]:9\",\"connect\":\"[::1]:9\"";
	const char *ipv6_sources[] = { "[::1]:0", "[::]:0" };
	for (size_t i = 0; i < sizeof(ipv6_sources) / sizeof(ipv6_sources[0]);
	     i++) {
		bind_source = ipv6_sources[i];
		s = start_server(ipv6_fields);
		len = sizeof(local);
		CHECK(getsockname(s->pkt.fd, &local.sa, &len) == 0);
		CHECK(IN6_IS_ADDR_LOOPBACK(
			&s->pkt.rendezvous_local.in6.sin6_addr));
		CHECK(s->pkt.rendezvous_local.in6.sin6_port ==
		      local.in6.sin6_port);
		destroy_server(s);
	}
}

static void service_packet(
	struct server *s, uint16_t what, const char *id, size_t len,
	unsigned port)
{
	struct msgframe msg = { .addr.in = { .sin_family = AF_INET,
					     .sin_port = (uint16_t)port } };
	write_uint32(msg.buf, 0);
	write_uint16(msg.buf + 4, what);
	size_t offset =
		6 +
		inetaddr_write(msg.buf + 6, &msg.addr.sa, sizeof(msg.buf) - 6);
	write_uint16(msg.buf + offset, (uint_fast16_t)len);
	offset += 2;
	memcpy(msg.buf + offset, id, len);
	msg.len = (uint16_t)(offset + len);
	session0(s, &msg);
}

static void service_cases(void)
{
	struct server *s = start_server("\"max_services\":1");
	service_packet(s, S0MSG_LISTEN, "one", 3, 1);
	CHECK(table_size(s->pkt.services) == 1);
	service_packet(s, S0MSG_LISTEN, "two", 3, 2);
	CHECK(table_size(s->pkt.services) == 1);
	service_packet(s, S0MSG_LISTEN, "one", 3, 3);
	struct hashkey key = { .data = "one", .len = 3 };
	struct service *svc;
	CHECK(table_find(s->pkt.services, &key, (void **)&svc));
	CHECK(svc->server_addr[1].in.sin_port == 3);
	write_config("\"max_services\":2");
	reload_config(s);
	service_packet(s, S0MSG_LISTEN, "two", 3, 2);
	CHECK(table_size(s->pkt.services) == 2);
	write_config("\"max_services\":1");
	reload_config(s);
	CHECK(table_size(s->pkt.services) == 2);
	service_packet(s, S0MSG_LISTEN, "new", 3, 4);
	CHECK(table_size(s->pkt.services) == 2);
	service_packet(s, S0MSG_LISTEN, "one", 3, 5);
	CHECK(svc->server_addr[1].in.sin_port == 5);
	CHECK(table_find(s->pkt.services, &key, (void **)&svc));
	svc->last_seen = ev_now(s->loop) - s->session_timeout;
	key.data = "two";
	CHECK(table_find(s->pkt.services, &key, (void **)&svc));
	svc->last_seen = ev_now(s->loop) - s->session_timeout;
	timeout_cb(s->loop, &s->w_timeout, EV_TIMER);
	CHECK(table_size(s->pkt.services) == 0);
	char id[257];
	memset(id, 'a', sizeof(id));
	service_packet(s, S0MSG_LISTEN, id, 257, 1);
	CHECK(table_size(s->pkt.services) == 0);
	service_packet(s, S0MSG_LISTEN, id, 256, 1);
	CHECK(table_size(s->pkt.services) == 1);
	size_t queued = sent;
	service_packet(s, S0MSG_CONNECT, id, 257, 2);
	CHECK(sent == queued);
	service_packet(s, S0MSG_CONNECT, id, 256, 2);
	CHECK(sent == queued + 2);
	const int modes[] = { MODE_SERVER, MODE_CLIENT, MODE_RENDEZVOUS,
			      MODE_SERVER | MODE_RENDEZVOUS,
			      MODE_CLIENT | MODE_RENDEZVOUS };
	for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
		((struct config *)s->conf)->mode = modes[i];
		service_packet(s, S0MSG_LISTEN, "one", 3, 1);
		service_packet(s, S0MSG_CONNECT, id, 256, 2);
		CHECK(table_size(s->pkt.services) == 1);
		CHECK(sent == queued + 2);
	}
	destroy_server(s);
}

static void limit_cases(void)
{
	const char *valid[] = { "\"max_services\":1", "\"max_services\":65535",
				"\"timeout\":600" };
	for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
		write_config(valid[i]);
		struct config *conf = conf_read(args.conf_path);
		CHECK(conf != NULL);
		CHECK(conf->max_services == (i == 0 ? 1 :
					     i == 1 ? 65535 :
						      1024));
		conf_free(conf);
	}
	const char *invalid[] = { "\"max_services\":0",
				  "\"max_services\":65536",
				  "\"max_services\":-1",
				  "\"max_services\":1.5" };
	for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		write_config(invalid[i]);
		CHECK(conf_read(args.conf_path) == NULL);
	}
}

int main(int argc, char **argv)
{
	CHECK(argc == 2);
	CHECK(mkdir("tmp", 0700) == 0 || errno == EEXIST);
	char path[128];
	CHECK(snprintf(
		      path, sizeof(path), "tmp/reload-config-%s.json",
		      argv[1]) > 0);
	args.conf_path = path;
	loadlibs();
	slog_setlevel(LOG_LEVEL_DEBUG);
	slog_setoutput(SLOG_OUTPUT_WRITER, capture, (void *)NULL);
	if (strcmp(argv[1], "reload") == 0) {
		reload_cases();
	} else if (strcmp(argv[1], "rendezvous") == 0) {
		rendezvous_cases();
	} else if (strcmp(argv[1], "services") == 0) {
		service_cases();
	} else {
		limit_cases();
	}
	CHECK(sockets == 0);
	unloadlibs();
	CHECK(remove(args.conf_path) == 0);
	return EXIT_SUCCESS;
}
