#ifndef SOCKUTIL_H
#define SOCKUTIL_H

#include "hashtable.h"

#include <stdbool.h>
#include <stdint.h>

#include <netinet/in.h>
#include <sys/socket.h>

typedef struct {
	uint32_t b[7];
} sockaddr_max_t;
_Static_assert(
	sizeof(sockaddr_max_t) >= sizeof(struct sockaddr_in),
	"unexpected inet4 address size");
_Static_assert(
	sizeof(sockaddr_max_t) >= sizeof(struct sockaddr_in6),
	"unexpected inet6 address size");

int socket_setup(int fd);
void socket_set_reuseport(int fd, bool reuseport);
void socket_set_tcp(int fd, bool nodelay, bool keepalive);
void socket_set_buffer(int fd, size_t send, size_t recv);

void conv_make_key(hashkey_t *key, const struct sockaddr *sa, uint32_t conv);

socklen_t getsocklen(const struct sockaddr *sa);
bool sa_equals(const struct sockaddr *a, const struct sockaddr *b);
struct sockaddr *clonesockaddr(const struct sockaddr *src);
void format_sa(const struct sockaddr *sa, char *s, size_t buf_size);

enum {
	RESOLVE_TCP = 0x0,
	RESOLVE_UDP = 0x1,
	RESOLVE_PASSIVE = 0x2,
};

struct sockaddr *resolve(const char *hostname, const char *service, int flags);

#endif /* SOCKUTIL_H */
