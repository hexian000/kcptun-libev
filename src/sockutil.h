#ifndef SOCKUTIL_H
#define SOCKUTIL_H

#include "hashtable.h"

#include <stdint.h>
#include <sys/socket.h>

typedef struct {
	uint32_t b[7];
} sockaddr_max_t;

int socket_set_nonblock(int fd);
void socket_set_reuseport(int fd, int reuseport);
void socket_set_tcp(int fd, int nodelay, int linger, int keepalive);
void socket_set_buffer(int fd, size_t send, size_t recv);

void conv_make_key(hashkey_t *key, const struct sockaddr *sa, uint32_t conv);

socklen_t getsocklen(const struct sockaddr *sa);
struct sockaddr *clonesockaddr(const struct sockaddr *src);
void format_sa(const struct sockaddr *sa, char *s, size_t buf_size);
struct sockaddr *
resolve(const char *hostname, const char *service, int socktype);

#endif /* SOCKUTIL_H */
