#ifndef SOCKUTIL_H
#define SOCKUTIL_H

#include "hashtable.h"

#include <stdint.h>
#include <sys/socket.h>

typedef struct {
	uint32_t b[7];
} sockaddr_max_t;

int socket_set_nodelay(int fd);
int socket_set_nonblock(int fd);
int socket_set_reuseport(int fd);

socklen_t getsocklen(const struct sockaddr *sa);
void format_sa(const struct sockaddr *sa, char *s, size_t buf_size);

void conv_make_key(hashkey_t *key, const struct sockaddr *sa, uint32_t conv);

#endif /* SOCKUTIL_H */
