#ifndef PROXY_H
#define PROXY_H

#include "hashtable.h"

#include <sys/socket.h>

#include <stdint.h>

struct server;
struct session;

struct session *
proxy_dial(struct server *s, struct sockaddr *addr, int32_t conv);

#endif /* PROXY_H */
