#ifndef PROXY_H
#define PROXY_H

#include <sys/socket.h>

#include <stdbool.h>

struct session;

bool proxy_dial(struct session *restrict ss, struct sockaddr *sa);

#endif /* PROXY_H */
