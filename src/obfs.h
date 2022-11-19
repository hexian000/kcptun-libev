#ifndef OBFS_H
#define OBFS_H

#include "pktqueue.h"

#include <stdbool.h>
#include <stdint.h>

struct server;
struct obfs;
struct obfs_ctx;

struct obfs *obfs_new(struct server *restrict s);
bool obfs_resolve(struct obfs *obfs);
void obfs_stats(struct obfs *obfs);
bool obfs_start(struct obfs *obfs, struct server *s);
void obfs_stop(struct obfs *obfs, struct server *s);
void obfs_free(struct obfs *obfs);

bool obfs_open_inplace(struct obfs *obfs, struct msgframe *msg);
uint16_t obfs_offset(struct obfs *obfs);
bool obfs_seal_inplace(struct obfs *obfs, struct msgframe *msg);

#endif /* OBFS_H */
