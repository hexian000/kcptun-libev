#ifndef OBFS_H
#define OBFS_H

#include "pktqueue.h"

#include <ev.h>

#include <stdbool.h>
#include <stdint.h>

struct server;
struct obfs;
struct obfs_ctx;

struct obfs *obfs_new(struct ev_loop *loop, struct config *conf);
bool obfs_resolve(struct obfs *obfs);
bool obfs_start(struct obfs *obfs, struct server *s);
void obfs_stop(struct obfs *obfs, struct server *s);
void obfs_free(struct obfs *obfs);

bool obfs_open_inplace(struct obfs *obfs, struct msgframe *msg);
uint16_t obfs_offset(struct obfs *obfs);
bool obfs_seal_inplace(struct obfs *obfs, struct msgframe *msg);

bool obfs_ctx_timeout(struct obfs_ctx *ctx, ev_tstamp now);

#endif /* OBFS_H */
