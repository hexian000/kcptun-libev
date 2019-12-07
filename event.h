#ifndef EVENT_H
#define EVENT_H

#include "conf.h"
#include "util.h"

#include <stdbool.h>
#include <stddef.h>

struct ev_loop;
struct ev_async;
struct ev_io;
struct ev_timer;
struct IKCPCB;

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void udp_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void udp_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void udp_output_cb(struct ev_loop *loop, struct ev_async *watcher, int revents);
void kcp_update_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);
void keepalive_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);

int udp_output(const char *buf, int len, struct IKCPCB *kcp, void *user);

extern const char tag_client[];
extern const size_t tag_client_size;
extern const char tag_server[];
extern const size_t tag_server_size;

#endif /* EVENT_H */
