#ifndef EVENT_H
#define EVENT_H

#include "conf.h"
#include "util.h"

#include <stdbool.h>
#include <stddef.h>

struct server;
struct session;

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

size_t tcp_recv(struct session *ss);
int udp_output(const char *buf, int len, struct IKCPCB *kcp, void *user);
size_t kcp_send(struct session *ss);
void kcp_recv(struct session *ss);
void kcp_close(struct session *ss);

void tcp_notify_write(struct session *ss);
void udp_notify_write(struct server *s);
void kcp_notify(struct session *ss);
void kcp_update_all(struct server *s);

#endif /* EVENT_H */
