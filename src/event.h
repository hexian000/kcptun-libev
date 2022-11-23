#ifndef EVENT_H
#define EVENT_H

#include "conf.h"
#include "util.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct server;
struct session;

struct ev_loop;
struct ev_io;
struct ev_timer;
struct IKCPCB;

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void pkt_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void pkt_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void kcp_update_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);
void timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);
void http_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

int udp_output(const char *buf, int len, struct IKCPCB *kcp, void *user);
void kcp_update(struct session *ss);
bool kcp_sendmsg(struct session *ss, uint16_t msg);
bool kcp_push(struct session *ss);
void kcp_recv(struct session *ss);
void kcp_close(struct session *ss);
void kcp_reset(struct session *ss);

void tcp_flush(struct session *ss);
void kcp_flush(struct session *ss);
void pkt_flush(struct server *s);

void kcp_notify_update(struct server *s);

#endif /* EVENT_H */
