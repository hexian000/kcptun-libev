/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

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

void tcp_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void tcp_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void tcp_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void pkt_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void pkt_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void pkt_update_cb(struct ev_loop *loop, struct ev_idle *watcher, int revents);
void kcp_update_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);
void listener_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);
void keepalive_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);
void resolve_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);
void timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);
void http_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

int udp_output(const char *buf, int len, struct IKCPCB *kcp, void *user);
void kcp_update(struct session *ss);
bool kcp_sendmsg(struct session *ss, uint16_t msg);
bool kcp_push(struct session *ss);
void kcp_recv(struct session *ss);
void kcp_reset(struct session *ss);

int tcp_send(struct session *ss);
void pkt_flush(struct server *s);

#endif /* EVENT_H */
