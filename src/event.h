/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef EVENT_H
#define EVENT_H

#include <stdbool.h>
#include <stdint.h>

struct server;
struct session;

struct ev_loop;
struct ev_io;
struct ev_timer;
struct IKCPCB;

void tcp_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void tcp_socket_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void pkt_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void pkt_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void kcp_update_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);
void listener_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);
void keepalive_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);
void resolve_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);
void timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);
void http_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

bool kcp_cansend(const struct session *ss);
bool kcp_canrecv(const struct session *ss);

int kcp_output(const char *buf, int len, struct IKCPCB *kcp, void *user);
bool kcp_sendmsg(struct session *ss, uint16_t msg);
bool kcp_push(struct session *ss);
void kcp_recv(struct session *ss);

void tcp_flush(struct session *ss);
void tcp_notify(struct session *ss);

void pkt_notify_send(struct server *s);

#endif /* EVENT_H */
