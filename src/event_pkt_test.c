/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"
#include "event.h"
#include "pktqueue.h"
#include "server.h"
#include "util.h"

#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef TEST_PKT_FALLBACK
#undef HAVE_SENDMMSG
#undef HAVE_RECVMMSG
#define HAVE_SENDMMSG 0
#define HAVE_RECVMMSG 0
#endif

#define FRAME_COUNT ((size_t)MMSG_BATCH_SIZE * 8)
#define READ_BUDGET ((size_t)MMSG_BATCH_SIZE * 4)

static struct msgframe frames[FRAME_COUNT];
static bool live[FRAME_COUNT];
static size_t outstanding, allocations, allocation_limit = SIZE_MAX;
static bool real_io;
static int send_script[16];
static unsigned char send_heads[16];
static size_t send_step, send_steps;
static size_t receive_left, received, truncate_at = SIZE_MAX;
static int receive_error;
static size_t dispatched, dispatch_calls;

static struct msgframe *test_frame_new(const struct pktqueue *q)
{
	if (allocations == allocation_limit) {
		return NULL;
	}
	allocations++;
	for (size_t i = 0; i < FRAME_COUNT; i++) {
		if (!live[i]) {
			live[i] = true;
			outstanding++;
			frames[i] = (struct msgframe){ .off = q->msg_offset };
			return &frames[i];
		}
	}
	FAILMSG("frame registry exhausted");
}

static void test_frame_delete(struct pktqueue *q, struct msgframe *msg)
{
	UNUSED(q);
	for (size_t i = 0; i < FRAME_COUNT; i++) {
		if (msg == &frames[i]) {
			CHECK(live[i]);
			live[i] = false;
			outstanding--;
			return;
		}
	}
	FAILMSG("unowned frame deleted");
}

static int send_result(const struct msghdr *hdr)
{
	CHECK(send_step < send_steps);
	CHECK(hdr->msg_iovlen == 1);
	CHECK(hdr->msg_iov[0].iov_len > 0);
	send_heads[send_step] =
		*(const unsigned char *)hdr->msg_iov[0].iov_base;
	const int result = send_script[send_step++];
	if (result < 0) {
		errno = -result;
		return -1;
	}
	return result;
}

#if HAVE_SENDMMSG
static int
test_sendmmsg(int fd, struct mmsghdr *messages, unsigned count, int flags)
{
	if (real_io) {
		return sendmmsg(fd, messages, count, flags);
	}
	CHECK(count > 0 && count <= MMSG_BATCH_SIZE);
	const int result = send_result(&messages[0].msg_hdr);
	CHECK(result < 0 || (unsigned)result <= count);
	return result;
}
#else
static ssize_t test_sendmsg(int fd, const struct msghdr *hdr, int flags)
{
	if (real_io) {
		return sendmsg(fd, hdr, flags);
	}
	const int result = send_result(hdr);
	CHECK(result <= 1);
	return result < 0 ? -1 : (ssize_t)hdr->msg_iov[0].iov_len;
}
#endif /* HAVE_SENDMMSG */

static ssize_t receive_one(struct msghdr *hdr)
{
	CHECK(received < READ_BUDGET * 2);
	CHECK(hdr->msg_iovlen == 1);
	CHECK(hdr->msg_iov[0].iov_len == MAX_PACKET_SIZE);
	memset(hdr->msg_iov[0].iov_base, (unsigned char)received, 3);
	struct sockaddr_in *addr = hdr->msg_name;
	*addr = (struct sockaddr_in){ .sin_family = AF_INET };
	hdr->msg_namelen = sizeof(*addr);
	hdr->msg_flags = received == truncate_at ? MSG_TRUNC : 0;
	received++;
	receive_left--;
	return 3;
}

static bool receive_failed(void)
{
	if (receive_error != 0) {
		errno = receive_error;
		receive_error = 0;
		return true;
	}
	if (receive_left == 0) {
		errno = EAGAIN;
		return true;
	}
	return false;
}

#if HAVE_RECVMMSG
static int test_recvmmsg(
	int fd, struct mmsghdr *messages, unsigned count, int flags,
	struct timespec *timeout)
{
	if (real_io) {
		return recvmmsg(fd, messages, count, flags, timeout);
	}
	CHECK(count > 0 && count <= MMSG_BATCH_SIZE);
	if (receive_failed()) {
		return -1;
	}
	unsigned n = 0;
	while (n < count && receive_left > 0) {
		messages[n].msg_len =
			(unsigned)receive_one(&messages[n].msg_hdr);
		n++;
	}
	return (int)n;
}
#else
static ssize_t test_recvmsg(int fd, struct msghdr *hdr, int flags)
{
	if (real_io) {
		return recvmsg(fd, hdr, flags);
	}
	return receive_failed() ? -1 : receive_one(hdr);
}
#endif /* HAVE_RECVMMSG */

static void test_dispatch(struct server *s)
{
	struct pktqueue *q = s->pkt.queue;
	dispatch_calls++;
	for (size_t i = 0; i < q->mq_recv_len; i++) {
		CHECK(q->mq_recv[i]->len == 3);
		CHECK(q->mq_recv[i]->buf[0] == (unsigned char)dispatched);
		dispatched++;
		test_frame_delete(q, q->mq_recv[i]);
	}
	q->mq_recv_len = 0;
}

#define msgframe_new test_frame_new
#define msgframe_delete test_frame_delete
#define queue_dispatch test_dispatch
#if HAVE_SENDMMSG
#define sendmmsg test_sendmmsg
#else
#define sendmsg test_sendmsg
#endif
#if HAVE_RECVMMSG
#define recvmmsg test_recvmmsg
#else
#define recvmsg test_recvmsg
#endif
#include "event_pkt.c"
#undef msgframe_new
#undef msgframe_delete
#undef queue_dispatch
#undef sendmmsg
#undef sendmsg
#undef recvmmsg
#undef recvmsg

struct fixture {
	struct server server;
	struct config conf;
	struct pktqueue queue;
	struct msgframe *send[(size_t)MMSG_BATCH_SIZE * 2];
	struct msgframe *recv[(size_t)MMSG_BATCH_SIZE * 2];
};

static void fixture_init(struct fixture *f)
{
	CHECK(outstanding == 0);
	allocations = 0;
	allocation_limit = SIZE_MAX;
	real_io = false;
	send_step = send_steps = 0;
	receive_left = received = 0;
	truncate_at = SIZE_MAX;
	receive_error = 0;
	dispatched = dispatch_calls = 0;
	*f = (struct fixture){ 0 };
	f->server.conf = &f->conf;
	f->server.loop = ev_loop_new(EVFLAG_NOENV);
	CHECK(f->server.loop != NULL);
	f->server.pkt.queue = &f->queue;
	f->server.pkt.last_send_time = -1;
	f->queue.mq_send = f->send;
	f->queue.mq_recv = f->recv;
	f->queue.mq_send_cap = f->queue.mq_recv_cap =
		(size_t)MMSG_BATCH_SIZE * 2;
	const int fd = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(fd >= 0);
	CHECK(socket_set_nonblock(fd) == 0);
	ev_io_init(&f->server.pkt.w_write, pkt_write_cb, fd, EV_WRITE);
	f->server.pkt.w_write.data = &f->server;
}

static void fixture_free(struct fixture *f)
{
	for (size_t i = 0; i < f->queue.mq_send_len; i++) {
		test_frame_delete(&f->queue, f->send[i]);
	}
	for (size_t i = 0; i < f->queue.mq_recv_len; i++) {
		test_frame_delete(&f->queue, f->recv[i]);
	}
	CHECK(outstanding == 0);
	ev_io_stop(f->server.loop, &f->server.pkt.w_write);
	socket_close(f->server.pkt.w_write.fd);
	ev_loop_destroy(f->server.loop);
}

static void enqueue(struct fixture *f, unsigned char id)
{
	struct msgframe *msg = test_frame_new(&f->queue);
	CHECK(msg != NULL);
	msg->addr.in.sin_family = AF_INET;
	msg->len = id;
	memset(msg->buf, id, msg->len);
	f->send[f->queue.mq_send_len++] = msg;
}

static void send_backpressure(void)
{
	struct fixture f;
	fixture_init(&f);
	enqueue(&f, 1);
	enqueue(&f, 2);
	enqueue(&f, 3);
	struct msgframe *second = f.send[1], *third = f.send[2];
	send_script[0] = 1;
	send_script[1] = -EAGAIN;
	send_steps = 2;
	pkt_notify_send(&f.server);
	CHECK(send_step == 2 && send_heads[0] == 1 && send_heads[1] == 2);
	CHECK(f.queue.mq_send_len == 2 && outstanding == 2);
	CHECK(f.send[0] == second && f.send[1] == third);
	CHECK(f.server.stats.pkt_tx == 1);
	CHECK(f.server.pkt.last_send_time == ev_now(f.server.loop));
	CHECK(ev_is_active(&f.server.pkt.w_write));

	f.server.pkt.last_send_time = -7;
	send_script[2] = -EAGAIN;
	send_steps = 3;
	pkt_write_cb(f.server.loop, &f.server.pkt.w_write, EV_WRITE);
	CHECK(f.server.pkt.last_send_time == -7);
	CHECK(f.server.stats.pkt_tx == 1 && outstanding == 2);
	CHECK(f.send[0] == second && f.send[1] == third);
	CHECK(ev_is_active(&f.server.pkt.w_write));
	send_script[3] = send_script[4] = 1;
	send_steps = 5;
	pkt_write_cb(f.server.loop, &f.server.pkt.w_write, EV_WRITE);
	CHECK(send_step == 5 && send_heads[3] == 2 && send_heads[4] == 3);
	CHECK(f.queue.mq_send_len == 0 && outstanding == 0);
	CHECK(f.server.stats.pkt_tx == 6);
	CHECK(f.server.pkt.last_send_time == ev_now(f.server.loop));
	pkt_write_cb(f.server.loop, &f.server.pkt.w_write, EV_WRITE);
	CHECK(!ev_is_active(&f.server.pkt.w_write));
	fixture_free(&f);
}

static void send_errors(void)
{
	struct fixture f;
	fixture_init(&f);
	enqueue(&f, 1);
	enqueue(&f, 2);
	enqueue(&f, 3);
	const int script[] = { -EINTR, -EMSGSIZE, 1, -EAGAIN, 1 };
	memcpy(send_script, script, sizeof(script));
	send_steps = 4;
	pkt_notify_send(&f.server);
	CHECK(send_step == 4);
	CHECK(send_heads[0] == 1 && send_heads[1] == 1);
	CHECK(send_heads[2] == 2 && send_heads[3] == 3);
	CHECK(f.queue.mq_send_len == 1 && f.send[0]->buf[0] == 3);
	CHECK(outstanding == 1 && f.server.stats.pkt_tx == 2);
	CHECK(ev_is_active(&f.server.pkt.w_write));
	send_steps = 5;
	pkt_write_cb(f.server.loop, &f.server.pkt.w_write, EV_WRITE);
	CHECK(f.queue.mq_send_len == 0 && outstanding == 0);
	CHECK(f.server.stats.pkt_tx == 5);
	fixture_free(&f);

	fixture_init(&f);
	enqueue(&f, 1);
	send_script[0] = -ECONNREFUSED;
	send_steps = 1;
	pkt_notify_send(&f.server);
	CHECK(f.queue.mq_send_len == 0 && outstanding == 0);
	CHECK(f.server.stats.pkt_tx == 0 && f.server.pkt.last_send_time == -1);
	fixture_free(&f);
}

static void receive_truncation(void)
{
	struct fixture f;
	fixture_init(&f);
	receive_left = 3;
	truncate_at = 1;
	CHECK(pkt_recv(&f.server, 0, 4) == 3);
	CHECK(f.queue.mq_recv_len == 2 && outstanding == 2);
	CHECK(f.recv[0]->buf[0] == 0 && f.recv[1]->buf[0] == 2);
	CHECK(f.recv[0]->ts == ev_now(f.server.loop));
	CHECK(f.server.stats.pkt_rx == 6);
	fixture_free(&f);
}

static void receive_allocation(void)
{
	struct fixture f;
	fixture_init(&f);
	receive_left = (size_t)MMSG_BATCH_SIZE * 2;
	allocation_limit = MMSG_BATCH_SIZE;
	CHECK(pkt_recv(&f.server, 0, (size_t)MMSG_BATCH_SIZE * 2) ==
	      MMSG_BATCH_SIZE);
	CHECK(f.queue.mq_recv_len == MMSG_BATCH_SIZE);
	CHECK(outstanding == MMSG_BATCH_SIZE);
	CHECK(f.server.stats.pkt_rx == (size_t)MMSG_BATCH_SIZE * 3);
	for (size_t i = 0; i < MMSG_BATCH_SIZE; i++) {
		CHECK(f.recv[i]->buf[0] == (unsigned char)i);
	}
	fixture_free(&f);

	fixture_init(&f);
	receive_left = 2;
	allocation_limit = 3;
	CHECK(pkt_recv(&f.server, 0, MMSG_BATCH_SIZE) == 2);
	CHECK(f.queue.mq_recv_len == 2 && outstanding == 2);
	CHECK(f.server.stats.pkt_rx == 6);
	fixture_free(&f);
}

static void receive_errors(void)
{
	struct fixture f;
	const int errors[] = { EINTR, EAGAIN, ECONNRESET, EIO };
	for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		fixture_init(&f);
		receive_left = 1;
		receive_error = errors[i];
		const size_t expected = errors[i] == EINTR ? 1 : 0;
		CHECK(pkt_recv(&f.server, 0, 2) == expected);
		CHECK(f.queue.mq_recv_len == expected &&
		      outstanding == expected);
		CHECK(f.server.stats.pkt_rx == expected * 3);
		fixture_free(&f);
	}
	fixture_init(&f);
	allocation_limit = 0;
	CHECK(pkt_recv(&f.server, 0, 1) == 0);
	CHECK(f.queue.mq_recv_len == 0 && outstanding == 0);
	CHECK(pkt_recv(&f.server, 0, 0) == 0);
	fixture_free(&f);
}

static void timer_cb(struct ev_loop *loop, ev_timer *watcher, int events)
{
	UNUSED(loop);
	CHECK((events & EV_TIMER) != 0);
	*(bool *)watcher->data = true;
}

static void callback_budget(void)
{
	struct fixture f;
	fixture_init(&f);
	/* A short receive queue forces repeated dispatches within one callback. */
	f.queue.mq_recv_cap = 7;
	receive_left = READ_BUDGET + 1;
	ev_io reader;
	ev_io_init(&reader, pkt_read_cb, f.server.pkt.w_write.fd, EV_READ);
	reader.data = &f.server;
	bool timer_fired = false;
	ev_timer timer;
	ev_timer_init(&timer, timer_cb, 0, 0);
	timer.data = &timer_fired;
	ev_timer_start(f.server.loop, &timer);
	ev_feed_event(f.server.loop, &reader, EV_READ);
	ev_run(f.server.loop, EVRUN_NOWAIT);
	CHECK(timer_fired);
	CHECK(received == READ_BUDGET && receive_left == 1);
	CHECK(dispatched == READ_BUDGET && dispatch_calls > 1);
	CHECK(outstanding == 0 && f.server.stats.pkt_rx == 3 * READ_BUDGET);
	pkt_read_cb(f.server.loop, &reader, EV_READ);
	CHECK(received == READ_BUDGET + 1 && receive_left == 0);
	CHECK(dispatched == READ_BUDGET + 1 && outstanding == 0);
	fixture_free(&f);
}

static void socket_roundtrip(void)
{
	struct fixture f;
	fixture_init(&f);
	real_io = true;
	const int fd = f.server.pkt.w_write.fd;
	struct sockaddr_in addr = { .sin_family = AF_INET,
				    .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	CHECK(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
	socklen_t addrlen = sizeof(addr);
	CHECK(getsockname(fd, (struct sockaddr *)&addr, &addrlen) == 0);
	for (unsigned char i = 1; i <= 3; i++) {
		enqueue(&f, i);
		f.send[i - 1]->addr.in = addr;
	}
	pkt_notify_send(&f.server);
	CHECK(f.queue.mq_send_len == 0 && f.server.stats.pkt_tx == 6);
	CHECK(pkt_recv(&f.server, fd, 4) == 3);
	CHECK(f.queue.mq_recv_len == 3 && f.server.stats.pkt_rx == 6);
	for (size_t i = 0; i < 3; i++) {
		CHECK(f.recv[i]->len == i + 1);
		CHECK(f.recv[i]->buf[0] == i + 1);
		test_frame_delete(&f.queue, f.recv[i]);
	}
	f.queue.mq_recv_len = 0;
	unsigned char oversized[MAX_PACKET_SIZE + 1] = { 0 };
	CHECK(sendto(fd, oversized, sizeof(oversized), 0,
		     (const struct sockaddr *)&addr,
		     sizeof(addr)) == sizeof(oversized));
	CHECK(pkt_recv(&f.server, fd, 1) == 1);
	CHECK(f.queue.mq_recv_len == 0 && outstanding == 0);
	CHECK(f.server.stats.pkt_rx == 6);
	CHECK(sendto(fd, "", 0, 0, (const struct sockaddr *)&addr,
		     sizeof(addr)) == 0);
	CHECK(pkt_recv(&f.server, fd, 1) == 1);
	CHECK(f.queue.mq_recv_len == 1 && f.recv[0]->len == 0);
	CHECK(f.server.stats.pkt_rx == 6);
	fixture_free(&f);
}

int main(void)
{
	slog_setoutput(SLOG_OUTPUT_STREAM, log_filewriter(stderr));
	slog_setlevel(LOG_LEVEL_ERROR);
	send_backpressure();
	send_errors();
	receive_truncation();
	receive_allocation();
	receive_errors();
	callback_budget();
	socket_roundtrip();
	slog_setlevel(LOG_LEVEL_INFO);
	LOGI_F("UDP regression cases passed (sendmmsg=%d, recvmmsg=%d)",
	       HAVE_SENDMMSG, HAVE_RECVMMSG);
	return EXIT_SUCCESS;
}
