/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "pktqueue.h"

#include "conf.h"
#include "server.h"
#include "session.h"
#include "util.h"

#include "algo/hashtable.h"
#include "ikcp.h"
#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static void
dispatch(struct server *s, const unsigned char *packet, const uint16_t len)
{
	struct pktqueue *q = s->pkt.queue;
	CHECK(q->mq_recv_len == 0);
	struct msgframe *msg = msgframe_new(q);
	CHECK(msg != NULL);
	msg->addr = (union sockaddr_max){ .in = { .sin_family = AF_INET } };
	msg->len = len;
	memcpy(msg->buf + msg->off, packet, len);
	q->mq_recv[q->mq_recv_len++] = msg;
	queue_dispatch(s);
	CHECK(q->mq_recv_len == 0);
}

static struct session *find_session(struct server *s, const uint32_t conv)
{
	union sockaddr_max addr = { .in = { .sin_family = AF_INET } };
	unsigned char key[SESSION_KEY_SIZE];
	SESSION_MAKEKEY(key, &addr.sa, conv);
	const struct hashkey hkey = { .data = key, .len = sizeof(key) };
	struct session *ss = NULL;
	(void)table_find(s->sessions, &hkey, (void **)&ss);
	return ss;
}

static void test_initial_input(struct server *s)
{
	/* This KCP fork uses big-endian fields. WINS is valid with no payload. */
	unsigned char packet[48] = { 0, 0, 0, 1, 84 };
	for (uint16_t len = 0; len < 24; len++) {
		dispatch(s, packet, len);
		CHECK(table_size(s->sessions) == 0);
	}
	packet[4] = 0;
	dispatch(s, packet, 24);
	CHECK(table_size(s->sessions) == 0);
	packet[4] = 81;
	packet[23] = 1; /* Missing PUSH payload. */
	dispatch(s, packet, 24);
	CHECK(table_size(s->sessions) == 0);
	packet[4] = 84;
	packet[23] = 0;
	memcpy(packet + 24, packet, 24);
	packet[28] = 0; /* Valid first segment, invalid second command. */
	dispatch(s, packet, 48);
	CHECK(table_size(s->sessions) == 0);
	for (unsigned int i = 1; i <= 100; i++) {
		packet[3] = (unsigned char)i;
		dispatch(s, packet, 4);
		CHECK(table_size(s->sessions) == 0);
	}
	LOGI("malformed initial input discarded");
}

static struct session *accept_session(struct server *s)
{
	const unsigned char packet[24] = { 0, 0, 0, 1, 84 };
	dispatch(s, packet, 24);
	struct session *ss = find_session(s, 1);
	CHECK(ss != NULL);
	CHECK(ss->is_accepted);
	CHECK(ss->kcp_state == KCP_STATE_ESTABLISHED);
	CHECK(ss->stats.kcp_rx == 24);
	CHECK(s->stats.kcp_rx == 24);
	return ss;
}

static void test_existing_input(struct server *s)
{
	const unsigned char packet[4] = { 0, 0, 0, 1 };
	struct session *ss = accept_session(s);
	ikcpcb *kcp = ss->kcp;
	const enum kcp_state states[] = {
		KCP_STATE_CONNECT,
		KCP_STATE_ESTABLISHED,
		KCP_STATE_LINGER,
	};
	for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++) {
		ss->kcp_state = states[i];
		dispatch(s, packet, 4);
		CHECK(table_size(s->sessions) == 1);
		CHECK(find_session(s, 1) == ss);
		CHECK(ss->kcp == kcp);
		CHECK(ss->kcp_state == states[i]);
		CHECK(ss->stats.kcp_rx == 24);
		CHECK(s->stats.kcp_rx == 24);
	}
}

static void test_valid_input(struct server *s)
{
	const unsigned char packet[24] = { 0, 0, 0, 1, 84 };
	struct session *ss = find_session(s, 1);
	CHECK(ss != NULL);
	ss->kcp_state = KCP_STATE_CONNECT;
	dispatch(s, packet, 24);
	CHECK(ss->kcp_state == KCP_STATE_ESTABLISHED);
	CHECK(ss->stats.kcp_rx == 48);
	CHECK(s->stats.kcp_rx == 48);
	session_kcp_stop(ss);
	dispatch(s, packet, 24);
	CHECK(find_session(s, 1) == ss);
	CHECK(ss->kcp_state == KCP_STATE_TIME_WAIT);
	CHECK(ss->kcp == NULL);
	CHECK(s->stats.kcp_rx == 48);
	LOGI("existing sessions and accounting preserved");
}

struct budget_entry {
	uint32_t value;
	struct hashkey key;
};

static struct budget_entry *
fill_session_budget(struct server *s, const size_t count)
{
	/* Occupy the table budget without allocating 2 GiB of session buffers.
	 * These shorter keys cannot match a real SESSION_KEY_SIZE key. */
	struct budget_entry *entries = calloc(count, sizeof(*entries));
	CHECK(entries != NULL);
	for (size_t i = 0; i < count; i++) {
		entries[i].value = (uint32_t)i;
		entries[i].key = (struct hashkey){
			.len = sizeof(entries[i].value),
			.data = &entries[i].value,
		};
		void *element = &entries[i];
		s->sessions = table_set(s->sessions, &entries[i].key, &element);
		CHECK(element == NULL);
	}
	return entries;
}

static void test_session_budget(struct server *s)
{
	struct session *first = accept_session(s);
	const size_t count = MAX_SESSIONS - 2;
	struct budget_entry *entries = fill_session_budget(s, count);
	CHECK(table_size(s->sessions) == MAX_SESSIONS - 1);
	unsigned char packet[24] = { 0, 0, 0, 2, 84 };
	dispatch(s, packet, sizeof(packet));
	CHECK(table_size(s->sessions) == MAX_SESSIONS);
	struct session *second = find_session(s, 2);
	CHECK(second != NULL);
	CHECK(second->kcp_state == KCP_STATE_ESTABLISHED);
	CHECK(s->stats.kcp_rx == 48);

	packet[3] = 3;
	for (size_t i = 0; i < 2; i++) {
		dispatch(s, packet, sizeof(packet));
		CHECK(table_size(s->sessions) == MAX_SESSIONS);
		CHECK(find_session(s, 3) == NULL);
		CHECK(s->stats.kcp_rx == 48);
	}
	packet[3] = 1;
	dispatch(s, packet, sizeof(packet));
	CHECK(find_session(s, 1) == first);
	CHECK(first->kcp_state == KCP_STATE_ESTABLISHED);
	CHECK(first->stats.kcp_rx == 48);
	CHECK(s->stats.kcp_rx == 72);
	CHECK(table_size(s->sessions) == MAX_SESSIONS);

	void *element = NULL;
	s->sessions = table_del(s->sessions, &entries[0].key, &element);
	CHECK(element == &entries[0]);
	packet[3] = 3;
	dispatch(s, packet, sizeof(packet));
	CHECK(table_size(s->sessions) == MAX_SESSIONS);
	CHECK(find_session(s, 3) != NULL);
	CHECK(s->stats.kcp_rx == 96);
	packet[3] = 2;
	dispatch(s, packet, sizeof(packet));
	CHECK(find_session(s, 2) == second);
	CHECK(second->stats.kcp_rx == 48);
	CHECK(s->stats.kcp_rx == 120);
	for (size_t i = 1; i < count; i++) {
		s->sessions = table_del(s->sessions, &entries[i].key, &element);
		CHECK(element == &entries[i]);
	}
	free(entries);
	CHECK(table_size(s->sessions) == 3);
	LOGI("session budget: last slot admitted, excess rejected, existing traffic and re-admission preserved");
}

static void capture_warning(void *ud, const unsigned char *buf, size_t len)
{
	size_t *count = ud;
	char line[1024];
	if (len >= sizeof(line)) {
		len = sizeof(line) - 1;
	}
	memcpy(line, buf, len);
	line[len] = '\0';
	if (strstr(line, "ikcp_input:") != NULL) {
		(*count)++;
	}
}

static void test_warning_rate(struct server *s)
{
	const unsigned char packet[24] = { 0, 0, 0, 1, 84 };
	dispatch(s, packet, sizeof(packet));
	struct session *ss = find_session(s, 1);
	CHECK(ss != NULL);
	size_t warnings = 0;
	slog_setlevel(LOG_LEVEL_WARNING);
	slog_setoutput(SLOG_OUTPUT_WRITER, capture_warning, (void *)&warnings);
	for (size_t i = 0; i < 100; i++) {
		dispatch(s, packet, 4);
	}
	slog_setoutput(SLOG_OUTPUT_STREAM, log_filewriter(stdout));
	slog_setlevel(LOG_LEVEL_INFO);
	CHECK(warnings == 1);
	CHECK(find_session(s, 1) == ss);
	CHECK(ss->kcp_state == KCP_STATE_ESTABLISHED);
	CHECK(ss->stats.kcp_rx == sizeof(packet));
	dispatch(s, packet, sizeof(packet));
	CHECK(ss->stats.kcp_rx == sizeof(packet) * 2);
	LOGI("100 rejected packets at one event-loop timestamp produced one warning");
}

static bool free_session(
	const struct hashtable *t, const void *key, void *element, void *ud)
{
	UNUSED(t);
	UNUSED(key);
	UNUSED(ud);
	session_free(element);
	return false;
}

int main(int argc, char **argv)
{
	CHECK(argc == 2);
	init();
	loadlibs();
	slog_setlevel(LOG_LEVEL_INFO);
	struct config conf = {
		.mode = MODE_SERVER,
		.kcp_sndwnd = 32,
		.kcp_rcvwnd = 32,
		.kcp_nodelay = 1,
		.kcp_interval = 10,
	};
	struct ev_loop *loop = ev_loop_new(0);
	CHECK(loop != NULL);
	struct server s = { .conf = &conf, .loop = loop };
	s.pkt.w_write.fd = -1;
	s.sessions = table_new(NULL);
	CHECK(s.sessions != NULL);
	s.pkt.queue = queue_new(&s);
	CHECK(s.pkt.queue != NULL);
	s.pkt.queue->mss = 1200;
	if (strcmp(argv[1], "admission") == 0) {
		test_initial_input(&s);
		test_existing_input(&s);
		test_valid_input(&s);
	} else if (strcmp(argv[1], "budget") == 0) {
		test_session_budget(&s);
	} else {
		CHECK(strcmp(argv[1], "logging") == 0);
		test_warning_rate(&s);
	}
	s.sessions = table_filter(s.sessions, free_session, NULL);
	table_free(s.sessions);
	queue_free(s.pkt.queue);
	ev_loop_destroy(loop);
	unloadlibs();
	return EXIT_SUCCESS;
}
