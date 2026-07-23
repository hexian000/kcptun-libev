/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "util.h"

#include "conf.h"
#include "crypto.h"
#include "pktqueue.h"

#include "ikcp.h"
#include "io/file.h"
#include "math/rand.h"
#include "meta/minmax.h"
#include "net/addr.h"
#include "os/clock.h"
#include "os/socket.h"
#include "utils/debug.h"
#include "utils/mcache.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <locale.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <threads.h>
#include <time.h>

bool check_rate_limit(
	ev_tstamp *restrict last, const ev_tstamp now, const double interval)
{
	const ev_tstamp last_tick = *last;
	if (last_tick == TSTAMP_NIL || now < last_tick) {
		*last = now;
		return false;
	}
	const double dt = now - last_tick;
	if (dt < interval) {
		return false;
	}
	*last = (dt < 2.0 * interval) ? (last_tick + interval) : now;
	return true;
}

#if defined(WIN32)
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

void init(void)
{
	if (setlocale(LC_ALL, "") == NULL) {
		LOGW("setlocale: failed to set the locale from environment");
	}
	/* io_filewriter() heap-allocates a stream that slog only borrows; keep
	 * it in a static so it stays reachable (and stdout unbuffered) for the
	 * process lifetime rather than dangling once the sink is later replaced. */
	static struct io_stream *log_writer = NULL;
	if (log_writer == NULL) {
		log_writer = io_filewriter(stdout);
	}
	slog_setoutput(SLOG_OUTPUT_WRITER, log_writer);
	{
		static char prefix[] = __FILE__;
		char *s = strrchr(prefix, PATH_SEPARATOR);
		if (s != NULL) {
			s[1] = '\0';
		}
		slog_setfileprefix(prefix);
	}
	slog_setlevel(LOG_LEVEL_VERBOSE);

	struct sigaction ignore = {
		.sa_handler = SIG_IGN,
	};
	if (sigaction(SIGPIPE, &ignore, NULL) != 0) {
		const int err = errno;
		FAILMSGF("sigaction: %s", strerror(err));
	}
#if WITH_CRASH_HANDLER
	crashhandler_install();
#endif
}

struct mcache *msgpool;

void loadlibs(void)
{
	LOGD_F("%s: %s", PROJECT_NAME, PROJECT_VER);
	LOGD_F("libev: %d.%d", ev_version_major(), ev_version_minor());

#if WITH_CRYPTO
	crypto_init();
	srand64(((uint64_t)crypto_rand32() << 32u) | crypto_rand32());
#else
	srand64((uint64_t)time(NULL));
#endif

	/* msgpool doubles as libkcp's segment pool (ikcp_segment_pool below):
	 * two otherwise-unrelated allocator clients intentionally share one
	 * fixed-size cache, sized to fit the larger of the two. */
	const size_t size =
		MAX(sizeof(struct IKCPSEG) + MAX_PACKET_SIZE,
		    sizeof(struct msgframe));
	msgpool = mcache_new((size_t)MMSG_BATCH_SIZE * 2, size);
	CHECKOOM(msgpool);
	ikcp_segment_pool = msgpool;
}

void unloadlibs(void)
{
	mcache_free(msgpool);
	ikcp_segment_pool = msgpool = NULL;
}

#if WITH_CRYPTO
void genpsk(const char *restrict method)
{
	loadlibs();
	struct crypto *crypto = crypto_new(method);
	if (crypto == NULL) {
		LOGF("failed to initialize crypto");
		exit(EXIT_FAILURE);
	}
	char key[256];
	if (!crypto_keygen(crypto, key, sizeof(key))) {
		LOGF("failed to generate random key");
		exit(EXIT_FAILURE);
	}
	(void)fprintf(stdout, "%s\n", key);
	(void)fflush(stdout);
	crypto_free(crypto);
}
#endif /* WITH_CRYPTO */

void socket_bind_netdev(const int fd, const char *restrict netdev)
{
#ifdef SO_BINDTODEVICE
	char ifname[IFNAMSIZ];
	if (strlen(netdev) >= sizeof(ifname)) {
		LOGW_F("SO_BINDTODEVICE: interface name too long: `%s'",
		       netdev);
		return;
	}
	(void)strncpy(ifname, netdev, sizeof(ifname) - 1);
	ifname[sizeof(ifname) - 1] = '\0';
	if (setsockopt(
		    fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, sizeof(ifname))) {
		const int err = errno;
		LOGW_F("SO_BINDTODEVICE: (%d) %s", err, strerror(err));
	}
#else
	(void)fd;
	if (netdev[0] != '\0') {
		LOGW("SO_BINDTODEVICE: not supported in current build");
	}
#endif /* SO_BINDTODEVICE */
}

bool socket_nonblock_or_close(const int fd)
{
	if (!socket_set_nonblock(fd)) {
		socket_close(fd);
		return false;
	}
	return true;
}

void accept_backoff(
	struct ev_loop *loop, ev_io *restrict w_accept,
	ev_timer *restrict w_timer, const int err)
{
	LOGE_F("accept: (%d) %s", err, strerror(err));
	/* sleep for a while, see listener_cb */
	ev_io_stop(loop, w_accept);
	if (!ev_is_active(w_timer)) {
		ev_timer_start(loop, w_timer);
	}
}

void tcp_apply_conf(const int fd, const struct config *restrict conf)
{
	(void)socket_set_tcp(fd, conf->tcp_nodelay, conf->tcp_keepalive);
	(void)socket_set_buffer(fd, conf->tcp_sndbuf, conf->tcp_rcvbuf);
}

static bool split_addrstr(
	const char *restrict addrstr, char *restrict buf,
	char **restrict hoststr, char **restrict portstr)
{
	const size_t addrlen = strlen(addrstr);
	if (addrlen >= FQDN_MAX_LENGTH + sizeof(":65535")) {
		LOGE_F("address too long: `%s'", addrstr);
		return false;
	}
	memcpy(buf, addrstr, addrlen + 1);
	return splithostport(buf, hoststr, portstr);
}

bool resolve_addr(
	union sockaddr_max *restrict addr, const char *restrict addrstr,
	const enum sa_resolve_type type)
{
	char buf[FQDN_MAX_LENGTH + sizeof(":65535")];
	char *hoststr, *portstr;
	if (!split_addrstr(addrstr, buf, &hoststr, &portstr)) {
		return false;
	}
	return sa_resolve(addr, hoststr, portstr, type, PF_UNSPEC);
}

bool resolve_bindaddr(
	union sockaddr_max *restrict addr, const char *restrict addrstr,
	const enum sa_resolve_type type)
{
	char buf[FQDN_MAX_LENGTH + sizeof(":65535")];
	char *hoststr, *portstr;
	if (!split_addrstr(addrstr, buf, &hoststr, &portstr)) {
		return false;
	}
	return sa_resolve_bind(addr, hoststr, portstr, type);
}

double thread_load(void)
{
	static thread_local struct {
		struct timespec monotime, cputime;
		bool set;
	} last = { .set = false };
	double load = -1;
	struct timespec monotime, cputime;
	if (!clock_monotonic(&monotime)) {
		return load;
	}
	if (!clock_thread(&cputime)) {
		return load;
	}
	if (last.set) {
		const int_fast64_t total =
			TIMESPEC_DIFF(monotime, last.monotime);
		const int_fast64_t busy = TIMESPEC_DIFF(cputime, last.cputime);
		if (busy > 0 && total > 0 && busy <= total) {
			load = (double)busy / (double)total;
		}
	}
	last.monotime = monotime;
	last.cputime = cputime;
	last.set = true;
	return load;
}
