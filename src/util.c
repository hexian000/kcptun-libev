/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "util.h"

#include "crypto.h"
#include "os/socket.h"
#include "pktqueue.h"

#include "math/rand.h"
#include "net/addr.h"
#include "os/clock.h"
#include "utils/debug.h"
#include "utils/mcache.h"
#include "utils/minmax.h"
#include "utils/slog.h"

#include "ikcp.h"

#include <ev.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <signal.h>
#include <unistd.h>

#include <errno.h>
#include <inttypes.h>
#include <locale.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

void init(int argc, char **argv)
{
	UNUSED(argc);
	UNUSED(argv);
	(void)setlocale(LC_ALL, "");
	(void)setvbuf(stdout, NULL, _IONBF, 0);
	slog_setoutput(SLOG_OUTPUT_FILE, stdout);
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

	const size_t size =
		MAX(sizeof(struct IKCPSEG) + MAX_PACKET_SIZE,
		    sizeof(struct msgframe));
	msgpool = mcache_new(MMSG_BATCH_SIZE * 2, size);
	CHECKOOM(msgpool);
	ikcp_segment_pool = msgpool;
}

void unloadlibs(void)
{
	mcache_free(msgpool);
	ikcp_segment_pool = msgpool = NULL;
}

#if WITH_CRYPTO
void genpsk(const char *method)
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
#endif

/** Read a timespec as signed 64-bit nanoseconds. */
#define READ_TIMESPEC(ts)                                                      \
	((int_fast64_t)(ts).tv_sec * INT64_C(1000000000) +                     \
	 (int_fast64_t)(ts).tv_nsec)

double thread_load(void)
{
	static _Thread_local struct {
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
			READ_TIMESPEC(monotime) - READ_TIMESPEC(last.monotime);
		const int_fast64_t busy =
			READ_TIMESPEC(cputime) - READ_TIMESPEC(last.cputime);
		if (busy > 0 && total > 0 && busy <= total) {
			load = (double)busy / (double)total;
		}
	}
	last.monotime = monotime;
	last.cputime = cputime;
	last.set = true;
	return load;
}

#undef READ_TIMESPEC

void socket_bind_netdev(const int fd, const char *restrict netdev)
{
#ifdef SO_BINDTODEVICE
	char ifname[IFNAMSIZ];
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
		LOGW_F("SO_BINDTODEVICE: %s", "not supported in current build");
	}
#endif
}
