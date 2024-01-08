/* kcptun-libev (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "util.h"
#include "math/rand.h"
#include "utils/slog.h"
#include "utils/debug.h"
#include "utils/minmax.h"
#include "utils/mcache.h"
#include "crypto.h"
#include "pktqueue.h"

#include "ikcp.h"

#include <ev.h>
#include <unistd.h>
#include <pwd.h>
#if _BSD_SOURCE || _GNU_SOURCE
#include <grp.h>
#endif

#include <assert.h>
#include <locale.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

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

struct mcache *msgpool;

void init(int argc, char **argv)
{
	UNUSED(argc);
	UNUSED(argv);

	(void)setlocale(LC_ALL, "");
	slog_setoutput(SLOG_OUTPUT_FILE, stdout);

	struct sigaction ignore = {
		.sa_handler = SIG_IGN,
	};
	if (sigaction(SIGPIPE, &ignore, NULL) != 0) {
		const int err = errno;
		FAILMSGF("sigaction: %s", strerror(err));
	}
}

static void unloadlibs(void);

void loadlibs(void)
{
	{
		static bool loaded = false;
		if (loaded) {
			return;
		}
		loaded = true;

		const int ret = atexit(unloadlibs);
		if (ret != 0) {
			FAILMSGF("atexit: %d", ret);
		}
	}

	LOGD_F("libev: %d.%d", ev_version_major(), ev_version_minor());

#if WITH_CRYPTO
	crypto_init();
	srand64(((uint64_t)crypto_rand32() << 32u) | crypto_rand32());
#else
	srand64((uint64_t)clock_monotonic());
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
	fprintf(stdout, "%s\n", key);
	fflush(stdout);
	crypto_free(crypto);
}
#endif

void drop_privileges(const char *user)
{
	if (getuid() != 0) {
		return;
	}
	struct passwd *restrict pw = getpwnam(user);
	if (pw == NULL) {
		LOGW_F("su: user \"%s\" does not exist ", user);
		return;
	}
	if (pw->pw_uid == 0) {
		return;
	}
	LOGI_F("su: user=%s uid=%jd gid=%jd", user, (intmax_t)pw->pw_uid,
	       (intmax_t)pw->pw_gid);
#if _BSD_SOURCE || _GNU_SOURCE
	if (setgroups(0, NULL) != 0) {
		const int err = errno;
		LOGW_F("unable to drop supplementary group privileges: %s",
		       strerror(err));
	}
#endif
	if (setgid(pw->pw_gid) != 0 || setegid(pw->pw_gid) != 0) {
		const int err = errno;
		LOGW_F("unable to drop group privileges: %s", strerror(err));
	}
	if (setuid(pw->pw_uid) != 0 || seteuid(pw->pw_uid) != 0) {
		const int err = errno;
		LOGW_F("unable to drop user privileges: %s", strerror(err));
	}
}

void daemonize(const char *user, const bool nochdir, const bool noclose)
{
	/* Create an anonymous pipe for communicating with daemon process. */
	int fd[2];
	if (pipe(fd) == -1) {
		const int err = errno;
		FAILMSGF("pipe: %s", strerror(err));
	}
	/* First fork(). */
	{
		const pid_t pid = fork();
		if (pid < 0) {
			const int err = errno;
			FAILMSGF("fork: %s", strerror(err));
		} else if (pid > 0) {
			(void)close(fd[1]);
			char buf[256];
			/* Wait for the daemon process to be started. */
			const ssize_t nread = read(fd[0], buf, sizeof(buf));
			CHECK(nread > 0);
			LOGI_F("%.*s", (int)nread, buf);
			/* Finally, call exit() in the original process. */
			exit(EXIT_SUCCESS);
		} else {
			(void)close(fd[0]);
		}
	}
	/* In the child, call setsid(). */
	if (setsid() < 0) {
		const int err = errno;
		LOGW_F("setsid: %s", strerror(err));
	}
	/* In the child, call fork() again. */
	{
		const pid_t pid = fork();
		if (pid < 0) {
			const int err = errno;
			FAILMSGF("fork: %s", strerror(err));
		} else if (pid > 0) {
			/* Call exit() in the first child. */
			exit(EXIT_SUCCESS);
		}
	}
	/* In the daemon process, connect /dev/null to standard input, output, and error. */
	if (!noclose) {
		FILE *f;
		f = freopen("/dev/null", "r", stdin);
		assert(f == stdin);
		f = freopen("/dev/null", "w", stdout);
		assert(f == stdout);
		f = freopen("/dev/null", "w", stderr);
		assert(f == stderr);
		(void)f;
	}
	/* In the daemon process, reset the umask to 0. */
	(void)umask(0);
	/* In the daemon process, change the current directory to the
           root directory (/), in order to avoid that the daemon
           involuntarily blocks mount points from being unmounted. */
	if (!nochdir) {
		if (chdir("/") != 0) {
			const int err = errno;
			LOGW_F("chdir: %s", strerror(err));
		}
	}
	/* In the daemon process, drop privileges */
	if (user != NULL) {
		drop_privileges(user);
	}
	/* From the daemon process, notify the original process started
           that initialization is complete. */
	{
		char buf[256];
		const int n = snprintf(
			buf, sizeof(buf),
			"daemon process has started with pid %jd",
			(intmax_t)getpid());
		assert(n > 0 && (size_t)n < sizeof(buf));
		const ssize_t nwritten = write(fd[1], buf, n);
		assert(nwritten == n);
		(void)nwritten;
	}
	/* Close the anonymous pipe. */
	(void)close(fd[1]);

	/* Set logging output to syslog. */
	slog_setoutput(SLOG_OUTPUT_SYSLOG, "kcptun-libev");
}
