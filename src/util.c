/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "util.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "utils/minmax.h"
#include "utils/mcache.h"
#include "crypto.h"
#include "pktqueue.h"
#include "kcp/ikcp.h"

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
#include <time.h>

uint32_t tstamp2ms(const ev_tstamp t)
{
	return (uint32_t)fmod(t * 1e+3, UINT32_MAX + 1.0);
}

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

static void uninit(void);

void init(void)
{
	{
		const int ret = atexit(uninit);
		if (ret != 0) {
			FAILMSGF("atexit: %d", ret);
		}
	}

	(void)setlocale(LC_ALL, "");

	struct sigaction ignore = {
		.sa_handler = SIG_IGN,
	};
	if (sigaction(SIGPIPE, &ignore, NULL) != 0) {
		const int err = errno;
		FAILMSGF("sigaction: %s", strerror(err));
	}

	const size_t size =
		MAX(sizeof(struct IKCPSEG) + MAX_PACKET_SIZE,
		    sizeof(struct msgframe));
	msgpool = mcache_new(256, size);
	CHECKOOM(msgpool);
	ikcp_segment_pool = msgpool;
}

void uninit(void)
{
	mcache_free(msgpool);
	ikcp_segment_pool = msgpool = NULL;
}

void daemonize(void)
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
			char buf[32];
			/* Wait for the daemon process to be started. */
			const ssize_t nread = read(fd[0], buf, sizeof(buf));
			CHECK(nread > 0);
			LOGI_F("daemon process has started with pid %.*s",
			       (int)nread, buf);
			/* Finally, call exit() in the original process. */
			exit(EXIT_SUCCESS);
		} else {
			(void)close(fd[0]);
		}
	}
	/* In the child, call setsid(). */
	if (setsid() < 0) {
		const int err = errno;
		LOGE_F("setsid: %s", strerror(err));
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
	FILE *f;
	f = freopen("/dev/null", "r", stdin);
	assert(f == stdin);
	f = freopen("/dev/null", "w", stdout);
	assert(f == stdout);
	f = freopen("/dev/null", "w", stderr);
	assert(f == stderr);
	(void)f;
	/* In the daemon process, reset the umask to 0. */
	(void)umask(0);
	/* From the daemon process, notify the original process started
           that initialization is complete. */
	char buf[32] = { 0 };
	const int n = snprintf(buf, sizeof(buf), "%jd", (intmax_t)getpid());
	assert(n > 0 && (size_t)n < sizeof(buf));
	const ssize_t nwritten = write(fd[1], buf, n);
	assert(nwritten == n);
	(void)nwritten;
	/* Close the anonymous pipe. */
	(void)close(fd[1]);

	/* Disable logging to avoid unnecessary string formatting. */
	slog_level = LOG_LEVEL_SILENCE;
}

void drop_privileges(const char *user)
{
	if (getuid() != 0) {
		return;
	}
	if (user == NULL) {
		LOGW("running as root, please consider set \"user\" field in config");
		return;
	}
	if (chdir("/") != 0) {
		const int err = errno;
		LOGW_F("chdir: %s", strerror(err));
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

#if WITH_CRYPTO
void genpsk(const char *method)
{
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
