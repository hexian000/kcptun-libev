/* kcptun-libev (c) 2019-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "util.h"

#include "crypto.h"
#include "pktqueue.h"

#include "math/rand.h"
#include "utils/arraysize.h"
#include "utils/debug.h"
#include "utils/intbound.h"
#include "utils/mcache.h"
#include "utils/minmax.h"
#include "utils/slog.h"

#include "ikcp.h"

#include <ev.h>

#include <grp.h>
#include <pwd.h>
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

#if WITH_CRASH_HANDLER
static struct {
	int signo;
	struct sigaction oact;
} sighandlers[] = {
	{ SIGQUIT, { .sa_handler = SIG_DFL } },
	{ SIGILL, { .sa_handler = SIG_DFL } },
	{ SIGTRAP, { .sa_handler = SIG_DFL } },
	{ SIGABRT, { .sa_handler = SIG_DFL } },
	{ SIGBUS, { .sa_handler = SIG_DFL } },
	{ SIGFPE, { .sa_handler = SIG_DFL } },
	{ SIGSEGV, { .sa_handler = SIG_DFL } },
	{ SIGSYS, { .sa_handler = SIG_DFL } },
};

static void crash_handler(const int signo)
{
	LOG_STACK_F(FATAL, 2, "FATAL ERROR: %s", strsignal(signo));
	struct sigaction *act = NULL;
	for (size_t i = 0; i < ARRAY_SIZE(sighandlers); i++) {
		if (sighandlers[i].signo == signo) {
			act = &sighandlers[i].oact;
			break;
		}
	}
	if (sigaction(signo, act, NULL) != 0) {
		LOGE_F("sigaction: %s", strerror(errno));
		_Exit(EXIT_FAILURE);
	}
	if (raise(signo)) {
		_Exit(EXIT_FAILURE);
	}
}

static void set_crash_handler(void)
{
	struct sigaction act = {
		.sa_handler = crash_handler,
	};
	for (size_t i = 0; i < ARRAY_SIZE(sighandlers); i++) {
		const int signo = sighandlers[i].signo;
		struct sigaction *oact = &sighandlers[i].oact;
		if (sigaction(signo, &act, oact) != 0) {
			LOGE_F("sigaction: %s", strerror(errno));
		}
	}
}
#endif /* WITH_CRASH_HANDLER */

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
	set_crash_handler();
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

bool parse_user(struct user_ident *ident, const char *s)
{
	const size_t len = strlen(s);
	if (len >= 1024) {
		LOGE_F("user name is too long: `%s'", s);
		return false;
	}
	char buf[len + 1];
	memcpy(buf, s, len + 1);

	const char *user = NULL, *group = NULL;
	char *const colon = strchr(buf, ':');
	if (colon != NULL) {
		if (colon != buf) {
			user = buf;
		}
		*colon = '\0';
		if (colon[1] != '\0') {
			group = &colon[1];
		}
	} else {
		user = buf;
		group = NULL;
	}

	uid_t uid = (uid_t)-1;
	gid_t gid = (gid_t)-1;
	const struct passwd *pw = NULL;
	if (user != NULL) {
		char *endptr;
		const intmax_t uidvalue = strtoimax(user, &endptr, 10);
		if (*endptr || !BOUNDCHECK_INT(uid, uidvalue)) {
			/* search user database for user name */
			pw = getpwnam(user);
			if (pw == NULL) {
				LOGE_F("passwd: name `%s' does not exist",
				       user);
				return false;
			}
			LOGD_F("passwd: `%s' uid=%jd gid=%jd", user,
			       (intmax_t)pw->pw_uid, (intmax_t)pw->pw_gid);
			uid = pw->pw_uid;
		} else {
			uid = (uid_t)uidvalue;
		}
	}

	if (group != NULL) {
		char *endptr;
		const intmax_t gidvalue = strtoimax(group, &endptr, 10);
		if (*endptr || !BOUNDCHECK_INT(gid, gidvalue)) {
			/* search group database for group name */
			const struct group *gr = getgrnam(group);
			if (gr == NULL) {
				LOGE_F("group: name `%s' does not exist",
				       group);
				return false;
			}
			LOGD_F("group: `%s' gid=%jd", group,
			       (intmax_t)gr->gr_gid);
			gid = gr->gr_gid;
		} else {
			gid = (gid_t)gidvalue;
		}
	} else if (user != NULL && colon != NULL) {
		/* group is not specified, search from user database */
		if (pw == NULL) {
			pw = getpwuid(uid);
			if (pw == NULL) {
				LOGE_F("passwd: user `%s' does not exist",
				       user);
				return false;
			}
			LOGD_F("passwd: `%s' uid=%jd gid=%jd", user,
			       (intmax_t)pw->pw_uid, (intmax_t)pw->pw_gid);
		}
		gid = pw->pw_gid;
	}
	if (ident != NULL) {
		*ident = (struct user_ident){
			.uid = uid,
			.gid = gid,
		};
	}
	return true;
}

void drop_privileges(const struct user_ident *restrict ident)
{
#if _BSD_SOURCE || _GNU_SOURCE
	if (setgroups(0, NULL) != 0) {
		LOGW_F("unable to drop supplementary group privileges: %s",
		       strerror(errno));
	}
#endif
	if (ident->gid != (gid_t)-1) {
		LOGD_F("setgid: %jd", (intmax_t)ident->gid);
		if (setgid(ident->gid) != 0 || setegid(ident->gid) != 0) {
			LOGW_F("unable to drop group privileges: %s",
			       strerror(errno));
		}
	}
	if (ident->uid != (uid_t)-1) {
		LOGD_F("setuid: %jd", (intmax_t)ident->uid);
		if (setuid(ident->uid) != 0 || seteuid(ident->uid) != 0) {
			LOGW_F("unable to drop user privileges: %s",
			       strerror(errno));
		}
	}
}

void daemonize(
	const struct user_ident *ident, const bool nochdir, const bool noclose)
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
			CLOSE_FD(fd[1]);
			char buf[256];
			/* Wait for the daemon process to be started. */
			const ssize_t nread = read(fd[0], buf, sizeof(buf));
			CHECK(nread > 0);
			LOGI_F("%.*s", (int)nread, buf);
			/* Finally, call exit() in the original process. */
			exit(EXIT_SUCCESS);
		} else {
			CLOSE_FD(fd[0]);
		}
	}
	/* In the child, call setsid(). */
	if (setsid() < 0) {
		LOGW_F("setsid: %s", strerror(errno));
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
		ASSERT(f == stdin);
		f = freopen("/dev/null", "w", stdout);
		ASSERT(f == stdout);
		f = freopen("/dev/null", "w", stderr);
		ASSERT(f == stderr);
		UNUSED(f);
	}
	/* In the daemon process, reset the umask to 0. */
	(void)umask(0);
	/* In the daemon process, change the current directory to the
           root directory (/), in order to avoid that the daemon
           involuntarily blocks mount points from being unmounted. */
	if (!nochdir) {
		if (chdir("/") != 0) {
			LOGW_F("chdir: %s", strerror(errno));
		}
	}
	/* In the daemon process, drop privileges */
	if (ident != NULL) {
		drop_privileges(ident);
	}
	/* From the daemon process, notify the original process started
           that initialization is complete. */
	{
		char buf[256];
		const int n = snprintf(
			buf, sizeof(buf),
			"daemon process has started with pid %jd",
			(intmax_t)getpid());
		ASSERT(n > 0 && (size_t)n < sizeof(buf));
		const ssize_t nwritten = write(fd[1], buf, n);
		ASSERT(nwritten == n);
		UNUSED(nwritten);
	}
	/* Close the anonymous pipe. */
	CLOSE_FD(fd[1]);

	/* Set logging output to syslog. */
	slog_setoutput(SLOG_OUTPUT_SYSLOG, "kcptun-libev");
}

double thread_load(void)
{
	static _Thread_local struct {
		struct timespec monotime, cputime;
		bool set;
	} last = { .set = false };
	double load = -1;
	struct timespec monotime, cputime;
	if (clock_gettime(CLOCK_MONOTONIC, &monotime)) {
		return load;
	}
	if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cputime)) {
		return load;
	}
	if (last.set) {
		const double total =
			(monotime.tv_sec - last.monotime.tv_sec) +
			(monotime.tv_nsec - last.monotime.tv_nsec) * 1e-9;
		const double busy =
			(cputime.tv_sec - last.cputime.tv_sec) +
			(cputime.tv_nsec - last.cputime.tv_nsec) * 1e-9;
		load = busy / total;
	}
	last.monotime = monotime;
	last.cputime = cputime;
	last.set = true;
	return load;
}
