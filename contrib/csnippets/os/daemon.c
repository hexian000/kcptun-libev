/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "daemon.h"

#include "utils/debug.h"
#include "utils/intcast.h"
#include "utils/slog.h"

#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#if WITH_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void drop_privileges(const char *identity)
{
	const size_t len = strlen(identity);
	if (len >= 1024) {
		LOGE_F("user name is too long: `%s'", identity);
		return;
	}
	char buf[len + 1];
	memcpy(buf, identity, len + 1);

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
		if (*endptr || !INTCAST_CHECK(uid, uidvalue)) {
			/* search user database for user name */
			pw = getpwnam(user);
			if (pw == NULL) {
				LOGE_F("passwd: name `%s' does not exist",
				       user);
				return;
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
		if (*endptr || !INTCAST_CHECK(gid, gidvalue)) {
			/* search group database for group name */
			const struct group *gr = getgrnam(group);
			if (gr == NULL) {
				LOGE_F("group: name `%s' does not exist",
				       group);
				return;
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
				return;
			}
			LOGD_F("passwd: `%s' uid=%jd gid=%jd", user,
			       (intmax_t)pw->pw_uid, (intmax_t)pw->pw_gid);
		}
		gid = pw->pw_gid;
	}

#if _BSD_SOURCE || _GNU_SOURCE
	if (setgroups(0, NULL) != 0) {
		const int err = errno;
		LOGW_F("unable to drop supplementary group privileges: %s",
		       strerror(err));
	}
#endif
	if (gid != (gid_t)-1) {
		LOGD_F("setgid: %jd", (intmax_t)gid);
		if (setgid(gid) != 0 || setegid(gid) != 0) {
			const int err = errno;
			LOGW_F("unable to drop group privileges: %s",
			       strerror(err));
		}
	}
	if (uid != (uid_t)-1) {
		LOGD_F("setuid: %jd", (intmax_t)uid);
		if (setuid(uid) != 0 || seteuid(uid) != 0) {
			const int err = errno;
			LOGW_F("unable to drop user privileges: %s",
			       strerror(err));
		}
	}
}

void daemonize(const char *identity, const bool nochdir, const bool noclose)
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
	if (identity != NULL) {
		drop_privileges(identity);
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
}

int systemd_notify(const char *state)
{
#if WITH_SYSTEMD
	return sd_notify(0, state);
#else
	(void)state;
	return -1;
#endif
}
