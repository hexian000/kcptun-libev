/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "daemon.h"

#include "meta/intcast.h"
#include "utils/debug.h"
#include "utils/slog.h"

#if WITH_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void drop_privileges(const char *const identity)
{
	const size_t len = strlen(identity);
	if (len >= 1024) {
		FAILMSGF("user name is too long: `%s'", identity);
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

	/* Track "was it specified?" separately rather than sentinel-encoding it
	 * into uid_t/gid_t: (uid_t)-1 is a representable parse result, so an
	 * identity of "4294967295" would otherwise alias the sentinel and skip
	 * the drop entirely. */
	uid_t uid;
	gid_t gid;
	bool has_uid = false, has_gid = false;
	const struct passwd *pw = NULL;
	if (user != NULL) {
		char *endptr;
		const intmax_t uidvalue = strtoimax(user, &endptr, 10);
		if (endptr == user || *endptr ||
		    !INTCAST_CHECK(uid, uidvalue)) {
			/* search user database for user name */
			pw = getpwnam(user);
			if (pw == NULL) {
				FAILMSGF(
					"passwd: name `%s' does not exist",
					user);
			}
			LOGD_F("passwd: `%s' uid=%jd gid=%jd", user,
			       (intmax_t)pw->pw_uid, (intmax_t)pw->pw_gid);
			uid = pw->pw_uid;
		} else {
			uid = (uid_t)uidvalue;
		}
		has_uid = true;
	}

	if (group != NULL) {
		char *endptr;
		const intmax_t gidvalue = strtoimax(group, &endptr, 10);
		if (endptr == group || *endptr ||
		    !INTCAST_CHECK(gid, gidvalue)) {
			/* search group database for group name */
			const struct group *const gr = getgrnam(group);
			if (gr == NULL) {
				FAILMSGF(
					"group: name `%s' does not exist",
					group);
			}
			LOGD_F("group: `%s' gid=%jd", group,
			       (intmax_t)gr->gr_gid);
			gid = gr->gr_gid;
		} else {
			gid = (gid_t)gidvalue;
		}
		has_gid = true;
	} else if (user != NULL && colon != NULL) {
		/* group is not specified, search from user database */
		if (pw == NULL) {
			pw = getpwuid(uid);
			if (pw == NULL) {
				FAILMSGF(
					"passwd: user `%s' does not exist",
					user);
			}
			LOGD_F("passwd: `%s' uid=%jd gid=%jd", user,
			       (intmax_t)pw->pw_uid, (intmax_t)pw->pw_gid);
		}
		gid = pw->pw_gid;
		has_gid = true;
	}

	/* A requested privilege drop that cannot be completed must be fatal: a
	 * daemon that keeps its original (possibly root) credentials while
	 * reporting readiness is CWE-273. */
	if (!has_uid && !has_gid) {
		FAILMSGF(
			"invalid identity `%s': neither user nor group specified",
			identity);
	}
	if (setgroups(0, NULL) != 0) {
		const int err = errno;
		FAILMSGF(
			"unable to drop supplementary group privileges: (%d) %s",
			err, strerror(err));
	}
	if (has_gid) {
		LOGD_F("setgid: %jd", (intmax_t)gid);
		if (setgid(gid) != 0) {
			const int err = errno;
			FAILMSGF("setgid: (%d) %s", err, strerror(err));
		}
		if (setegid(gid) != 0) {
			const int err = errno;
			FAILMSGF("setegid: (%d) %s", err, strerror(err));
		}
	}
	if (has_uid) {
		LOGD_F("setuid: %jd", (intmax_t)uid);
		if (setuid(uid) != 0) {
			const int err = errno;
			FAILMSGF("setuid: (%d) %s", err, strerror(err));
		}
		if (seteuid(uid) != 0) {
			const int err = errno;
			FAILMSGF("seteuid: (%d) %s", err, strerror(err));
		}
	}
}

void daemonize(
	const char *const identity, const bool nochdir, const bool noclose)
{
	/* Create an anonymous pipe for communicating with daemon process. */
	int fd[2];
	if (pipe(fd) == -1) {
		const int err = errno;
		FAILMSGF("pipe: %s", strerror(err));
	}
	/* pipe() returns the lowest free descriptors, so if the caller pre-closed
	 * a standard fd an end can land on 0/1/2 -- exactly where the
	 * freopen("/dev/null", ...) below (when noclose is false) would reopen it,
	 * silently discarding the readiness message and making the parent report a
	 * spurious startup failure. Relocate both ends above the standard fds so
	 * noclose=false is safe regardless of the caller's open descriptors. */
	for (int i = 0; i < 2; i++) {
		if (fd[i] > STDERR_FILENO) {
			continue;
		}
		const int hi = fcntl(fd[i], F_DUPFD, STDERR_FILENO + 1);
		if (hi < 0) {
			const int err = errno;
			FAILMSGF("fcntl(F_DUPFD): %s", strerror(err));
		}
		(void)close(fd[i]);
		fd[i] = hi;
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
			/* Wait for the daemon process to signal readiness. If it
			 * exits or crashes first instead, the pipe closes with no
			 * message and this read() returns 0 (EOF), which the CHECK
			 * below reports as a startup failure. Retry on EINTR so a
			 * signal during startup does not spuriously abort the
			 * parent (matching the grandchild's write loop below). */
			ssize_t nread;
			do {
				nread = read(fd[0], buf, sizeof(buf));
			} while (nread < 0 && errno == EINTR);
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
		LOGW_F("setsid: (%d) %s", err, strerror(err));
	}
	/* In the child, call fork() again. */
	{
		const pid_t pid = fork();
		if (pid < 0) {
			const int err = errno;
			FAILMSGF("fork: %s", strerror(err));
		} else if (pid > 0) {
			/* Terminate the intermediate child with _exit(), not
			 * exit(): it shares (via fork) the original process's stdio
			 * buffers and atexit registrations, so a full exit() would
			 * double-flush any buffered output and run those handlers in
			 * this throwaway process. */
			_exit(EXIT_SUCCESS);
		}
	}
	/* In the daemon process, connect /dev/null to standard input, output, and error. */
	if (!noclose) {
		CHECK(freopen("/dev/null", "r", stdin) == stdin);
		CHECK(freopen("/dev/null", "w", stdout) == stdout);
		CHECK(freopen("/dev/null", "w", stderr) == stderr);
	}
	/* In the daemon process, reset the umask to 0. */
	(void)umask(0);
	/* In the daemon process, change the current directory to the
           root directory (/), in order to avoid that the daemon
           involuntarily blocks mount points from being unmounted. */
	if (!nochdir) {
		if (chdir("/") != 0) {
			const int err = errno;
			LOGW_F("chdir: (%d) %s", err, strerror(err));
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
		size_t written = 0;
		const size_t len = (size_t)n;
		while (written < len) {
			/* write(2) may complete partially or be interrupted by a
			 * signal; retry until len bytes are written or a genuine
			 * (non-EINTR) error occurs. */
			const ssize_t ret =
				write(fd[1], buf + written, len - written);
			if (ret < 0) {
				const int err = errno;
				CHECK(err == EINTR);
				continue;
			}
			written += (size_t)ret;
		}
	}
	/* Close the anonymous pipe. */
	(void)close(fd[1]);
}

int systemd_notify(const char *const state)
{
#if WITH_SYSTEMD
	return sd_notify(0, state);
#else
	(void)state;
	return -1;
#endif
}
