/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef OS_DAEMON_H
#define OS_DAEMON_H

#include <stdbool.h>

/**
 * @defgroup daemon
 * @brief Utilities for daemonizing processes and dropping privileges.
 * @{
 */

/**
 * @brief Drop privileges to the specified user and group.
 * @param identity The user and group identity in the format "user:group" or
 *     "user"; at least one of the two must be specified.
 * @note How the primary group is resolved depends on the identity form,
 *     mirroring chown(1)'s "user" vs "user:" distinction: "user:group" sets the
 *     gid to @p group; a trailing colon "user:" sets it to @p user's login
 *     group from the passwd database; a bare "user" (no colon) sets the uid
 *     only and leaves the primary gid untouched. Supplementary groups are
 *     always cleared. Retaining the primary gid for a bare "user" is
 *     security-relevant: a process started as root with identity "user" keeps
 *     gid 0 and can still reach root-group-owned files (the incomplete-drop
 *     side of CWE-273), so pass "user:" or "user:group" when the primary group
 *     must be dropped as well.
 * @note Requires POSIX.1-2001 for seteuid and setegid, and a BSD/glibc
 *       extension (_DEFAULT_SOURCE or equivalent, defined by the build
 *       system for daemon.c) for setgroups.
 * @note Does not return on failure: any error -- an unresolvable name, a
 *     getpwuid miss, or a failing setgroups/setgid/setuid -- aborts the
 *     process. This is deliberate. A requested privilege drop that cannot be
 *     completed must be fatal, since continuing with the original (possibly
 *     root) credentials is CWE-273.
 */
void drop_privileges(const char *identity);

/**
 * @brief Daemonize the current process. A POSIX-compliant replacement for
 *     the BSD daemon(3).
 * @param identity The user and group to drop privileges to, or NULL.
 * @param nochdir If true, do not change the current directory to /.
 * @param noclose If true, do not redirect stdin, stdout, stderr to /dev/null.
 * @note Performs the classic double-fork idiom (fork, setsid, fork
 *     again), so the final daemon process is never a session leader and
 *     cannot inadvertently reacquire a controlling terminal.
 * @note Only returns in the final daemon process; the original process
 *     blocks until that process confirms it is running, then exits.
 * @note Resets the daemon process's umask to 0, unconditionally and with no
 *     way to opt out; the previous mask is discarded, not returned. This
 *     diverges from BSD daemon(3), which does not touch it, and is
 *     security-relevant: a file the daemon later creates with the customary
 *     0666 lands world-writable, so callers that care must set their own
 *     umask after this returns.
 * @note Does not return on failure: a failing pipe, fork or freopen, or a
 *     daemon process that dies before confirming startup, aborts the process.
 *     If identity is non-NULL, drop_privileges' own fatal failures apply too.
 * @note Requires POSIX.1-1990 for setsid.
 */
void daemonize(const char *identity, bool nochdir, bool noclose);

#define DAEMON_SYSTEMD_STATE_READY "READY=1"
#define DAEMON_SYSTEMD_STATE_STOPPING "STOPPING=1"
#define DAEMON_SYSTEMD_STATE_RELOADING "RELOADING=1"
#define DAEMON_SYSTEMD_STATE_WATCHDOG "WATCHDOG=1"

/**
 * @brief Send a state notification to systemd.
 * @param state The state string to notify, e.g., DAEMON_SYSTEMD_STATE_READY.
 * @return >0 on successfully notified, 0 if systemd is not running, <0 on error.
 */
int systemd_notify(const char *state);

/** @} */

#endif /* OS_DAEMON_H */
