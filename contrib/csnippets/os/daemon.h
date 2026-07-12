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
 * @param identity The user and group identity in the format "user:group" or "user".
 * @note Requires POSIX.1-2001 for seteuid and setegid, and a BSD/glibc
 *       extension (_DEFAULT_SOURCE or equivalent, defined by the build
 *       system for daemon.c) for setgroups.
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
