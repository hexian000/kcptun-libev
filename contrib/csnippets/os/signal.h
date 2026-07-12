/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef OS_SIGNAL_H
#define OS_SIGNAL_H

/**
 * @defgroup signal
 * @brief Utilities for signal handling and crash management.
 * @{
 */

/**
 * @brief Install crash signal handlers for fatal signals.
 *
 * This function installs custom signal handlers for signals that typically
 * indicate program crashes (SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGBUS,
 * SIGFPE, SIGSEGV, SIGSYS). The handlers log the signal and re-raise it.
 *
 * @note Requires POSIX.1-2001 due to SIGBUS and SIGSYS signals.
 * @note Installs no handlers if capturing a stack backtrace does not work.
 * @note Safe to call again while already installed: signals already
 *   captured by a previous call are left untouched.
 * @note Not safe to call concurrently with itself, with
 *   crashhandler_uninstall(), or while any thread could still raise one of
 *   the guarded signals: the internal bookkeeping is read and written
 *   without synchronization, and a signal handler cannot safely take a
 *   lock to protect it. Call once, during single-threaded startup, before
 *   spawning any thread that could raise a guarded signal.
 */
void crashhandler_install(void);

/**
 * @brief Uninstall crash signal handlers and restore original handlers.
 * @note Restores exactly the signals installed by crashhandler_install.
 * @note Same caller restrictions as crashhandler_install(): not safe to
 *   call concurrently with itself, with crashhandler_install(), or while
 *   any thread could still raise one of the guarded signals. Call once,
 *   during single-threaded teardown, after joining any such thread.
 */
void crashhandler_uninstall(void);

/**
 * @brief Convert a signal number to a string description.
 * @param signo The signal number.
 * @return A pointer to a string describing the signal, or NULL if unknown.
 * @note Only POSIX-defined signals are supported; a POSIX-compatible
 *   alternative to strsignal().
 */
const char *os_strsignal(int signo);

/** @} */

#endif /* OS_SIGNAL_H */
