/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef OS_SIGNAL_H
#define OS_SIGNAL_H

#include <stdbool.h>

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
 */
void crashhandler_install(void);

/**
 * @brief Uninstall crash signal handlers and restore original handlers.
 *
 * This function restores the original signal handlers for the signals
 * handled by crashhandler_install.
 */
void crashhandler_uninstall(void);

/**
 * @brief Convert a signal number to a string description.
 *
 * This function returns a string describing the signal with the given number.
 * Only POSIX-defined signals are supported. For unknown signals, NULL is returned.
 *
 * @param signo The signal number.
 * @return A pointer to a string describing the signal, or NULL if unknown.
 *
 * @note This is a POSIX-compatible alternative to strsignal().
 */
const char *os_strsignal(int signo);

/** @} */

#endif /* OS_SIGNAL_H */
