/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "signal.h"

#include "utils/debug.h"

#include <signal.h>
#include <stdlib.h>

struct sigmap_entry {
	int signo;
	const char *str;
};

static int compare_signo(const void *key, const void *element)
{
	int signo_key = *(const int *)key;
	const struct sigmap_entry *entry = element;
	return signo_key - entry->signo;
}

const char *os_strsignal(int signo)
{
	static const struct sigmap_entry sigmap[] = {
		{ SIGHUP, "Hangup" },
		{ SIGINT, "Interrupt" },
		{ SIGQUIT, "Quit" },
		{ SIGILL, "Illegal instruction" },
		{ SIGTRAP, "Trace/breakpoint trap" },
		{ SIGABRT, "Aborted" },
		{ SIGBUS, "Bus error" },
		{ SIGFPE, "Floating point exception" },
		{ SIGKILL, "Killed" },
		{ SIGUSR1, "User defined signal 1" },
		{ SIGSEGV, "Segmentation fault" },
		{ SIGUSR2, "User defined signal 2" },
		{ SIGPIPE, "Broken pipe" },
		{ SIGALRM, "Alarm clock" },
		{ SIGTERM, "Terminated" },
		{ SIGCHLD, "Child exited" },
		{ SIGCONT, "Continued" },
		{ SIGSTOP, "Stopped (signal)" },
		{ SIGTSTP, "Stopped" },
		{ SIGTTIN, "Stopped (tty input)" },
		{ SIGTTOU, "Stopped (tty output)" },
		{ SIGURG, "Urgent I/O condition" },
		{ SIGSYS, "Bad system call" },
	};

	const struct sigmap_entry *result =
		bsearch(&signo, sigmap, sizeof(sigmap) / sizeof(sigmap[0]),
			sizeof(sigmap[0]), compare_signo);
	return result ? result->str : NULL;
}

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
#define NUM_SIGHANDLERS (sizeof(sighandlers) / sizeof(sighandlers[0]))

static void sighandler_crash(const int signo)
{
	const char *sigstr = os_strsignal(signo);
	if (sigstr != NULL) {
		LOG_STACK_F(FATAL, 2, "DEADLY SIGNAL: (%d) %s", signo, sigstr);
	} else {
		LOG_STACK_F(FATAL, 2, "DEADLY SIGNAL: (%d)", signo);
	}
	struct sigaction *act = NULL;
	for (size_t i = 0; i < NUM_SIGHANDLERS; i++) {
		if (sighandlers[i].signo == signo) {
			act = &sighandlers[i].oact;
			break;
		}
	}
	if (sigaction(signo, act, NULL) != 0) {
		LOG_PERROR("sigaction");
		_Exit(EXIT_FAILURE);
	}
	if (raise(signo)) {
		_Exit(EXIT_FAILURE);
	}
}

void crashhandler_install(void)
{
	struct sigaction act = { .sa_handler = sighandler_crash };
	for (size_t i = 0; i < NUM_SIGHANDLERS; i++) {
		const int signo = sighandlers[i].signo;
		struct sigaction *oact = &sighandlers[i].oact;
		if (sigaction(signo, &act, oact) != 0) {
			LOG_PERROR("sigaction");
		}
	}
}

void crashhandler_uninstall(void)
{
	for (size_t i = 0; i < NUM_SIGHANDLERS; i++) {
		const int signo = sighandlers[i].signo;
		struct sigaction *oact = &sighandlers[i].oact;
		if (sigaction(signo, oact, NULL) != 0) {
			LOG_PERROR("sigaction");
			continue;
		}
		sighandlers[i].oact =
			(struct sigaction){ .sa_handler = SIG_DFL };
	}
}
