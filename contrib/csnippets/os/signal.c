/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "signal.h"

#include "meta/arraysize.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>

struct sigmap_entry {
	int signo;
	const char *str;
};

/* read by sighandler_crash() (inside a signal handler) and read/written by
 * crashhandler_install()/crashhandler_uninstall() (ordinary thread context);
 * left unsynchronized by design, see the caller contract in signal.h -- a
 * signal handler cannot safely take a lock, and delivery of a guarded
 * signal races the OS scheduler, not any userspace acquire/release. */
static struct {
	struct sigaction oact;
	int signo;
	bool installed;
} sighandlers[] = {
	{ { .sa_handler = SIG_DFL }, SIGQUIT, false },
	{ { .sa_handler = SIG_DFL }, SIGILL, false },
	{ { .sa_handler = SIG_DFL }, SIGTRAP, false },
	{ { .sa_handler = SIG_DFL }, SIGABRT, false },
	{ { .sa_handler = SIG_DFL }, SIGBUS, false },
	{ { .sa_handler = SIG_DFL }, SIGFPE, false },
	{ { .sa_handler = SIG_DFL }, SIGSEGV, false },
	{ { .sa_handler = SIG_DFL }, SIGSYS, false },
};
#define NUM_SIGHANDLERS ARRAY_SIZE(sighandlers)

static void sighandler_crash(const int signo)
{
	const char *const sigstr = os_strsignal(signo);
	if (sigstr != NULL) {
		LOG_STACK_F(FATAL, 2, "DEADLY SIGNAL: (%d) %s", signo, sigstr);
	} else {
		LOG_STACK_F(FATAL, 2, "DEADLY SIGNAL: (%d)", signo);
	}
	size_t idx = NUM_SIGHANDLERS;
	for (size_t i = 0; i < NUM_SIGHANDLERS; i++) {
		if (sighandlers[i].signo == signo) {
			idx = i;
			break;
		}
	}
	const struct sigaction *const act =
		idx < NUM_SIGHANDLERS ? &sighandlers[idx].oact : NULL;
	if (sigaction(signo, act, NULL) != 0) {
		LOG_PERROR("sigaction");
		_Exit(EXIT_FAILURE);
	}
	if (idx < NUM_SIGHANDLERS) {
		/* the original disposition is live again; a later
		 * crashhandler_install() must re-capture and re-arm this
		 * signal instead of skipping it as still installed. */
		sighandlers[idx].installed = false;
		sighandlers[idx].oact =
			(struct sigaction){ .sa_handler = SIG_DFL };
	}
	if (raise(signo)) {
		_Exit(EXIT_FAILURE);
	}
}

/* the first capture lazily allocates internal resources, which is not
 * async-signal-safe; capture once beforehand and verify it works */
static bool probe_backtrace(void)
{
	void *frames[DEBUG_STACK_MAXDEPTH];
	return debug_backtrace(frames, 0, DEBUG_STACK_MAXDEPTH) > 0;
}

void crashhandler_install(void)
{
	if (!probe_backtrace()) {
		LOGW("crash handler not installed: backtrace unavailable");
		return;
	}
	const struct sigaction act = { .sa_handler = sighandler_crash };
	for (size_t i = 0; i < NUM_SIGHANDLERS; i++) {
		if (sighandlers[i].installed) {
			/* already captured; re-installing would overwrite
			 * oact with the crash handler itself */
			continue;
		}
		const int signo = sighandlers[i].signo;
		struct sigaction *const oact = &sighandlers[i].oact;
		if (sigaction(signo, &act, oact) != 0) {
			LOG_PERROR("sigaction");
			continue;
		}
		sighandlers[i].installed = true;
	}
}

void crashhandler_uninstall(void)
{
	for (size_t i = 0; i < NUM_SIGHANDLERS; i++) {
		if (!sighandlers[i].installed) {
			/* never captured (install skipped or failed for this
			 * signal); nothing of ours to restore */
			continue;
		}
		const int signo = sighandlers[i].signo;
		struct sigaction *const oact = &sighandlers[i].oact;
		if (sigaction(signo, oact, NULL) != 0) {
			LOG_PERROR("sigaction");
			continue;
		}
		sighandlers[i].installed = false;
		sighandlers[i].oact =
			(struct sigaction){ .sa_handler = SIG_DFL };
	}
}

const char *os_strsignal(const int signo)
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

	/* Linear scan: the table is small and this is not a hot path, and it
	 * avoids bsearch's requirement that sigmap be sorted ascending by signo
	 * -- an ordering nothing here enforces, which would silently break on a
	 * platform whose signal numbers are assigned in a different order. */
	for (size_t i = 0; i < ARRAY_SIZE(sigmap); i++) {
		if (sigmap[i].signo == signo) {
			return sigmap[i].str;
		}
	}
	return NULL;
}
