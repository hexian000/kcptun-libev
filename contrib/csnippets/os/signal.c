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

/* AddressSanitizer instrumentation inflates stack frames several-fold, so the
 * crash handlers' alternate stack must be sized larger when built with it, or
 * the instrumented handler chain overflows a stack budgeted for release code
 * and double-faults to SIGSEGV -- defeating the very SA_ONSTACK protection the
 * alternate stack exists to provide. */
#if defined(__SANITIZE_ADDRESS__)
#define CRASH_ALTSTACK_INSTRUMENTED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define CRASH_ALTSTACK_INSTRUMENTED 1
#endif
#endif
#ifndef CRASH_ALTSTACK_INSTRUMENTED
#define CRASH_ALTSTACK_INSTRUMENTED 0
#endif

/* A dedicated stack for the crash handlers. The single most common SIGSEGV a
 * crash tracer exists to capture -- stack exhaustion from runaway recursion --
 * leaves no room on the faulting stack for the handler's own frames
 * (LOG_STACK_F alone reserves a DEBUG_STACK_MAXDEPTH-entry pc buffer), so
 * without SA_ONSTACK the handler double-faults and the process dies untraced.
 * Set up once alongside the first crashhandler_install() and torn down on
 * uninstall, saving and restoring any alternate stack the calling thread
 * already had rather than clobbering it. sigaltstack is per-thread, so this
 * covers only the installing thread; a guarded fault on another thread still
 * runs on that thread's own stack. */
static void *crash_altstack;
static stack_t crash_prev_altstack;

static size_t crash_altstack_size(void)
{
	size_t size = (size_t)SIGSTKSZ + DEBUG_STACK_MAXDEPTH * sizeof(void *);
#if CRASH_ALTSTACK_INSTRUMENTED
	/* the instrumented handler chain needs several times the room */
	size *= 4;
#endif
	return size;
}

static void crash_altstack_setup(void)
{
	if (crash_altstack != NULL) {
		return; /* already installed */
	}
	const size_t altsize = crash_altstack_size();
	void *const base = malloc(altsize);
	if (base == NULL) {
		return; /* fall back to the faulting stack (no SA_ONSTACK) */
	}
	const stack_t ss = {
		.ss_sp = base,
		.ss_size = altsize,
		.ss_flags = 0,
	};
	/* capture the caller's previous alternate stack so uninstall can put it
	 * back instead of discarding it */
	if (sigaltstack(&ss, &crash_prev_altstack) != 0) {
		LOG_PERROR("sigaltstack");
		free(base);
		return;
	}
	crash_altstack = base;
}

static void crash_altstack_teardown(void)
{
	if (crash_altstack == NULL) {
		return;
	}
	/* restore whatever alternate stack was effective before install rather
	 * than forcing SS_DISABLE, so a consumer's own SA_ONSTACK stack is left
	 * intact. A previously-disabled stack reports an unspecified
	 * ss_sp/ss_size (POSIX), so rebuild a clean descriptor for that case. */
	stack_t ss = crash_prev_altstack;
	if ((ss.ss_flags & SS_DISABLE) != 0) {
		ss = (stack_t){ .ss_sp = NULL,
				.ss_size = 0,
				.ss_flags = SS_DISABLE };
	}
	if (sigaltstack(&ss, NULL) != 0) {
		LOG_PERROR("sigaltstack");
	}
	free(crash_altstack);
	crash_altstack = NULL;
}

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
	crash_altstack_setup();
	struct sigaction act = { .sa_handler = sighandler_crash };
	/* run the handlers on the alternate stack if one was installed, so a
	 * stack-overflow fault still leaves room for the handler to report it */
	if (crash_altstack != NULL) {
		act.sa_flags = SA_ONSTACK;
	}
	/* POSIX requires a sigset_t be initialized with sigemptyset/sigfillset
	 * before use rather than relying on an all-zero value meaning empty */
	(void)sigemptyset(&act.sa_mask);
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
	crash_altstack_teardown();
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
