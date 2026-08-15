/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "signal.h"

#include "meta/arraysize.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

struct sigmap_entry {
	int signo;
	const char *str;
};

/* Crash-signal bookkeeping, shared between sighandler_crash() (signal handler
 * context, possibly on several threads at once) and crashhandler_install()/
 * crashhandler_uninstall() (ordinary thread context). Per signal.h's caller
 * contract, install/uninstall never run concurrently with signal delivery, so
 * oact is written only outside a handler and read-only within one -- concurrent
 * handlers for one signal thus only read it, never a data race. installed is the
 * one field a handler writes, and two threads can fault on the same guarded
 * signal at once (sa_mask blocks only the current thread), so it is atomic; an
 * always-lock-free atomic keeps that access async-signal-safe. */
static struct {
	struct sigaction oact;
	int signo;
	atomic_bool installed;
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

static_assert(
	ATOMIC_BOOL_LOCK_FREE == 2,
	"sighandlers[].installed must be always lock-free so the crash "
	"handler's access to it stays async-signal-safe");
#if SLOG_MT_SAFE
static_assert(
	ATOMIC_INT_LOCK_FREE == 2,
	"slog_level_ is read by the crash handler's LOGLEVEL() gate, where "
	"ISO C11 7.14.1.1p5 admits an atomic access only if it is lock-free");
#endif

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

/* SIGSTKSZ is the system's budget for a *trivial* handler, but the report
 * below also runs the unwinder and the symbolizer on this stack, and neither
 * is trivial: measured high-water marks of debug_backtrace() +
 * debug_backtrace_fd() on x86-64 are ~5 KiB through glibc execinfo, plus the
 * ~2.3 KiB pc window debug_backtrace() keeps on that backend, ~8.5 KiB
 * through libbacktrace and ~11.5 KiB through libunwind (whose unw_cursor_t
 * alone is ~2 KiB and whose symbol lookup parses ELF with PATH_MAX-sized
 * buffers) -- already past SIGSTKSZ on its own. Budget that work separately
 * so the handler does not overflow the very stack it installed to survive a
 * stack overflow, writing past the allocation and corrupting the heap. */
#define CRASH_REPORT_STACKSZ 32768

static size_t crash_altstack_size(void)
{
	size_t size = (size_t)SIGSTKSZ + CRASH_REPORT_STACKSZ +
		      DEBUG_STACK_MAXDEPTH * sizeof(void *);
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
	/* the allocation is registered as an alternate signal stack on the
	 * thread that installed it, and sigaltstack is per-thread, so free it
	 * only once this thread no longer has it registered. If the active
	 * alternate stack here is not ours -- uninstall ran on a different
	 * thread than install, or a consumer swapped stacks -- leave the
	 * allocation in place: freeing memory still registered elsewhere would
	 * leave a later SA_ONSTACK delivery running on freed memory. */
	stack_t cur;
	if (sigaltstack(NULL, &cur) != 0) {
		LOG_PERROR("sigaltstack");
		return;
	}
	if ((cur.ss_flags & SS_DISABLE) != 0 || cur.ss_sp != crash_altstack) {
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
		/* POSIX permits EPERM while the stack is active; the allocation
		 * stays registered, so keep it rather than free memory a later
		 * delivery would still run on. */
		LOG_PERROR("sigaltstack");
		return;
	}
	free(crash_altstack);
	crash_altstack = NULL;
}

static void sighandler_crash(const int signo)
{
	/* A signal handler must leave errno as it found it on any path back to
	 * the interrupted code. Save it up front (the sigaction() below clobbers
	 * it) and restore it just before re-raising. */
	const int saved_errno = errno;

	/* Report the crash without any async-signal-unsafe call: slog_panicf()
	 * and debug_backtrace_fd() write straight to stderr with write(2) -- no
	 * lock, no buffered stdio, no allocation -- unlike the LOG_STACK_F() path
	 * this replaced, which deadlocked if the crash interrupted a thread
	 * already holding slog's output lock or inside malloc.
	 * debug_backtrace_init() (crashhandler_install) must have warmed the
	 * backtrace machinery first. */
	if (LOGLEVEL(FATAL)) {
		const char *const sigstr = os_strsignal(signo);
		if (sigstr != NULL) {
			slog_panicf(
				LOG_LEVEL_FATAL, __FILE__, __LINE__,
				"DEADLY SIGNAL: (%d) %s", signo, sigstr);
		} else {
			slog_panicf(
				LOG_LEVEL_FATAL, __FILE__, __LINE__,
				"DEADLY SIGNAL: (%d)", signo);
		}
		/* skip=2 drops debug_backtrace, sighandler_crash and the signal
		 * trampoline so the trace starts at the faulting frame, matching
		 * the previous LOG_STACK_F(FATAL, 2, ...) */
		void *frames[DEBUG_STACK_MAXDEPTH];
		const int n = debug_backtrace(frames, 2, DEBUG_STACK_MAXDEPTH);
		debug_backtrace_fd(STDERR_FILENO, frames, n);
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
		/* async-signal-safe error report on the near-impossible restore
		 * failure; strerror() is unsafe, so emit the raw errno */
		slog_panicf(
			LOG_LEVEL_ERROR, __FILE__, __LINE__, "sigaction: (%d)",
			errno);
		_Exit(EXIT_FAILURE);
	}
	if (idx < NUM_SIGHANDLERS) {
		/* the original disposition is live again; a later
		 * crashhandler_install() must re-capture and re-arm this signal
		 * instead of skipping it as still installed. Only installed is
		 * touched, atomically, so a concurrent handler for the same
		 * signal races on nothing: oact is left untouched (install()
		 * re-captures it whenever installed is false). */
		atomic_store_explicit(
			&sighandlers[idx].installed, false,
			memory_order_relaxed);
	}
	errno = saved_errno;
	if (raise(signo) != 0) {
		_Exit(EXIT_FAILURE);
	}
}

void crashhandler_install(void)
{
	/* Warm the capture and symbolization paths up front (both lazily
	 * allocate/parse on first use, which is not async-signal-safe) and
	 * verify a backtrace is actually available before arming the handlers. */
	if (!debug_backtrace_init()) {
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
	/* Block blockable signals on the handler's thread to prevent nested
	 * asynchronous delivery from interrupting its report. Other threads can
	 * run crash handlers concurrently, so their reports may interleave. */
	(void)sigfillset(&act.sa_mask);
	for (size_t i = 0; i < NUM_SIGHANDLERS; i++) {
		if (atomic_load_explicit(
			    &sighandlers[i].installed, memory_order_relaxed)) {
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
		atomic_store_explicit(
			&sighandlers[i].installed, true, memory_order_relaxed);
	}
}

void crashhandler_uninstall(void)
{
	for (size_t i = 0; i < NUM_SIGHANDLERS; i++) {
		if (!atomic_load_explicit(
			    &sighandlers[i].installed, memory_order_relaxed)) {
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
		atomic_store_explicit(
			&sighandlers[i].installed, false, memory_order_relaxed);
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
		/* the rest of the POSIX.1-2008 base set, then the XSI pair,
		 * which is optional and so guarded */
		{ SIGXCPU, "CPU time limit exceeded" },
		{ SIGXFSZ, "File size limit exceeded" },
		{ SIGVTALRM, "Virtual timer expired" },
#ifdef SIGPROF
		{ SIGPROF, "Profiling timer expired" },
#endif
#ifdef SIGPOLL
		{ SIGPOLL, "I/O possible" },
#endif
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
