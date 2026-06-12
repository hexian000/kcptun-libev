/* kcptun-libev (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"
#include "crypto.h"
#include "server.h"
#include "util.h"

#include "os/daemon.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct {
	const char *conf_path;
	const char *user_name;
#if WITH_CRYPTO
	const char *genpsk;
#endif
	int verbosity;
	bool daemonize : 1;
} args = { 0 };

static struct {
	ev_signal w_sighup;
	ev_signal w_sigint;
	ev_signal w_sigterm;
} app;

void signal_cb(struct ev_loop *loop, ev_signal *watcher, const int revents);

static void print_usage(char *argv0)
{
	(void)fprintf(
		stderr, "%s %s\n  %s\n\n", PROJECT_NAME, PROJECT_VER,
		PROJECT_HOMEPAGE);
	(void)fprintf(stderr, "usage: %s <option>... \n", argv0);
	(void)fprintf(
		stderr, "%s",
		"  -h, --help                 show usage and exit\n"
		"  -c, --config <file>        specify json config\n"
		"  -C, --color                colorized log output using ANSI escape sequences\n"
		"  -d, --daemonize            run in background and write logs to syslog\n"
		"  -u, --user [user][:[group]]\n"
		"                             run as the specified identity, e.g. `nobody:nogroup'\n"
		"  -v, --verbose              increase logging verbosity, can be specified more than once\n"
		"                             e.g. \"-v -v\" prints debug messages\n"
		"  -s, --silence              decrease logging verbosity\n"
#if WITH_CRYPTO
		"\ncrypto options:\n"
		"  --list-methods             list supported crypto methods and exit\n"
		"  --genpsk <method>          generate random preshared key for specified method\n"
#endif
		"\n");
	(void)fflush(stderr);
}

static void set_log_config(const struct config *restrict conf, const int level)
{
	slog_setlevel(level);
	if (conf->log == NULL) {
		return;
	}
	const char *log = conf->log;
	if (strcmp(log, "stdout") == 0) {
		slog_setoutput(SLOG_OUTPUT_FILE, stdout);
	} else if (strcmp(log, "stderr") == 0) {
		slog_setoutput(SLOG_OUTPUT_FILE, stderr);
	} else if (strcmp(log, "syslog") == 0) {
		slog_setoutput(SLOG_OUTPUT_SYSLOG, PROJECT_NAME);
	} else if (strcmp(log, "discard") == 0) {
		slog_setoutput(SLOG_OUTPUT_DISCARD);
	} else {
		LOGW_F("unknown log output: \"%s\"", conf->log);
	}
}

static void parse_args(int argc, char **argv)
{
#define OPT_REQUIRE_ARG(argc, argv, i)                                         \
	do {                                                                   \
		if ((i) + 1 >= (argc)) {                                       \
			LOGF_F("option `%s' requires an argument",             \
			       (argv)[(i)]);                                   \
			exit(EXIT_FAILURE);                                    \
		}                                                              \
	} while (false)

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0 ||
		    strcmp(argv[i], "--help") == 0) {
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
		if (strcmp(argv[i], "-c") == 0 ||
		    strcmp(argv[i], "--config") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			args.conf_path = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "-C") == 0 ||
		    strcmp(argv[i], "--color") == 0) {
			slog_setoutput(SLOG_OUTPUT_TERMINAL, stdout);
			continue;
		}
		if (strcmp(argv[i], "-u") == 0 ||
		    strcmp(argv[i], "--user") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			args.user_name = argv[++i];
			continue;
		}
#if WITH_CRYPTO
		if (strcmp(argv[i], "--list-methods") == 0) {
			crypto_list_methods();
			exit(EXIT_FAILURE);
		}
		if (strcmp(argv[i], "--genpsk") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			args.genpsk = argv[++i];
			continue;
		}
#endif
		if (strcmp(argv[i], "-v") == 0 ||
		    strcmp(argv[i], "--verbose") == 0) {
			args.verbosity++;
			continue;
		}
		if (strcmp(argv[i], "-s") == 0 ||
		    strcmp(argv[i], "--silence") == 0) {
			args.verbosity--;
			continue;
		}
		if (strcmp(argv[i], "-d") == 0 ||
		    strcmp(argv[i], "--daemonize") == 0) {
			args.daemonize = true;
			continue;
		}
		if (strcmp(argv[i], "--") == 0) {
			break;
		}
		LOGF_F("unknown argument: `%s'", argv[i]);
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

#undef OPT_REQUIRE_ARG
	slog_setlevel(LOG_LEVEL_NOTICE + args.verbosity);
}

int main(int argc, char **argv)
{
	init(argc, argv);
	parse_args(argc, argv);
#if WITH_CRYPTO
	if (args.genpsk) {
		genpsk(args.genpsk);
		return EXIT_SUCCESS;
	}
#endif
	if (args.conf_path == NULL) {
		LOGF("config file must be specified");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}
	struct config *restrict conf = conf_read(args.conf_path);
	if (conf == NULL) {
		LOGF_F("failed to read config `%s'", args.conf_path);
		return EXIT_FAILURE;
	}
	set_log_config(conf, conf->log_level + args.verbosity);
	loadlibs();

	struct ev_loop *loop = ev_default_loop(0);
	CHECK(loop != NULL);

	struct server *restrict s = server_new(loop, conf);
	if (s == NULL) {
		LOGE_F("failed to init %s", conf_modestr(conf));
		conf_free(conf);
		return EXIT_FAILURE;
	}
	bool ok = server_start(s);
	if (!ok) {
		LOGE_F("failed to start %s", conf_modestr(conf));
		server_free(s);
		conf_free(conf);
		return EXIT_FAILURE;
	}

	{
		const char *user_name =
			args.user_name ? args.user_name : conf->user;
		if (args.daemonize) {
			daemonize(user_name, true, false);
			slog_setoutput(SLOG_OUTPUT_SYSLOG, PROJECT_NAME);
		} else if (user_name != NULL) {
			drop_privileges(user_name);
		}
	}

	{
		ev_signal *w_sighup = &app.w_sighup;
		ev_signal_init(w_sighup, signal_cb, SIGHUP);
		ev_set_priority(w_sighup, EV_MAXPRI);
		w_sighup->data = s;
		ev_signal_start(loop, w_sighup);

		ev_signal *w_sigint = &app.w_sigint;
		ev_signal_init(w_sigint, signal_cb, SIGINT);
		ev_set_priority(w_sigint, EV_MAXPRI);
		w_sigint->data = s;
		ev_signal_start(loop, w_sigint);

		ev_signal *w_sigterm = &app.w_sigterm;
		ev_signal_init(w_sigterm, signal_cb, SIGTERM);
		ev_set_priority(w_sigterm, EV_MAXPRI);
		w_sigterm->data = s;
		ev_signal_start(loop, w_sigterm);
	}

#if WITH_SYSTEMD
	(void)systemd_notify(DAEMON_SYSTEMD_STATE_READY);
#endif
	LOGN_F("%s start", conf_modestr(conf));
	ev_run(loop, 0);

	server_stop(s);
	server_free(s);
	LOGN_F("%s shutdown gracefully", conf_modestr(conf));
	ev_loop_destroy(loop);
	conf_free(conf);
	unloadlibs();

	LOGD("program terminated normally");
	return EXIT_SUCCESS;
}

void signal_cb(struct ev_loop *loop, ev_signal *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_SIGNAL);

	struct server *restrict s = watcher->data;
	switch (watcher->signum) {
	case SIGHUP: {
#if WITH_SYSTEMD
		(void)systemd_notify(DAEMON_SYSTEMD_STATE_RELOADING);
#endif
		struct config *conf = conf_read(args.conf_path);
		if (conf == NULL) {
			LOGE_F("failed to read config: %s", args.conf_path);
			return;
		}
		if (s->conf->mode != conf->mode) {
			conf_modestr(conf);
			LOGE_F("incompatible config: mode %s (0x%x) -> %s (0x%x)",
			       conf_modestr(s->conf), s->conf->mode,
			       conf_modestr(conf), conf->mode);
			return;
		}
		set_log_config(conf, conf->log_level);
		conf_free((struct config *)s->conf);
		server_loadconf(s, conf);
		LOGN("config successfully reloaded");
		(void)server_resolve(s);
		s->last_resolve_time = ev_now(s->loop);
#if WITH_SYSTEMD
		(void)systemd_notify(DAEMON_SYSTEMD_STATE_READY);
#endif
	} break;
	case SIGINT:
	case SIGTERM: {
		LOGD_F("signal %d received, breaking", watcher->signum);
#if WITH_SYSTEMD
		(void)systemd_notify(DAEMON_SYSTEMD_STATE_STOPPING);
#endif
		ev_break(loop, EVBREAK_ALL);
	} break;
	default:;
	}
}
