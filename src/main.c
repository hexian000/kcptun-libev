/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "utils/slog.h"
#include "utils/check.h"
#include "crypto.h"
#include "util.h"
#include "conf.h"
#include "server.h"

#include <ev.h>
#include <signal.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

static struct {
	const char *conf_path;
	const char *user_name;
	int verbosity;
	bool daemonize : 1;
} args = { 0 };

static struct {
	struct ev_signal w_sighup;
	struct ev_signal w_sigint;
	struct ev_signal w_sigterm;
} app;

void signal_cb(struct ev_loop *loop, struct ev_signal *watcher, int revents);

static void print_usage(char *argv0)
{
	fprintf(stderr, "%s",
		PROJECT_NAME " " PROJECT_VER "\n"
			     "  " PROJECT_HOMEPAGE "\n\n");
	fprintf(stderr, "usage: %s <option>... \n", argv0);
	fprintf(stderr, "%s",
		"  -h, --help                 show usage and exit\n"
		"  -c, --config <file>        specify json config\n"
		"  -d, --daemonize            run in background and discard all logs\n"
		"  -u, --user <name>          run as the specified limited user, e.g. nobody\n"
		"  -v, --verbose              increase logging verbosity, can be specified more than once\n"
		"                             e.g. \"-v -v\" prints verbose messages\n"
		"  -s, --silence              decrease logging verbosity\n"
#if WITH_CRYPTO
		"\ncrypto options:\n"
		"  --list-methods             list supported crypto methods and exit\n"
		"  --genpsk <method>          generate random preshared key for specified method\n"
#endif
		"\n");
	fflush(stderr);
}

static void parse_args(int argc, char **argv)
{
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0 ||
		    strcmp(argv[i], "--help") == 0) {
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
		if (strcmp(argv[i], "-c") == 0 ||
		    strcmp(argv[i], "--config") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr,
					"option \"%s\" requires an argument\n",
					argv[i]);
				print_usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			args.conf_path = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "-u") == 0 ||
		    strcmp(argv[i], "--user") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr,
					"option \"%s\" requires an argument\n",
					argv[i]);
				print_usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			args.user_name = argv[++i];
			continue;
		}
#if WITH_CRYPTO
		if (strcmp(argv[i], "--list-methods") == 0) {
			crypto_list_methods();
			exit(EXIT_FAILURE);
		}
		if (strcmp(argv[i], "--genpsk") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr,
					"option \"%s\" requires an argument\n",
					argv[i]);
				print_usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			genpsk(argv[++i]);
			exit(EXIT_SUCCESS);
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
			continue;
		}
		LOGF_F("unknown argument: \"%s\"", argv[i]);
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char **argv)
{
	init();

	parse_args(argc, argv);
	if (args.conf_path == NULL) {
		LOGF("config file must be specified");
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	struct config *restrict conf = conf_read(args.conf_path);
	if (conf == NULL) {
		LOGF("failed to read config");
		return EXIT_FAILURE;
	}
	slog_level = conf->log_level + args.verbosity;

	struct ev_loop *loop = ev_default_loop(0);
	CHECK(loop != NULL);

	struct server *restrict s = server_new(loop, conf);
	if (s == NULL) {
		LOGE_F("failed to init %s", runmode_str(conf->mode));
		conf_free(conf);
		return EXIT_FAILURE;
	}
	bool ok = server_start(s);
	if (!ok) {
		LOGE_F("failed to start %s", runmode_str(conf->mode));
		server_free(s);
		conf_free(conf);
		return EXIT_FAILURE;
	}

	const char *user = args.user_name ? args.user_name : conf->user;
	if (args.daemonize) {
		daemonize(user);
	} else if (user != NULL) {
		drop_privileges(user);
	}

	/* signal watchers */
	{
		struct ev_signal *restrict w_sighup = &app.w_sighup;
		ev_signal_init(w_sighup, signal_cb, SIGHUP);
		ev_set_priority(w_sighup, EV_MAXPRI);
		w_sighup->data = s;
		ev_signal_start(loop, w_sighup);
		struct ev_signal *restrict w_sigint = &app.w_sigint;
		ev_signal_init(w_sigint, signal_cb, SIGINT);
		ev_set_priority(w_sigint, EV_MAXPRI);
		w_sigint->data = s;
		ev_signal_start(loop, w_sigint);
		struct ev_signal *restrict w_sigterm = &app.w_sigterm;
		ev_signal_init(w_sigterm, signal_cb, SIGTERM);
		ev_set_priority(w_sigterm, EV_MAXPRI);
		w_sigterm->data = s;
		ev_signal_start(loop, w_sigterm);
	}

	/* start event loop */
	LOGI_F("%s start", runmode_str(conf->mode));
	ev_run(loop, 0);

	server_stop(s);
	server_free(s);
	LOGI_F("%s shutdown", runmode_str(conf->mode));
	ev_loop_destroy(loop);
	conf_free(conf);

	LOGI("program terminated normally.");
	return EXIT_SUCCESS;
}

void signal_cb(struct ev_loop *loop, struct ev_signal *watcher, int revents)
{
	UNUSED(revents);

	struct server *restrict s = watcher->data;
	switch (watcher->signum) {
	case SIGHUP: {
		struct config *conf = conf_read(args.conf_path);
		if (conf == NULL) {
			LOGE_F("failed to read config: %s", args.conf_path);
			return;
		}
		conf_free((struct config *)s->conf);
		slog_level = conf->log_level;
		s->conf = conf;
		(void)server_resolve(s);
		LOGI("config successfully reloaded");
	} break;
	case SIGINT:
	case SIGTERM: {
		LOGI_F("signal %d received, breaking", watcher->signum);
		ev_break(loop, EVBREAK_ALL);
	} break;
	}
}
