#include "aead.h"
#include "slog.h"
#include "util.h"
#include "conf.h"
#include "server.h"

#include <assert.h>
#include <ev.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <signal.h>

static struct {
	const char *conf_path;
	struct ev_signal w_sighup;
	struct ev_signal w_sigint;
	struct ev_signal w_sigterm;
} app;

void signal_cb(struct ev_loop *loop, struct ev_signal *watcher, int revents);

static void print_usage(char *argv0)
{
	fprintf(stderr, "usage: %s <option>... \n", argv0);
	fprintf(stderr, "%s",
		"  -h, --help                 show usage\n"
		"  -c, --config <file>        specify json config\n"
#if WITH_CRYPTO
		"  --genpsk <method>          generate random preshared key for specified method\n"
#endif
		"\n");
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
			app.conf_path = argv[++i];
			continue;
		}
#if WITH_CRYPTO
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
	fprintf(stderr, "%s",
		PROJECT_NAME " " PROJECT_VER "\n"
			     "  " PROJECT_HOMEPAGE "\n\n");

	parse_args(argc, argv);
	if (app.conf_path == NULL) {
		LOGF("config file must be specified");
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	struct config *conf = conf_read(app.conf_path);
	if (conf == NULL) {
		LOGE("failed to read config");
		return EXIT_FAILURE;
	}
	slog_level = conf->log_level;

	struct ev_loop *loop = ev_default_loop(0);
	check(loop != NULL);

	struct server *restrict s = server_start(loop, conf);
	if (s == NULL) {
		LOGE_F("failed to start %s", runmode_str(conf->mode));
		conf_free(conf);
		return EXIT_FAILURE;
	}

	/* signal watchers */
	signal(SIGPIPE, SIG_IGN);
	{
		struct ev_signal *restrict w_sighup = &app.w_sighup;
		ev_signal_init(w_sighup, signal_cb, SIGHUP);
		w_sighup->data = s;
		ev_signal_start(loop, w_sighup);
		struct ev_signal *restrict w_sigint = &app.w_sigint;
		ev_signal_init(w_sigint, signal_cb, SIGINT);
		w_sigint->data = s;
		ev_signal_start(loop, w_sigint);
		struct ev_signal *restrict w_sigterm = &app.w_sigterm;
		ev_signal_init(w_sigterm, signal_cb, SIGTERM);
		w_sigterm->data = s;
		ev_signal_start(loop, w_sigterm);
	}

	// Start infinite loop
	LOGI_F("%s start", runmode_str(conf->mode));
	ev_run(loop, 0);

	ev_signal_stop(loop, &app.w_sighup);
	ev_signal_stop(loop, &app.w_sigint);
	ev_signal_stop(loop, &app.w_sigterm);

	server_shutdown(s);
	LOGI_F("%s shutdown", runmode_str(conf->mode));
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
		struct config *conf = conf_read(app.conf_path);
		if (conf == NULL) {
			LOGE_F("failed to read config: %s", app.conf_path);
			return;
		}
		conf_free(s->conf);
		s->conf = conf;
		slog_level = conf->log_level;
		LOGI("config successfully reloaded");
	} break;
	case SIGINT:
	case SIGTERM: {
		LOGI_F("signal %d received, breaking", watcher->signum);
		ev_break(loop, EVBREAK_ALL);
	} break;
	}
}
