#include "aead.h"
#include "slog.h"
#include "util.h"
#include "conf.h"
#include "server.h"

#include "kcp/ikcp.h"
#include "b64/b64.h"
#include <ev.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <signal.h>

void signal_cb(struct ev_loop *loop, struct ev_signal *watcher, int revents);

static void print_usage(char *argv0)
{
	printf("usage: %s <option>... \n", argv0);
	printf("%s",
	       "  -h, --help                 show usage\n"
	       "  -c, --config <file>        specify json config\n"
#if WITH_CRYPTO
	       "  --genpsk <method>          generate random preshared key for specified method\n"
#endif
	       "\n");
}

static void init(void)
{
	ikcp_allocator(util_malloc, util_free);
}

#if WITH_CRYPTO
static void genpsk(const char *method)
{
	struct aead *crypto = aead_create(method);
	if (crypto == NULL) {
		exit(EXIT_FAILURE);
	}
	unsigned char *key = must_malloc(crypto->key_size);
	aead_keygen(crypto, key);
	char *keystr = b64_encode(key, crypto->key_size);
	printf("%s\n", keystr);
	util_free(key);
	free(keystr);
	aead_free(crypto);
}
#endif

static char *conf_path = NULL;

int main(int argc, char **argv)
{
	fprintf(stderr, "%s %s\n", PROJECT_NAME, PROJECT_VER);
	fprintf(stderr, "  %s\n", PROJECT_HOMEPAGE);
	fprintf(stderr, "\n");

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0 ||
		    strcmp(argv[i], "--help") == 0) {
			print_usage(argv[0]);
			return EXIT_SUCCESS;
		} else if (
			strcmp(argv[i], "-c") == 0 ||
			strcmp(argv[i], "--config") == 0) {
			if (i + 1 >= argc) {
				print_usage(argv[0]);
				return EXIT_FAILURE;
			}
			conf_path = argv[++i];
		}
#if WITH_CRYPTO
		else if (strcmp(argv[i], "--genpsk") == 0) {
			if (i + 1 >= argc) {
				print_usage(argv[0]);
				return EXIT_FAILURE;
			}
			genpsk(argv[++i]);
			return EXIT_SUCCESS;
		}
#endif
		else {
			printf("unknown argument: %s\n", argv[i]);
			print_usage(argv[0]);
			return EXIT_SUCCESS;
		}
	}
	if (conf_path == NULL) {
		print_usage(argv[0]);
		return EXIT_SUCCESS;
	}

	init();
	LOGI("initializing...");
	struct ev_loop *loop = ev_default_loop(0);
	check(loop != NULL);

	struct config *conf = conf_read(conf_path);
	if (conf == NULL) {
		LOGE("failed to read config");
		return EXIT_FAILURE;
	}
	slog_level = conf->log_level;
	struct server *restrict s = server_start(loop, conf);
	if (s == NULL) {
		LOGE_F("failed to start %s", runmode_str(conf->mode));
		conf_free(conf);
		return EXIT_FAILURE;
	}

	/* signal watchers */
	signal(SIGPIPE, SIG_IGN);
	struct ev_signal *w_sighup = must_malloc(sizeof(struct ev_signal));
	struct ev_signal *w_sigint = must_malloc(sizeof(struct ev_signal));
	struct ev_signal *w_sigterm = must_malloc(sizeof(struct ev_signal));
	ev_signal_init(w_sighup, signal_cb, SIGHUP);
	w_sighup->data = s;
	ev_signal_start(loop, w_sighup);
	ev_signal_init(w_sigint, signal_cb, SIGINT);
	w_sigint->data = s;
	ev_signal_start(loop, w_sigint);
	ev_signal_init(w_sigterm, signal_cb, SIGTERM);
	w_sigterm->data = s;
	ev_signal_start(loop, w_sigterm);

	// Start infinite loop
	LOGI_F("%s start", runmode_str(conf->mode));
	ev_run(loop, 0);

	ev_signal_stop(loop, w_sighup);
	UTIL_SAFE_FREE(w_sighup);
	ev_signal_stop(loop, w_sigint);
	UTIL_SAFE_FREE(w_sigint);
	ev_signal_stop(loop, w_sigterm);
	UTIL_SAFE_FREE(w_sigterm);

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
		struct config *conf = conf_read(conf_path);
		if (conf == NULL) {
			LOGE_F("failed to read config: %s", conf_path);
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
