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
	       "  --genpsk                   generate a random preshared key\n"
#endif
	       "\n");
}

static void init()
{
#if WITH_CRYPTO
	aead_init();
#endif
	ikcp_allocator(util_malloc, util_free);
}

int main(int argc, char **argv)
{
	fprintf(stderr, "%s %s\n", PROJECT_NAME, PROJECT_VER);
	fprintf(stderr, "  %s\n", PROJECT_HOMEPAGE);
	fprintf(stderr, "\n");

	char *conf_path = NULL;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0 ||
		    strcmp(argv[i], "--help") == 0) {
			print_usage(argv[0]);
			return EXIT_SUCCESS;
		} else if (
			strcmp(argv[i], "-c") == 0 ||
			strcmp(argv[i], "--config") == 0) {
			if (i + 1 >= argc) {
				printf("incomplete argument: %s", argv[i]);
				print_usage(argv[0]);
				return EXIT_FAILURE;
			}
			conf_path = argv[++i];
		}
#if WITH_CRYPTO
		else if (strcmp(argv[i], "--genpsk") == 0) {
			const size_t key_size = crypto_key_size();
			unsigned char *key = must_malloc(key_size);
			crypto_gen_key(key);
			char *keystr = b64_encode(key, key_size);
			printf("%s\n", keystr);
			util_free(key);
			free(keystr);
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
	UTIL_ASSERT(loop);
	struct ev_signal *w_sigint = util_malloc(sizeof(struct ev_signal));
	UTIL_ASSERT(w_sigint);
	struct ev_signal *w_sigterm = util_malloc(sizeof(struct ev_signal));
	UTIL_ASSERT(w_sigterm);

	struct config *conf = conf_read(conf_path);
	if (conf == NULL) {
		LOGE("failed to read config");
		util_free(w_sigint);
		util_free(w_sigterm);
		return EXIT_FAILURE;
	}
	slog_level = conf->log_level;
	struct server *restrict s = server_start(loop, conf);
	if (s == NULL) {
		LOGE_F("failed to start %s",
		       conf->mode == MODE_SERVER ? "server" : "client");
		util_free(w_sigint);
		util_free(w_sigterm);
		conf_free(conf);
		return EXIT_FAILURE;
	}

	signal(SIGPIPE, SIG_IGN);
	ev_signal_init(w_sigint, signal_cb, SIGINT);
	ev_signal_start(loop, w_sigint);
	ev_signal_init(w_sigterm, signal_cb, SIGTERM);
	ev_signal_start(loop, w_sigterm);

	// Start infinite loop
	LOGI_F("%s start", runmode_str(conf->mode));
	ev_run(loop, 0);

	server_shutdown(s);
	LOGI_F("%s shutdown", runmode_str(conf->mode));

	util_free(w_sigint);
	util_free(w_sigterm);
	conf_free(conf);

	LOGI("program terminated normally.");
	return EXIT_SUCCESS;
}

void signal_cb(struct ev_loop *loop, struct ev_signal *watcher, int revents)
{
	UNUSED(watcher);
	UNUSED(revents);
	LOGI("signal received, breaking");
	ev_break(loop, EVBREAK_ALL);
}
