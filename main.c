#include "util.h"
#include "conf.h"
#include "server.h"

#include "kcp/ikcp.h"
#include <ev.h>

#include <stdio.h>
#include <stdlib.h>

#include <signal.h>

void signal_cb(struct ev_loop *loop, struct ev_signal *watcher, int revents);

static void usage(char *argv0)
{
	printf("usage: %s <option>... \n", argv0);
	printf("  -h, --help                 show usage\n");
	printf("  -c, --config <file>        specify json config\n");
	printf("\n");
	exit(EXIT_SUCCESS);
}

static void init()
{
	ikcp_allocator(util_malloc, util_free);
	srand_uint32((uint32_t)time(NULL));
}

int main(int argc, char **argv)
{
	fprintf(stderr, "%s\n", PACKAGE_STRING);
	fprintf(stderr, "  %s\n", PACKAGE_URL);
	fprintf(stderr, "\n");
	if (argc != 3) {
		usage(argv[0]);
		return EXIT_SUCCESS;
	}
	if (strcmp(argv[1], "-c") != 0 && strcmp(argv[1], "--config") != 0) {
		usage(argv[0]);
		return EXIT_SUCCESS;
	}

	init();
	LOG_I("initializing...");
	struct ev_loop *loop = ev_default_loop(0);
	UTIL_ASSERT(loop);
	struct ev_signal *w_sigint = util_malloc(sizeof(struct ev_signal));
	UTIL_ASSERT(w_sigint);
	struct ev_signal *w_sigterm = util_malloc(sizeof(struct ev_signal));
	UTIL_ASSERT(w_sigterm);

	struct config *conf = conf_read(argv[2]);
	if (conf == NULL) {
		LOG_E("failed to read config");
		util_free(w_sigint);
		util_free(w_sigterm);
		return EXIT_FAILURE;
	}
	struct server *server = server_start(loop, conf);
	if (server == NULL) {
		LOG_E("failed to start server");
		util_free(w_sigint);
		util_free(w_sigterm);
		return EXIT_FAILURE;
	}

	signal(SIGPIPE, SIG_IGN);
	ev_signal_init(w_sigint, signal_cb, SIGINT);
	ev_signal_start(loop, w_sigint);
	ev_signal_init(w_sigterm, signal_cb, SIGTERM);
	ev_signal_start(loop, w_sigterm);

	// Start infinite loop
	LOG_I("server start");
	ev_run(loop, 0);

	server_shutdown(server);
	LOG_I("server shutdown");

	util_free(w_sigint);
	util_free(w_sigterm);

	LOG_I("program terminated normally.");
	return EXIT_SUCCESS;
}

void signal_cb(struct ev_loop *loop, struct ev_signal *watcher, int revents)
{
	UNUSED(watcher);
	UNUSED(revents);
	LOG_I("signal received, breaking");
	ev_break(loop, EVBREAK_ALL);
}
