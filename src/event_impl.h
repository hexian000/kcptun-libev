
#ifndef EVENT_IMPL_H
#define EVENT_IMPL_H

#include "event.h"
#include "aead.h"
#include "hashtable.h"
#include "server.h"
#include "session.h"
#include "serialize.h"
#include "util.h"
#include "sockutil.h"
#include "packet.h"

#include "kcp/ikcp.h"
#include <ev.h>

#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>

#define CHECK_EV_ERROR(revents)                                                \
	do {                                                                   \
		if ((unsigned)(revents) & (unsigned)EV_ERROR) {                \
			LOGE_PERROR("got error event");                        \
			return;                                                \
		}                                                              \
	} while (0)

#endif /* EVENT_IMPL_H */
