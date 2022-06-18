
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
			LOG_PERROR("got error event");                         \
			return;                                                \
		}                                                              \
	} while (0)

static inline struct tlv_header tlv_header_read(const unsigned char *restrict d)
{
	return (struct tlv_header){
		.msg = read_uint16((const uint8_t *)d),
		.len = read_uint16((const uint8_t *)d + sizeof(uint16_t)),
	};
}

static inline void
tlv_header_write(unsigned char *restrict d, struct tlv_header header)
{
	write_uint16((uint8_t *)d, header.msg);
	write_uint16((uint8_t *)d + sizeof(uint16_t), header.len);
}

/* session messages */
#define SMSG_DATA UINT16_C(0x0000)
#define SMSG_CLOSE UINT16_C(0x0001)

#endif /* EVENT_IMPL_H */
