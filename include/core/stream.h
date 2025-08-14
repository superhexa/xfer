#ifndef SECUREXFER_STREAM_H
#define SECUREXFER_STREAM_H

#include <stdint.h>
#include <stddef.h>
#include "protocol.h"
#include "transfer.h"

#ifdef __cplusplus
extern "C" {
#endif

int sx_send_packet(int fd, sx_pkt_type_t type, uint32_t seq, const uint8_t *payload, size_t payload_len);
int sx_recv_packet(int fd, sx_packet_t *out);
int sx_transfer_send_data_block(int sock_fd, const uint8_t *buf, size_t len, uint32_t seq, sx_session_t *session);

#ifdef __cplusplus
}
#endif

#endif