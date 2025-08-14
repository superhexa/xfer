#include "integrity.h"
#include "core/stream.h"
#include "core/protocol.h"
#include <string.h>

int sx_integrity_send_hash(int fd, const uint8_t hash32[32]){
	return sx_send_packet(fd, SX_PKT_CTRL, 0, hash32, 32);
}

int sx_integrity_verify_hash(const uint8_t expected32[32], const uint8_t received32[32]){
	return memcmp(expected32, received32, 32) == 0 ? 0 : -1;
}