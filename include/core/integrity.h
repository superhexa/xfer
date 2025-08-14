#ifndef SECUREXFER_INTEGRITY_H
#define SECUREXFER_INTEGRITY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int sx_integrity_send_hash(int fd, const uint8_t hash32[32]);
int sx_integrity_verify_hash(const uint8_t expected32[32], const uint8_t received32[32]);

#ifdef __cplusplus
}
#endif

#endif