#ifndef SECUREXFER_META_H
#define SECUREXFER_META_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int sx_meta_send(int sock_fd, const char *basename, uint64_t filesize, uint32_t mode, uint64_t mtime);
int sx_meta_parse(const uint8_t *payload, size_t payload_len, uint64_t *filesize_out, uint32_t *mode_out, uint64_t *mtime_out, const char **name_out, uint16_t *name_len_out);

#ifdef __cplusplus
}
#endif

#endif