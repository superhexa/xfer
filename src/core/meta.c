#include "core/meta.h"
#include "core/stream.h"
#include "core/protocol.h"
#include <string.h>
#include <stdlib.h>

int sx_meta_send(int sock_fd, const char *basename, uint64_t filesize, uint32_t mode, uint64_t mtime){
	uint16_t name_len = (uint16_t)strlen(basename);
	size_t payload_len = sizeof(uint64_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint64_t) + (size_t)name_len;
	uint8_t *payload = (uint8_t *)malloc(payload_len);
	if(!payload) return -1;
	uint64_t fs_be = htobe64(filesize);
	uint16_t nl_be = htons(name_len);
	uint32_t mode_be = htonl(mode);
	uint64_t mt_be = htobe64(mtime);
	size_t off = 0;
	memcpy(payload + off, &fs_be, sizeof(fs_be)); off += sizeof(fs_be);
	memcpy(payload + off, &nl_be, sizeof(nl_be)); off += sizeof(nl_be);
	memcpy(payload + off, &mode_be, sizeof(mode_be)); off += sizeof(mode_be);
	memcpy(payload + off, &mt_be, sizeof(mt_be)); off += sizeof(mt_be);
	memcpy(payload + off, basename, name_len);
	int rc = sx_send_packet(sock_fd, SX_PKT_META, 0, payload, payload_len);
	free(payload);
	return rc;
}

int sx_meta_parse(const uint8_t *payload, size_t payload_len, uint64_t *filesize_out, uint32_t *mode_out, uint64_t *mtime_out, const char **name_out, uint16_t *name_len_out){
	if(payload_len < sizeof(uint64_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint64_t)) return -1;
	size_t off = 0;
	uint64_t fs_be; uint16_t nl_be; uint32_t mode_be; uint64_t mt_be;
	memcpy(&fs_be, payload + off, sizeof(fs_be)); off += sizeof(fs_be);
	memcpy(&nl_be, payload + off, sizeof(nl_be)); off += sizeof(nl_be);
	memcpy(&mode_be, payload + off, sizeof(mode_be)); off += sizeof(mode_be);
	memcpy(&mt_be, payload + off, sizeof(mt_be)); off += sizeof(mt_be);
	uint16_t name_len = ntohs(nl_be);
	if(off + name_len > payload_len) return -1;
	*filesize_out = be64toh(fs_be);
	*mode_out = ntohl(mode_be);
	*mtime_out = be64toh(mt_be);
	*name_out = (const char *)(payload + off);
	*name_len_out = name_len;
	return 0;
}