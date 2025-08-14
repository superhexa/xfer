#ifndef SECUREXFER_PROTOCOL_H
#define SECUREXFER_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <arpa/inet.h>

#if defined(__linux__)
#include <endian.h>
#endif

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#endif

#ifndef htobe64
static inline uint64_t htobe64(uint64_t x) {
    uint32_t hi = htonl((uint32_t)(x >> 32));
    uint32_t lo = htonl((uint32_t)(x & 0xFFFFFFFF));
    return ((uint64_t)lo << 32) | hi;
}
#endif

#ifndef be64toh
static inline uint64_t be64toh(uint64_t x) {
    uint32_t hi = ntohl((uint32_t)(x >> 32));
    uint32_t lo = ntohl((uint32_t)(x & 0xFFFFFFFF));
    return ((uint64_t)lo << 32) | hi;
}
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SX_MAGIC 0x53584746
#define SX_PROTO_VER 1
#define SX_HDR_MAX_SZ 4096

typedef enum {
    SX_PKT_HANDSHAKE = 0x01,
    SX_PKT_KEYEX     = 0x02,
    SX_PKT_META      = 0x03,
    SX_PKT_DATA      = 0x04,
    SX_PKT_ACK       = 0x05,
    SX_PKT_ERR       = 0x06,
    SX_PKT_CTRL      = 0x07
} sx_pkt_type_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint32_t seq;
    uint64_t payload_len;
    uint32_t flags;
    uint32_t hdr_crc;
} sx_proto_hdr_t;

typedef struct sx_packet {
    sx_proto_hdr_t hdr;
    uint8_t *payload;
    size_t payload_len;
} sx_packet_t;

typedef struct __attribute__((packed)) {
    uint8_t client_pub[32];
    uint8_t iv[12];
} sx_handshake_t;

int sx_proto_init(void);
int sx_proto_build_hdr(sx_proto_hdr_t *hdr, sx_pkt_type_t type, uint32_t seq, uint64_t payload_len, uint32_t flags);
int sx_proto_serialize(const sx_packet_t *pkt, uint8_t *buf, size_t *buf_len);
int sx_proto_parse(const uint8_t *buf, size_t buf_len, sx_packet_t *out);
int sx_proto_free_packet(sx_packet_t *pkt);
uint32_t sx_proto_calc_crc(const void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif
