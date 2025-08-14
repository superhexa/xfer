#include "core/protocol.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static uint32_t sx_crc32_table[256];
static int sx_crc_inited = 0;

static void sx_crc_init(void){
    if(sx_crc_inited) return;
    for(int i=0;i<256;i++){
        uint32_t c = (uint32_t)i;
        for(int j=0;j<8;j++){
            if(c & 1) c = 0xEDB88320UL ^ (c >> 1);
            else c = c >> 1;
        }
        sx_crc32_table[i] = c;
    }
    sx_crc_inited = 1;
}

uint32_t sx_proto_calc_crc(const void *data, size_t len){
    sx_crc_init();
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFU;
    for(size_t i=0;i<len;i++) crc = sx_crc32_table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFU;
}

int sx_proto_init(void){
    sx_crc_init();
    return 0;
}

int sx_proto_build_hdr(sx_proto_hdr_t *hdr, sx_pkt_type_t type, uint32_t seq, uint64_t payload_len, uint32_t flags){
    if(!hdr) return -1;
    hdr->magic = htonl(SX_MAGIC);
    hdr->version = htons(SX_PROTO_VER);
    hdr->type = htons((uint16_t)type);
    hdr->seq = htonl(seq);
    hdr->payload_len = htobe64(payload_len);
    hdr->flags = htonl(flags);
    hdr->hdr_crc = 0;
    uint32_t crc = sx_proto_calc_crc(hdr, sizeof(*hdr));
    hdr->hdr_crc = htonl(crc);
    return 0;
}

int sx_proto_serialize(const sx_packet_t *pkt, uint8_t *buf, size_t *buf_len){
    if(!pkt || !buf || !buf_len) return -1;
    size_t need = sizeof(sx_proto_hdr_t) + pkt->payload_len;
    if(*buf_len < need) return -1;
    memcpy(buf, &pkt->hdr, sizeof(sx_proto_hdr_t));
    if(pkt->payload_len && pkt->payload) memcpy(buf + sizeof(sx_proto_hdr_t), pkt->payload, pkt->payload_len);
    *buf_len = need;
    return 0;
}

int sx_proto_parse(const uint8_t *buf, size_t buf_len, sx_packet_t *out){
    if(!buf || !out) return -1;
    if(buf_len < sizeof(sx_proto_hdr_t)) return -1;
    memcpy(&out->hdr, buf, sizeof(sx_proto_hdr_t));
    uint32_t magic = ntohl(out->hdr.magic);
    if(magic != SX_MAGIC) return -1;
    uint32_t crc = ntohl(out->hdr.hdr_crc);
    out->hdr.hdr_crc = 0;
    uint32_t calc = sx_proto_calc_crc(&out->hdr, sizeof(out->hdr));
    if(calc != crc) return -1;
    out->hdr.hdr_crc = htonl(crc);
    uint64_t plen = be64toh(out->hdr.payload_len);
    if(plen){
        if(buf_len < sizeof(sx_proto_hdr_t) + plen) return -1;
        out->payload = malloc((size_t)plen);
        memcpy(out->payload, buf + sizeof(sx_proto_hdr_t), (size_t)plen);
        out->payload_len = (size_t)plen;
    } else {
        out->payload = NULL;
        out->payload_len = 0;
    }
    return 0;
}

int sx_proto_free_packet(sx_packet_t *pkt){
    if(!pkt) return -1;
    if(pkt->payload){ free(pkt->payload); pkt->payload = NULL; pkt->payload_len = 0; }
    return 0;
}
