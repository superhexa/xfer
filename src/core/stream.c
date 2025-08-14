#include "core/stream.h"
#include "core/crypto.h"
#include "core/runtime.h"
#include <string.h>
#include <stdlib.h>
#include <zlib.h>

int sx_send_packet(int fd, sx_pkt_type_t type, uint32_t seq, const uint8_t *payload, size_t payload_len){
	sx_packet_t pkt; memset(&pkt,0,sizeof(pkt));
	sx_proto_build_hdr(&pkt.hdr, type, seq, (uint64_t)payload_len, 0);
	pkt.payload = (uint8_t *)payload; pkt.payload_len = payload_len;
	size_t blen = sizeof(sx_proto_hdr_t) + pkt.payload_len;
	uint8_t *sbuf = (uint8_t *)malloc(blen);
	if(!sbuf) return -1;
	if(sx_proto_serialize(&pkt, sbuf, &blen) != 0){ free(sbuf); return -1; }
	if(send(fd, sbuf, blen, 0) <= 0){ free(sbuf); return -1; }
	free(sbuf);
	return 0;
}

int sx_recv_packet(int fd, sx_packet_t *out){
	uint8_t hdrbuf[sizeof(sx_proto_hdr_t)];
	ssize_t r = recv(fd, hdrbuf, sizeof(hdrbuf), 0);
	if(r <= 0) return -1;
	sx_proto_hdr_t hdr; memcpy(&hdr, hdrbuf, sizeof(hdr));
	uint64_t plen = be64toh(hdr.payload_len);
	size_t total = sizeof(sx_proto_hdr_t) + (size_t)plen;
	uint8_t *buf = (uint8_t *)malloc(total);
	if(!buf) return -1;
	memcpy(buf, hdrbuf, sizeof(hdrbuf));
	if(plen){ if(recv(fd, buf + sizeof(sx_proto_hdr_t), (size_t)plen, 0) <= 0){ free(buf); return -1; } }
	int rc = sx_proto_parse(buf, total, out);
	free(buf);
	return rc;
}

int sx_transfer_send_data_block(int sock_fd, const uint8_t *buf, size_t len, uint32_t seq, sx_session_t *session){
	if(session && session->established){
		uint8_t work[131072];
		const uint8_t *src = buf; size_t srclen = len;
		uint8_t *cipher = work; size_t cipher_len = 0;
		uint8_t compbuf[131072]; const uint8_t *payload = NULL; size_t payload_len = 0;
		if(session->compression){
			z_stream zs; memset(&zs,0,sizeof(zs)); if(deflateInit(&zs, Z_BEST_SPEED) != Z_OK) return -1;
			zs.next_in = (Bytef *)src; zs.avail_in = (uInt)srclen; zs.next_out = compbuf; zs.avail_out = (uInt)sizeof(compbuf);
			if(deflate(&zs, Z_FINISH) != Z_STREAM_END){ deflateEnd(&zs); return -1; }
			deflateEnd(&zs);
			payload = compbuf; payload_len = zs.total_out;
		} else { payload = src; payload_len = srclen; }
		sx_sym_key_t k; memset(&k,0,sizeof(k)); k.cipher = SX_CIPHER_AES_GCM; k.key_len = 32; memcpy(k.key, session->key, 32); memcpy(k.iv, session->iv, 12);
		uint8_t tag[16];
		if(sx_crypto_aead_encrypt(&k, payload, payload_len, NULL, 0, cipher, &cipher_len, tag) != SX_CRYPTO_OK) return -1;
		if(sx_send_packet(sock_fd, SX_PKT_DATA, seq, cipher, cipher_len) != 0) return -1;
		if(send(sock_fd, tag, 16, 0) <= 0) return -1;
		return 0;
	} else {
		return sx_send_packet(sock_fd, SX_PKT_DATA, seq, buf, len);
	}
}