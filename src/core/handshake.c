#include "core/handshake.h"
#include "core/runtime.h"
#include "core/keyexchange.h"
#include "core/crypto.h"
#include "core/protocol.h"
#include <string.h>
#include <stdlib.h>

int sx_handshake_client(int fd, sx_session_t *session){
	sx_kx_ctx_t kx;
	if(sx_kx_init(&kx, 0) != SX_KX_OK) return -1;
	if(sx_kx_generate(&kx) != SX_KX_OK){ sx_kx_free(&kx); return -1; }
	uint8_t pub[32]; size_t publen = sizeof(pub);
	if(sx_kx_export_pub(&kx, pub, &publen) != SX_KX_OK){ sx_kx_free(&kx); return -1; }
	uint8_t iv[12];
	if(sx_crypto_generate_sym((sx_sym_key_t *)session, SX_CIPHER_AES_GCM) != SX_CRYPTO_OK){ sx_kx_free(&kx); return -1; }
	memcpy(iv, session->iv, sizeof(iv));
	uint8_t tokhash[32];
	memset(tokhash,0,sizeof(tokhash));
	const char *tok = sx_runtime_cfg_get()->auth_token;
	if(tok && tok[0]) sx_crypto_hash_sha256((const uint8_t *)tok, strlen(tok), tokhash);
	uint8_t hs[76];
	memcpy(hs, pub, 32);
	memcpy(hs+32, iv, 12);
	memcpy(hs+44, tokhash, 32);
	sx_packet_t p; memset(&p,0,sizeof(p));
	sx_proto_build_hdr(&p.hdr, SX_PKT_HANDSHAKE, 0, sizeof(hs), 0);
	p.payload = hs; p.payload_len = sizeof(hs);
	uint8_t buf[sizeof(sx_proto_hdr_t) + sizeof(hs)]; size_t blen = sizeof(buf);
	sx_proto_serialize(&p, buf, &blen);
	if(send(fd, buf, blen, 0) <= 0){ sx_kx_free(&kx); return -1; }
	sx_packet_t resp;
	uint8_t hb[sizeof(sx_proto_hdr_t)]; if(recv(fd,hb,sizeof(hb),0) <= 0){ sx_kx_free(&kx); return -1; }
	size_t plen = ((size_t)be64toh(((sx_proto_hdr_t *)hb)->payload_len));
	uint8_t *rb = (uint8_t *)malloc(sizeof(sx_proto_hdr_t)+plen);
	memcpy(rb,hb,sizeof(hb)); if(plen && recv(fd, rb+sizeof(sx_proto_hdr_t), plen, 0) <= 0){ free(rb); sx_kx_free(&kx); return -1; }
	if(sx_proto_parse(rb, sizeof(sx_proto_hdr_t)+plen, &resp) != 0){ free(rb); sx_kx_free(&kx); return -1; }
	free(rb);
	if(ntohs(resp.hdr.type) != SX_PKT_KEYEX || resp.payload_len != 32){ sx_proto_free_packet(&resp); sx_kx_free(&kx); return -1; }
	if(sx_kx_set_peer_pub(&kx, resp.payload, resp.payload_len) != SX_KX_OK){ sx_proto_free_packet(&resp); sx_kx_free(&kx); return -1; }
	if(sx_kx_derive_shared(&kx) != SX_KX_OK){ sx_proto_free_packet(&resp); sx_kx_free(&kx); return -1; }
	sx_proto_free_packet(&resp);
	uint8_t prk[32];
	if(sx_crypto_hash_sha256(kx.shared_secret, kx.shared_secret_len, prk) != SX_CRYPTO_OK){ sx_kx_free(&kx); return -1; }
	memcpy(session->key, prk, 32);
	session->send_seq = 0;
	session->recv_seq = 0;
	session->established = 1;
	session->compression = sx_runtime_cfg_get()->compression_enabled;
	sx_kx_free(&kx);
	return 0;
}

int sx_handshake_server(int fd, sx_session_t *session){
	sx_packet_t hs;
	uint8_t hb[sizeof(sx_proto_hdr_t)]; if(recv(fd,hb,sizeof(hb),0) <= 0) return -1;
	size_t plen = ((size_t)be64toh(((sx_proto_hdr_t *)hb)->payload_len));
	uint8_t *rb = (uint8_t *)malloc(sizeof(sx_proto_hdr_t)+plen);
	memcpy(rb,hb,sizeof(hb)); if(plen && recv(fd, rb+sizeof(sx_proto_hdr_t), plen, 0) <= 0){ free(rb); return -1; }
	if(sx_proto_parse(rb, sizeof(sx_proto_hdr_t)+plen, &hs) != 0){ free(rb); return -1; }
	free(rb);
	if(ntohs(hs.hdr.type) != SX_PKT_HANDSHAKE || (hs.payload_len != 44 && hs.payload_len != 76)){ sx_proto_free_packet(&hs); return -1; }
	uint8_t client_pub[32];
	memcpy(client_pub, hs.payload, 32);
	memcpy(session->iv, hs.payload+32, 12);
	if(hs.payload_len == 76){
		const char *tok = sx_runtime_cfg_get()->auth_token;
		if(tok && tok[0]){
			uint8_t expect[32];
			if(sx_crypto_hash_sha256((const uint8_t *)tok, strlen(tok), expect) != SX_CRYPTO_OK){ sx_proto_free_packet(&hs); return -1; }
			if(memcmp(expect, hs.payload+44, 32) != 0){ sx_proto_free_packet(&hs); return -1; }
		}
	} else {
		const char *tok = sx_runtime_cfg_get()->auth_token;
		if(tok && tok[0]){ sx_proto_free_packet(&hs); return -1; }
	}
	sx_proto_free_packet(&hs);
	sx_kx_ctx_t kx;
	if(sx_kx_init(&kx, 0) != SX_KX_OK) return -1;
	if(sx_kx_generate(&kx) != SX_KX_OK){ sx_kx_free(&kx); return -1; }
	if(sx_kx_set_peer_pub(&kx, client_pub, 32) != SX_KX_OK){ sx_kx_free(&kx); return -1; }
	if(sx_kx_derive_shared(&kx) != SX_KX_OK){ sx_kx_free(&kx); return -1; }
	uint8_t prk[32];
	if(sx_crypto_hash_sha256(kx.shared_secret, kx.shared_secret_len, prk) != SX_CRYPTO_OK){ sx_kx_free(&kx); return -1; }
	memcpy(session->key, prk, 32);
	uint8_t server_pub[32]; size_t spl = sizeof(server_pub);
	if(sx_kx_export_pub(&kx, server_pub, &spl) != SX_KX_OK){ sx_kx_free(&kx); return -1; }
	sx_packet_t p; memset(&p,0,sizeof(p)); sx_proto_build_hdr(&p.hdr, SX_PKT_KEYEX, 0, spl, 0);
	p.payload = server_pub; p.payload_len = spl;
	uint8_t buf[sizeof(sx_proto_hdr_t)+32]; size_t blen = sizeof(sx_proto_hdr_t)+spl;
	sx_proto_serialize(&p, buf, &blen);
	if(send(fd, buf, blen, 0) <= 0){ sx_kx_free(&kx); return -1; }
	session->send_seq = 0;
	session->recv_seq = 0;
	session->established = 1;
	session->compression = sx_runtime_cfg_get()->compression_enabled;
	sx_kx_free(&kx);
	return 0;
}