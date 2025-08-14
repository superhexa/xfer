#include "core/transfer.h"
#include "utils/fileio.h"
#include "core/protocol.h"
#include "core/crypto.h"
#include "utils/netutils.h"
#include "core/runtime.h"
#include "core/handshake.h"
#include "core/meta.h"
#include "core/stream.h"
#include "cli/ui.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <endian.h>
#include <sys/stat.h>
#include <utime.h>
#include <time.h>

int sx_transfer_init(sx_transfer_t *t, const sx_xfer_meta_t *meta){
	if(!t || !meta) return -1;
	memset(t,0,sizeof(*t));
	t->meta = *meta;
	pthread_mutex_init(&t->lock,NULL);
	pthread_cond_init(&t->cond,NULL);
	t->state = SX_XFER_IDLE;
	return 0;
}

int sx_transfer_start(sx_transfer_t *t, int out_fd){
	(void)out_fd;
	if(!t) return -1;
	ui_log_info("start transfer: file=%s size=%llu chunk=%u offset=%llu", t->meta.filename, (unsigned long long)t->meta.filesize, t->meta.chunk_size, (unsigned long long)t->meta.offset);
	pthread_mutex_lock(&t->lock);
	if(t->state != SX_XFER_IDLE){ pthread_mutex_unlock(&t->lock); ui_log_warn("invalid state=%d", t->state); return -1; }
	t->state = SX_XFER_RUNNING;
	pthread_mutex_unlock(&t->lock);
	sx_file_t f;
	if(sx_file_open(&f, t->meta.filename, O_RDONLY, 0) != SX_FIO_OK){ ui_log_error("open failed: %s", t->meta.filename); return -1; }
	uint8_t *buf = (uint8_t *)malloc(t->meta.chunk_size);
	if(!buf){ ui_log_error("alloc %u bytes failed", t->meta.chunk_size); sx_file_close(&f); return -1; }
	if(t->meta.offset) sx_file_seek(&f, (off_t)t->meta.offset, SEEK_SET);
	uint32_t seq = 0;
	int last_bucket = -1;
	while(1){
		ssize_t r = sx_file_read(&f, buf, t->meta.chunk_size);
		if(r == SX_FIO_EOF) break;
		if(r < 0) { ui_log_error("read error at seq=%u", seq); break; }
		if(sx_transfer_send_data_block(t->sock_fd, buf, (size_t)r, seq++, &t->session) != 0){ ui_log_error("send block failed seq=%u", seq-1); break; }
		t->stats.bytes_transferred += (uint64_t)r;
		if(t->meta.filesize){
			int pct = (int)((t->stats.bytes_transferred * 100.0) / t->meta.filesize + 0.5);
			int bucket = pct/10;
			if(bucket != last_bucket){ ui_log_info("progress %d%%", bucket*10); last_bucket = bucket; }
		}
		if(t->on_progress) t->on_progress(t, &t->stats);
	}
	free(buf);
	sx_file_close(&f);
	pthread_mutex_lock(&t->lock);
	t->state = SX_XFER_COMPLETED;
	pthread_mutex_unlock(&t->lock);
	if(t->on_complete) t->on_complete(t, 0);
	ui_log_info("done: bytes=%llu", (unsigned long long)t->stats.bytes_transferred);
	return 0;
}

int sx_transfer_resume(sx_transfer_t *t){ (void)t; return -1; }

int sx_transfer_pause(sx_transfer_t *t){ pthread_mutex_lock(&t->lock); if(t->state == SX_XFER_RUNNING) t->state = SX_XFER_PAUSED; pthread_mutex_unlock(&t->lock); return 0; }
int sx_transfer_stop(sx_transfer_t *t){ pthread_mutex_lock(&t->lock); t->state = SX_XFER_FAILED; pthread_mutex_unlock(&t->lock); return 0; }
int sx_transfer_destroy(sx_transfer_t *t){ if(!t) return -1; pthread_mutex_destroy(&t->lock); pthread_cond_destroy(&t->cond); return 0; }

int sx_transfer_send(const char *host, uint16_t port, const char *path){
	if(!host || !path) return -1;
	ui_log_info("connect %s:%u", host, port);
	if(sx_proto_init() != 0){ ui_log_error("proto init failed"); return -1; }
	if(sx_crypto_init() != SX_CRYPTO_OK){ ui_log_error("crypto init failed"); return -1; }
	struct stat st; if(stat(path, &st) != 0){ ui_log_error("stat failed: %s", path); return -1; } off_t fsz = st.st_size;
	const char *base = strrchr(path, '/'); base = base ? base + 1 : path;
	sx_xfer_meta_t meta; memset(&meta,0,sizeof(meta)); strncpy(meta.filename, path, sizeof(meta.filename)-1); meta.filesize = (uint64_t)fsz; meta.chunk_size = sx_runtime_cfg_get()->chunk_size; meta.offset = 0;
	sx_transfer_t xfer; if(sx_transfer_init(&xfer, &meta) != 0){ ui_log_error("xfer init failed"); return -1; }
	int sock_fd = -1; if(sx_net_connect_tcp(&sock_fd, host, port, 0) != SX_NET_OK){ ui_log_error("connect failed"); sx_transfer_destroy(&xfer); return -1; }
	ui_log_info("connected");
	xfer.sock_fd = sock_fd;
	ui_log_debug("handshake start"); if(sx_handshake_client(sock_fd, &xfer.session) != 0){ ui_log_error("handshake failed"); close(sock_fd); sx_transfer_destroy(&xfer); return -1; }
	ui_log_info("handshake ok");
	ui_log_debug("send meta: %s size=%llu", base, (unsigned long long)fsz); if(sx_meta_send(sock_fd, base, (uint64_t)fsz, (uint32_t)(st.st_mode & 07777), (uint64_t)st.st_mtime) != 0){ ui_log_error("send meta failed"); close(sock_fd); sx_transfer_destroy(&xfer); return -1; }
	int rc = sx_transfer_start(&xfer, -1);
	close(sock_fd);
	sx_transfer_destroy(&xfer);
	return rc;
}

int sx_transfer_send_offset(const char *host, uint16_t port, const char *path, uint64_t offset){
	if(!host || !path) return -1;
	ui_log_info("connect %s:%u", host, port);
	if(sx_proto_init() != 0){ ui_log_error("proto init failed"); return -1; }
	if(sx_crypto_init() != SX_CRYPTO_OK){ ui_log_error("crypto init failed"); return -1; }
	struct stat st; if(stat(path, &st) != 0){ ui_log_error("stat failed: %s", path); return -1; } off_t fsz = st.st_size;
	const char *base = strrchr(path, '/'); base = base ? base + 1 : path;
	sx_xfer_meta_t meta; memset(&meta,0,sizeof(meta)); strncpy(meta.filename, path, sizeof(meta.filename)-1); meta.filesize = (uint64_t)fsz; meta.chunk_size = sx_runtime_cfg_get()->chunk_size; meta.offset = offset;
	sx_transfer_t xfer; if(sx_transfer_init(&xfer, &meta) != 0){ ui_log_error("xfer init failed"); return -1; }
	int sock_fd = -1; if(sx_net_connect_tcp(&sock_fd, host, port, 0) != SX_NET_OK){ ui_log_error("connect failed"); sx_transfer_destroy(&xfer); return -1; }
	ui_log_info("connected");
	xfer.sock_fd = sock_fd;
	ui_log_debug("handshake start"); if(sx_handshake_client(sock_fd, &xfer.session) != 0){ ui_log_error("handshake failed"); close(sock_fd); sx_transfer_destroy(&xfer); return -1; }
	ui_log_info("handshake ok");
	ui_log_debug("send meta: %s size=%llu", base, (unsigned long long)fsz); if(sx_meta_send(sock_fd, base, (uint64_t)fsz, (uint32_t)(st.st_mode & 07777), (uint64_t)st.st_mtime) != 0){ ui_log_error("send meta failed"); close(sock_fd); sx_transfer_destroy(&xfer); return -1; }
	int rc = sx_transfer_start(&xfer, -1);
	close(sock_fd);
	sx_transfer_destroy(&xfer);
	return rc;
}

int sx_transfer_recv(uint16_t port, const char *out_path){
	if(!out_path) return -1;
	if(sx_proto_init() != 0){ ui_log_error("proto init failed"); return -1; }
	if(sx_crypto_init() != SX_CRYPTO_OK){ ui_log_error("crypto init failed"); return -1; }
	int lfd = -1; if(sx_net_bind_tcp(&lfd, NULL, port, 1) != SX_NET_OK){ ui_log_error("bind failed on %u", port); return -1; }
	ui_log_info("listening on %u", port);
	struct sockaddr_in peer; socklen_t sl = sizeof(peer);
	int cfd = accept(lfd, (struct sockaddr *)&peer, &sl); if(cfd < 0){ ui_log_error("accept failed"); close(lfd); return -1; }
	ui_log_info("accepted %s:%u", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
	sx_session_t session; memset(&session,0,sizeof(session)); if(sx_handshake_server(cfd, &session) != 0){ ui_log_error("handshake failed"); close(cfd); close(lfd); return -1; }
	ui_log_info("handshake ok");
	sx_file_t of; int have_meta = 0; uint64_t expect_size = 0; uint64_t received = 0; uint32_t recv_mode = 0644; uint64_t recv_mtime = 0;
	while(1){
		sx_packet_t pkt; if(sx_recv_packet(cfd, &pkt) != 0){ ui_log_warn("recv packet failed"); break; } uint16_t type = ntohs(pkt.hdr.type);
		if(type == SX_PKT_META){
			uint64_t fs; uint32_t mode; uint64_t mt; const char *name; uint16_t nlen;
			if(sx_meta_parse(pkt.payload, pkt.payload_len, &fs, &mode, &mt, &name, &nlen) != 0){ ui_log_error("meta parse failed"); sx_proto_free_packet(&pkt); break; }
			expect_size = fs; recv_mode = mode; recv_mtime = mt; ui_log_info("meta: size=%llu mode=%o name=%.*s", (unsigned long long)fs, (unsigned)mode, (int)nlen, name);
			if(sx_file_open(&of, out_path, O_CREAT | O_TRUNC | O_WRONLY, 0644) != SX_FIO_OK){ ui_log_error("open out failed: %s", out_path); sx_proto_free_packet(&pkt); break; }
			have_meta = 1; sx_proto_free_packet(&pkt);
		} else if(type == SX_PKT_DATA){
			if(!have_meta){ ui_log_warn("data before meta"); sx_proto_free_packet(&pkt); break; }
			uint8_t tag[16]; if(recv(cfd, tag, 16, 0) <= 0){ ui_log_error("tag read failed"); sx_proto_free_packet(&pkt); break; }
			sx_sym_key_t k; memset(&k,0,sizeof(k)); k.cipher = SX_CIPHER_AES_GCM; k.key_len = 32; memcpy(k.key, session.key, 32); memcpy(k.iv, session.iv, 12);
			uint8_t out[131072]; size_t outlen = 0;
			if(sx_crypto_aead_decrypt(&k, pkt.payload, pkt.payload_len, NULL, 0, tag, out, &outlen) != SX_CRYPTO_OK){ ui_log_error("decrypt failed"); sx_proto_free_packet(&pkt); break; }
			if(sx_file_write(&of, out, outlen) <= 0){ ui_log_error("write failed"); sx_proto_free_packet(&pkt); break; }
			received += (uint64_t)outlen; sx_proto_free_packet(&pkt); if(expect_size){ int pct=(int)((received*100.0)/expect_size+0.5); if(pct%10==0) ui_log_info("progress %d%%", pct); if(received >= expect_size){ break; }}
		} else { ui_log_warn("unexpected pkt=%u", type); sx_proto_free_packet(&pkt); break; }
	}
	if(have_meta) sx_file_close(&of); if(recv_mode) chmod(out_path, recv_mode); if(recv_mtime){ struct utimbuf tb; tb.actime = time(NULL); tb.modtime = (time_t)recv_mtime; utime(out_path, &tb); }
	close(cfd); close(lfd);
	if(expect_size && received == expect_size){ ui_log_info("recv done: bytes=%llu", (unsigned long long)received); return 0; } ui_log_error("recv incomplete: got=%llu expect=%llu", (unsigned long long)received, (unsigned long long)expect_size); return -1;
}

int sx_transfer_serve(uint16_t port, const char *out_dir){
	if(!out_dir) return -1;
	if(sx_proto_init() != 0){ ui_log_error("proto init failed"); return -1; }
	if(sx_crypto_init() != SX_CRYPTO_OK){ ui_log_error("crypto init failed"); return -1; }
	int lfd = -1; if(sx_net_bind_tcp(&lfd, NULL, port, 64) != SX_NET_OK){ ui_log_error("bind failed on %u", port); return -1; }
	ui_log_info("serve listening on %u", port);
	while(1){
		struct sockaddr_in peer; socklen_t sl = sizeof(peer);
		int cfd = accept(lfd, (struct sockaddr *)&peer, &sl); if(cfd < 0){ ui_log_warn("accept failed"); continue; }
		ui_log_info("client %s:%u", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
		sx_session_t session; memset(&session,0,sizeof(session)); if(sx_handshake_server(cfd, &session) != 0){ ui_log_warn("handshake failed"); close(cfd); continue; }
		sx_packet_t pkt; int have_meta = 0; uint64_t expect_size = 0; uint64_t received = 0; uint32_t recv_mode = 0644; uint64_t recv_mtime = 0; char out_path[2048]; sx_file_t of;
		while(1){
			if(sx_recv_packet(cfd, &pkt) != 0){ ui_log_warn("recv packet failed"); break; } uint16_t type = ntohs(pkt.hdr.type);
			if(type == SX_PKT_META){
				uint64_t fs; uint32_t mode; uint64_t mt; const char *name; uint16_t nlen;
				if(sx_meta_parse(pkt.payload, pkt.payload_len, &fs, &mode, &mt, &name, &nlen) != 0){ ui_log_error("meta parse failed"); sx_proto_free_packet(&pkt); break; }
				expect_size = fs; recv_mode = mode; recv_mtime = mt; snprintf(out_path, sizeof(out_path), "%s/%.*s", out_dir, (int)nlen, name); ui_log_info("meta: %s size=%llu", out_path, (unsigned long long)fs);
				if(sx_file_open(&of, out_path, O_CREAT | O_TRUNC | O_WRONLY, 0644) != SX_FIO_OK){ ui_log_error("open out failed: %s", out_path); sx_proto_free_packet(&pkt); break; }
				have_meta = 1; sx_proto_free_packet(&pkt);
			} else if(type == SX_PKT_DATA){
				if(!have_meta){ ui_log_warn("data before meta"); sx_proto_free_packet(&pkt); break; }
				uint8_t tag[16]; if(recv(cfd, tag, 16, 0) <= 0){ ui_log_error("tag read failed"); sx_proto_free_packet(&pkt); break; }
				sx_sym_key_t k; memset(&k,0,sizeof(k)); k.cipher = SX_CIPHER_AES_GCM; k.key_len = 32; memcpy(k.key, session.key, 32); memcpy(k.iv, session.iv, 12);
				uint8_t out[131072]; size_t outlen = 0;
				if(sx_crypto_aead_decrypt(&k, pkt.payload, pkt.payload_len, NULL, 0, tag, out, &outlen) != SX_CRYPTO_OK){ ui_log_error("decrypt failed"); sx_proto_free_packet(&pkt); break; }
				if(sx_file_write(&of, out, outlen) <= 0){ ui_log_error("write failed"); sx_proto_free_packet(&pkt); break; }
				received += (uint64_t)outlen; sx_proto_free_packet(&pkt); if(expect_size){ int pct=(int)((received*100.0)/expect_size+0.5); if(pct%10==0) ui_log_info("progress %d%%", pct); if(received >= expect_size){ break; }}
			} else { ui_log_warn("unexpected pkt=%u", type); sx_proto_free_packet(&pkt); break; }
		}
		if(have_meta) sx_file_close(&of); if(recv_mode) chmod(out_path, recv_mode); if(recv_mtime){ struct utimbuf tb; tb.actime = time(NULL); tb.modtime = (time_t)recv_mtime; utime(out_path, &tb); }
		close(cfd);
	}
	close(lfd);
	return 0;
}

