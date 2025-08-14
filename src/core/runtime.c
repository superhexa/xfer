#include "core/runtime.h"
#include <string.h>

static sx_runtime_cfg_t g_cfg = {
	.default_port = 9000,
	.chunk_size = 64 * 1024,
	.throttle_kbps = 0,
	.encryption_enabled = 1,
	.compression_enabled = 0,
	.streams = 1,
	.auth_token = {0},
	.io_timeout_ms = 30000,
	.connect_timeout_ms = 5000,
	.max_retries = 3,
	.keepalive_enabled = 1,
	.verify_enabled = 0,
	.cipher = SX_CIPHER_AES_GCM,
	.zlib_level = 6,
	.progress_style = 1,
	.preserve_mode = 1,
	.preserve_mtime = 1,
	.overwrite_policy = 1,
	.log_level = 1,
};

sx_runtime_cfg_t *sx_runtime_cfg_get(void){
	return &g_cfg;
}

void sx_runtime_cfg_set_chunk(uint32_t bytes){ g_cfg.chunk_size = bytes ? bytes : (64*1024); }
void sx_runtime_cfg_set_port(uint32_t port){ g_cfg.default_port = port ? port : 9000; }
void sx_runtime_cfg_set_throttle(uint32_t kbps){ g_cfg.throttle_kbps = kbps; }
void sx_runtime_cfg_set_encrypt(int enabled){ g_cfg.encryption_enabled = enabled ? 1 : 0; }
void sx_runtime_cfg_set_compress(int enabled){ g_cfg.compression_enabled = enabled ? 1 : 0; }
void sx_runtime_cfg_set_streams(uint32_t num){ g_cfg.streams = num ? num : 1; }
void sx_runtime_cfg_set_auth(const char *token){ if(token){ strncpy(g_cfg.auth_token, token, sizeof(g_cfg.auth_token)-1); g_cfg.auth_token[sizeof(g_cfg.auth_token)-1] = 0; } }
void sx_runtime_cfg_set_cipher(sx_cipher_t c){ g_cfg.cipher = c; }
void sx_runtime_cfg_set_zlevel(int level){ if(level < 0) level = 0; if(level > 9) level = 9; g_cfg.zlib_level = level; }
void sx_runtime_cfg_set_verify(int enabled){ g_cfg.verify_enabled = enabled ? 1 : 0; }
void sx_runtime_cfg_set_progress_style(int style){ g_cfg.progress_style = style; }
void sx_runtime_cfg_set_io_timeout(uint32_t ms){ g_cfg.io_timeout_ms = ms; }
void sx_runtime_cfg_set_connect_timeout(uint32_t ms){ g_cfg.connect_timeout_ms = ms; }
void sx_runtime_cfg_set_retries(uint32_t n){ g_cfg.max_retries = n; }
void sx_runtime_cfg_set_keepalive(int enabled){ g_cfg.keepalive_enabled = enabled ? 1 : 0; }
void sx_runtime_cfg_set_overwrite_policy(int policy){ g_cfg.overwrite_policy = policy; }
void sx_runtime_cfg_set_preserve_mode(int enabled){ g_cfg.preserve_mode = enabled ? 1 : 0; }
void sx_runtime_cfg_set_preserve_mtime(int enabled){ g_cfg.preserve_mtime = enabled ? 1 : 0; }
void sx_runtime_cfg_set_loglevel(uint32_t lvl){ g_cfg.log_level = lvl; }