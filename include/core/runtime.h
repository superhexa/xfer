#ifndef SECUREXFER_RUNTIME_H
#define SECUREXFER_RUNTIME_H

#include <stdint.h>
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sx_runtime_cfg {
	uint32_t default_port;
	uint32_t chunk_size;
	uint32_t throttle_kbps;
	int encryption_enabled;
	int compression_enabled;
	uint32_t streams;
	char auth_token[256];
	uint32_t io_timeout_ms;
	uint32_t connect_timeout_ms;
	uint32_t max_retries;
	int keepalive_enabled;
	int verify_enabled;
	sx_cipher_t cipher;
	int zlib_level;
	int progress_style;
	int preserve_mode;
	int preserve_mtime;
	int overwrite_policy;
	uint32_t log_level;
} sx_runtime_cfg_t;

sx_runtime_cfg_t *sx_runtime_cfg_get(void);
void sx_runtime_cfg_set_chunk(uint32_t bytes);
void sx_runtime_cfg_set_port(uint32_t port);
void sx_runtime_cfg_set_throttle(uint32_t kbps);
void sx_runtime_cfg_set_encrypt(int enabled);
void sx_runtime_cfg_set_compress(int enabled);
void sx_runtime_cfg_set_streams(uint32_t num);
void sx_runtime_cfg_set_auth(const char *token);
void sx_runtime_cfg_set_cipher(sx_cipher_t c);
void sx_runtime_cfg_set_zlevel(int level);
void sx_runtime_cfg_set_verify(int enabled);
void sx_runtime_cfg_set_progress_style(int style);
void sx_runtime_cfg_set_io_timeout(uint32_t ms);
void sx_runtime_cfg_set_connect_timeout(uint32_t ms);
void sx_runtime_cfg_set_retries(uint32_t n);
void sx_runtime_cfg_set_keepalive(int enabled);
void sx_runtime_cfg_set_overwrite_policy(int policy);
void sx_runtime_cfg_set_preserve_mode(int enabled);
void sx_runtime_cfg_set_preserve_mtime(int enabled);
void sx_runtime_cfg_set_loglevel(uint32_t lvl);

#ifdef __cplusplus
}
#endif

#endif