#ifndef SECUREXFER_COMMANDS_H
#define SECUREXFER_COMMANDS_H

#include <stdint.h>
#include <stddef.h>
#include "transfer.h"
#include "client.h"
#include "server.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SX_CMD_OK = 0,
    SX_CMD_ERR = -1,
    SX_CMD_INVALID = -2
} sx_cmd_err_t;

typedef struct sx_cmd_ctx {
    sx_server_t *server;
    sx_client_ctx_t *client;
    sx_transfer_t *transfer;
    void *user;
} sx_cmd_ctx_t;

int sx_cmd_send_file(sx_cmd_ctx_t *ctx, const char *path, const char *addr, uint16_t port);
int sx_cmd_receive_start(sx_cmd_ctx_t *ctx, const char *out_dir);
int sx_cmd_list_sessions(sx_cmd_ctx_t *ctx);
int sx_cmd_stop_session(sx_cmd_ctx_t *ctx, uint64_t session_id);
int sx_cmd_set_config(sx_cmd_ctx_t *ctx, const char *key, const char *value);

int sx_cmd_set_chunk(uint32_t bytes);
int sx_cmd_set_encrypt(int enabled);
int sx_cmd_set_throttle(uint32_t kbps);
int sx_cmd_show_config(void);
int sx_cmd_hash_file(const char *path);
int sx_cmd_resume(const char *host, uint16_t port, const char *path, uint64_t offset);
int sx_cmd_progress(void);
int sx_cmd_version(void);
int sx_cmd_ping(const char *host, uint16_t port);
int sx_cmd_recv_once(uint16_t port, const char *outfile);

#ifdef __cplusplus
}
#endif

#endif
