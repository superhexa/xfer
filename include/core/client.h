#ifndef SECUREXFER_CLIENT_H
#define SECUREXFER_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SX_CLI_OK = 0,
    SX_CLI_ERR = -1,
    SX_CLI_CONN_FAIL = -2,
    SX_CLI_PROTO_ERR = -3
} sx_cli_err_t;

typedef struct sx_peer {
    char host[256];
    uint16_t port;
    struct sockaddr_in addr;
    int fd;
    int connected;
    pthread_mutex_t lock;
} sx_peer_t;

typedef struct sx_client_cfg {
    char server_host[256];
    uint16_t server_port;
    int reconnect;
    size_t retry_interval_ms;
    int use_tls;
    const char *cert_path;
} sx_client_cfg_t;

typedef struct sx_client_ctx {
    sx_peer_t peer;
    sx_client_cfg_t cfg;
    pthread_t reader_thread;
    pthread_t writer_thread;
    volatile int running;
    void *user;
    int (*on_receive)(struct sx_client_ctx *, const void *, size_t);
    void (*on_disconnect)(struct sx_client_ctx *);
    int (*on_error)(struct sx_client_ctx *, int);
} sx_client_ctx_t;

sx_cli_err_t sx_client_init(sx_client_ctx_t *ctx, const sx_client_cfg_t *cfg);
sx_cli_err_t sx_client_connect(sx_client_ctx_t *ctx);
sx_cli_err_t sx_client_send(sx_client_ctx_t *ctx, const void *buf, size_t len);
sx_cli_err_t sx_client_close(sx_client_ctx_t *ctx);
sx_cli_err_t sx_client_destroy(sx_client_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif
