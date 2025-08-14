#include "core/client.h"
#include "utils/netutils.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

static void *sx_client_reader(void *arg){
    sx_client_ctx_t *ctx = (sx_client_ctx_t *)arg;
    uint8_t buf[4096];
    while(ctx->running){
        ssize_t r = recv(ctx->peer.fd, buf, sizeof(buf), 0);
        if(r <= 0) break;
        if(ctx->on_receive) ctx->on_receive(ctx, buf, (size_t)r);
    }
    ctx->running = 0;
    if(ctx->on_disconnect) ctx->on_disconnect(ctx);
    return NULL;
}

static void *sx_client_writer(void *arg){
    (void)arg;
    return NULL;
}

sx_cli_err_t sx_client_init(sx_client_ctx_t *ctx, const sx_client_cfg_t *cfg){
    if(!ctx || !cfg) return SX_CLI_ERR;
    memset(ctx,0,sizeof(*ctx));
    ctx->cfg = *cfg;
    ctx->peer.fd = -1;
    pthread_mutex_init(&ctx->peer.lock, NULL);
    return SX_CLI_OK;
}

sx_cli_err_t sx_client_connect(sx_client_ctx_t *ctx){
    if(!ctx) return SX_CLI_ERR;
    if(sx_net_connect_tcp(&ctx->peer.fd, ctx->cfg.server_host, ctx->cfg.server_port, (int)ctx->cfg.retry_interval_ms) != SX_NET_OK) return SX_CLI_CONN_FAIL;
    ctx->peer.connected = 1;
    ctx->running = 1;
    pthread_create(&ctx->reader_thread, NULL, sx_client_reader, ctx);
    pthread_create(&ctx->writer_thread, NULL, sx_client_writer, ctx);
    return SX_CLI_OK;
}

sx_cli_err_t sx_client_send(sx_client_ctx_t *ctx, const void *buf, size_t len){
    if(!ctx || ctx->peer.fd < 0) return SX_CLI_ERR;
    ssize_t w = send(ctx->peer.fd, buf, len, 0);
    if(w <= 0) return SX_CLI_ERR;
    return SX_CLI_OK;
}

sx_cli_err_t sx_client_close(sx_client_ctx_t *ctx){
    if(!ctx) return SX_CLI_ERR;
    ctx->running = 0;
    if(ctx->peer.fd >= 0) close(ctx->peer.fd);
    ctx->peer.fd = -1;
    return SX_CLI_OK;
}

sx_cli_err_t sx_client_destroy(sx_client_ctx_t *ctx){
    if(!ctx) return SX_CLI_ERR;
    pthread_cancel(ctx->reader_thread);
    pthread_cancel(ctx->writer_thread);
    pthread_mutex_destroy(&ctx->peer.lock);
    return SX_CLI_OK;
}
