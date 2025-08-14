#ifndef SECUREXFER_KEYEXCHANGE_H
#define SECUREXFER_KEYEXCHANGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SX_KX_OK = 0,
    SX_KX_ERR = -1,
    SX_KX_INVALID = -2
} sx_kx_err_t;

typedef struct sx_kx_ctx {
    uint8_t *local_priv;
    size_t local_priv_len;
    uint8_t *local_pub;
    size_t local_pub_len;
    uint8_t *peer_pub;
    size_t peer_pub_len;
    uint8_t shared_secret[64];
    size_t shared_secret_len;
    int curve_id;
} sx_kx_ctx_t;

int sx_kx_init(sx_kx_ctx_t *ctx, int curve_id);
int sx_kx_generate(sx_kx_ctx_t *ctx);
int sx_kx_set_peer_pub(sx_kx_ctx_t *ctx, const uint8_t *pub, size_t len);
int sx_kx_derive_shared(sx_kx_ctx_t *ctx);
int sx_kx_export_pub(const sx_kx_ctx_t *ctx, uint8_t *out, size_t *out_len);
int sx_kx_free(sx_kx_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif
