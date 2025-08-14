#include "core/keyexchange.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

int sx_kx_init(sx_kx_ctx_t *ctx, int curve_id){
    if(!ctx) return SX_KX_ERR;
    memset(ctx,0,sizeof(*ctx));
    ctx->curve_id = curve_id;
    return SX_KX_OK;
}

int sx_kx_generate(sx_kx_ctx_t *ctx){
    if(!ctx) return SX_KX_ERR;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if(!pctx) return SX_KX_ERR;
    if(EVP_PKEY_keygen_init(pctx) <= 0){ EVP_PKEY_CTX_free(pctx); return SX_KX_ERR; }
    EVP_PKEY *pkey = NULL;
    if(EVP_PKEY_keygen(pctx, &pkey) <= 0){ EVP_PKEY_CTX_free(pctx); return SX_KX_ERR; }
    size_t priv_len = 0, pub_len = 0;
    EVP_PKEY_get_raw_private_key(pkey, NULL, &priv_len);
    EVP_PKEY_get_raw_public_key(pkey, NULL, &pub_len);
    ctx->local_priv = malloc(priv_len);
    ctx->local_pub = malloc(pub_len);
    if(!ctx->local_priv || !ctx->local_pub){ if(ctx->local_priv) free(ctx->local_priv); if(ctx->local_pub) free(ctx->local_pub); EVP_PKEY_free(pkey); EVP_PKEY_CTX_free(pctx); return SX_KX_ERR; }
    if(EVP_PKEY_get_raw_private_key(pkey, ctx->local_priv, &priv_len) <= 0){ free(ctx->local_priv); free(ctx->local_pub); EVP_PKEY_free(pkey); EVP_PKEY_CTX_free(pctx); return SX_KX_ERR; }
    if(EVP_PKEY_get_raw_public_key(pkey, ctx->local_pub, &pub_len) <= 0){ free(ctx->local_priv); free(ctx->local_pub); EVP_PKEY_free(pkey); EVP_PKEY_CTX_free(pctx); return SX_KX_ERR; }
    ctx->local_priv_len = priv_len;
    ctx->local_pub_len = pub_len;
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return SX_KX_OK;
}

int sx_kx_set_peer_pub(sx_kx_ctx_t *ctx, const uint8_t *pub, size_t len){
    if(!ctx || !pub || !len) return SX_KX_ERR;
    ctx->peer_pub = malloc(len);
    if(!ctx->peer_pub) return SX_KX_ERR;
    memcpy(ctx->peer_pub, pub, len);
    ctx->peer_pub_len = len;
    return SX_KX_OK;
}

int sx_kx_derive_shared(sx_kx_ctx_t *ctx){
    if(!ctx || !ctx->local_priv || !ctx->peer_pub) return SX_KX_ERR;
    EVP_PKEY *local = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, ctx->local_priv, ctx->local_priv_len);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, ctx->peer_pub, ctx->peer_pub_len);
    if(!local || !peer){ if(local) EVP_PKEY_free(local); if(peer) EVP_PKEY_free(peer); return SX_KX_ERR; }
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(local, NULL);
    if(!pctx){ EVP_PKEY_free(local); EVP_PKEY_free(peer); return SX_KX_ERR; }
    if(EVP_PKEY_derive_init(pctx) <= 0){ EVP_PKEY_CTX_free(pctx); EVP_PKEY_free(local); EVP_PKEY_free(peer); return SX_KX_ERR; }
    if(EVP_PKEY_derive_set_peer(pctx, peer) <= 0){ EVP_PKEY_CTX_free(pctx); EVP_PKEY_free(local); EVP_PKEY_free(peer); return SX_KX_ERR; }
    size_t secret_len = 0;
    if(EVP_PKEY_derive(pctx, NULL, &secret_len) <= 0){ EVP_PKEY_CTX_free(pctx); EVP_PKEY_free(local); EVP_PKEY_free(peer); return SX_KX_ERR; }
    if(secret_len > sizeof(ctx->shared_secret)) secret_len = sizeof(ctx->shared_secret);
    if(EVP_PKEY_derive(pctx, ctx->shared_secret, &secret_len) <= 0){ EVP_PKEY_CTX_free(pctx); EVP_PKEY_free(local); EVP_PKEY_free(peer); return SX_KX_ERR; }
    ctx->shared_secret_len = secret_len;
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(local);
    EVP_PKEY_free(peer);
    return SX_KX_OK;
}

int sx_kx_export_pub(const sx_kx_ctx_t *ctx, uint8_t *out, size_t *out_len){
    if(!ctx || !ctx->local_pub || !out || !out_len) return SX_KX_ERR;
    if(*out_len < ctx->local_pub_len) return SX_KX_ERR;
    memcpy(out, ctx->local_pub, ctx->local_pub_len);
    *out_len = ctx->local_pub_len;
    return SX_KX_OK;
}

int sx_kx_free(sx_kx_ctx_t *ctx){
    if(!ctx) return SX_KX_ERR;
    if(ctx->local_priv){ free(ctx->local_priv); ctx->local_priv = NULL; ctx->local_priv_len = 0; }
    if(ctx->local_pub){ free(ctx->local_pub); ctx->local_pub = NULL; ctx->local_pub_len = 0; }
    if(ctx->peer_pub){ free(ctx->peer_pub); ctx->peer_pub = NULL; ctx->peer_pub_len = 0; }
    memset(ctx->shared_secret,0,sizeof(ctx->shared_secret));
    ctx->shared_secret_len = 0;
    return SX_KX_OK;
}
