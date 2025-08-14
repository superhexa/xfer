#include "core/crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <string.h>

int sx_crypto_init(void){
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    return SX_CRYPTO_OK;
}

int sx_crypto_generate_sym(sx_sym_key_t *out, sx_cipher_t cipher){
    if(!out) return SX_CRYPTO_ERR;
    out->cipher = cipher;
    if(cipher == SX_CIPHER_AES_GCM){
        out->key_len = 32;
        if(RAND_bytes(out->key, out->key_len) != 1) return SX_CRYPTO_ERR;
        if(RAND_bytes(out->iv, SX_IV_BYTES) != 1) return SX_CRYPTO_ERR;
        return SX_CRYPTO_OK;
    }
    if(cipher == SX_CIPHER_CHACHA20_POLY1305){
        out->key_len = 32;
        if(RAND_bytes(out->key, out->key_len) != 1) return SX_CRYPTO_ERR;
        if(RAND_bytes(out->iv, SX_IV_BYTES) != 1) return SX_CRYPTO_ERR;
        return SX_CRYPTO_OK;
    }
    return SX_CRYPTO_INVALID_KEY;
}

static int aead_do_encrypt(const sx_sym_key_t *k, const uint8_t *plaintext, size_t plen, const uint8_t *aad, size_t aad_len, uint8_t *out, size_t *out_len, uint8_t *tag){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cipher = NULL;
    if(k->cipher == SX_CIPHER_AES_GCM) cipher = EVP_aes_256_gcm();
    else cipher = EVP_chacha20_poly1305();
    if(!ctx) return SX_CRYPTO_ERR;
    if(EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) { EVP_CIPHER_CTX_free(ctx); return SX_CRYPTO_ERR; }
    if(k->cipher == SX_CIPHER_AES_GCM){
        if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SX_IV_BYTES, NULL) != 1){ EVP_CIPHER_CTX_free(ctx); return SX_CRYPTO_ERR; }
    }
    if(EVP_EncryptInit_ex(ctx, NULL, NULL, k->key, k->iv) != 1){ EVP_CIPHER_CTX_free(ctx); return SX_CRYPTO_ERR; }
    int len = 0;
    if(aad && aad_len){
        if(EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1){ EVP_CIPHER_CTX_free(ctx); return SX_CRYPTO_ERR; }
    }
    int outl = 0;
    if(plen){
        if(EVP_EncryptUpdate(ctx, out, &outl, plaintext, (int)plen) != 1){ EVP_CIPHER_CTX_free(ctx); return SX_CRYPTO_ERR; }
    }
    int tmplen = 0;
    if(EVP_EncryptFinal_ex(ctx, out + outl, &tmplen) != 1){ EVP_CIPHER_CTX_free(ctx); return SX_CRYPTO_AEAD_FAIL; }
    outl += tmplen;
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, SX_TAG_BYTES, tag) != 1){ EVP_CIPHER_CTX_free(ctx); return SX_CRYPTO_AEAD_FAIL; }
    *out_len = (size_t)outl;
    EVP_CIPHER_CTX_free(ctx);
    return SX_CRYPTO_OK;
}

static int aead_do_decrypt(const sx_sym_key_t *k, const uint8_t *ciphertext, size_t clen, const uint8_t *aad, size_t aad_len, const uint8_t *tag, uint8_t *out, size_t *out_len){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cipher = NULL;
    if(k->cipher == SX_CIPHER_AES_GCM) cipher = EVP_aes_256_gcm();
    else cipher = EVP_chacha20_poly1305();
    if(!ctx) return SX_CRYPTO_ERR;
    if(EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1){ EVP_CIPHER_CTX_free(ctx); return SX_CRYPTO_ERR; }
    if(k->cipher == SX_CIPHER_AES_GCM){
        if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SX_IV_BYTES, NULL) != 1){ EVP_CIPHER_CTX_free(ctx); return SX_CRYPTO_ERR; }
    }
    if(EVP_DecryptInit_ex(ctx, NULL, NULL, k->key, k->iv) != 1){ EVP_CIPHER_CTX_free(ctx); return SX_CRYPTO_ERR; }
    int len = 0;
    if(aad && aad_len){
        if(EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1){ EVP_CIPHER_CTX_free(ctx); return SX_CRYPTO_ERR; }
    }
    int outl = 0;
    if(clen){
        if(EVP_DecryptUpdate(ctx, out, &outl, ciphertext, (int)clen) != 1){ EVP_CIPHER_CTX_free(ctx); return SX_CRYPTO_ERR; }
    }
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, SX_TAG_BYTES, (void *)tag) != 1){ EVP_CIPHER_CTX_free(ctx); return SX_CRYPTO_ERR; }
    int tmplen = 0;
    int rv = EVP_DecryptFinal_ex(ctx, out + outl, &tmplen);
    if(rv != 1){ EVP_CIPHER_CTX_free(ctx); return SX_CRYPTO_AEAD_FAIL; }
    outl += tmplen;
    *out_len = (size_t)outl;
    EVP_CIPHER_CTX_free(ctx);
    return SX_CRYPTO_OK;
}

int sx_crypto_aead_encrypt(const sx_sym_key_t *k, const uint8_t *plaintext, size_t plen, const uint8_t *aad, size_t aad_len, uint8_t *out, size_t *out_len, uint8_t *tag){
    if(!k || !plaintext || !out || !out_len || !tag) return SX_CRYPTO_ERR;
    return aead_do_encrypt(k, plaintext, plen, aad, aad_len, out, out_len, tag);
}

int sx_crypto_aead_decrypt(const sx_sym_key_t *k, const uint8_t *ciphertext, size_t clen, const uint8_t *aad, size_t aad_len, const uint8_t *tag, uint8_t *out, size_t *out_len){
    if(!k || !ciphertext || !out || !out_len || !tag) return SX_CRYPTO_ERR;
    return aead_do_decrypt(k, ciphertext, clen, aad, aad_len, tag, out, out_len);
}

int sx_crypto_load_pem_key(const char *path, sx_asym_keypair_t *kp){
    FILE *f = fopen(path, "rb");
    if(!f) return SX_CRYPTO_ERR;
    EVP_PKEY *p = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    if(!p){
        rewind(f);
        EVP_PKEY *pub = PEM_read_PUBKEY(f, NULL, NULL, NULL);
        if(!pub){ fclose(f); return SX_CRYPTO_ERR; }
        BIO *bio = BIO_new(BIO_s_mem());
        if(!bio){ EVP_PKEY_free(pub); fclose(f); return SX_CRYPTO_ERR; }
        if(PEM_write_bio_PUBKEY(bio, pub) != 1){ BIO_free(bio); EVP_PKEY_free(pub); fclose(f); return SX_CRYPTO_ERR; }
        BUF_MEM *bptr;
        BIO_get_mem_ptr(bio, &bptr);
        kp->pub = malloc(bptr->length);
        memcpy(kp->pub, bptr->data, bptr->length);
        kp->pub_len = bptr->length;
        BIO_free(bio);
        EVP_PKEY_free(pub);
        fclose(f);
        return SX_CRYPTO_OK;
    }
    BIO *bio = BIO_new(BIO_s_mem());
    if(!bio){ EVP_PKEY_free(p); fclose(f); return SX_CRYPTO_ERR; }
    if(PEM_write_bio_PrivateKey(bio, p, NULL, NULL, 0, NULL, NULL) != 1){ BIO_free(bio); EVP_PKEY_free(p); fclose(f); return SX_CRYPTO_ERR; }
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    kp->priv = malloc(bptr->length);
    memcpy(kp->priv, bptr->data, bptr->length);
    kp->priv_len = bptr->length;
    BIO_free(bio);
    EVP_PKEY_free(p);
    fclose(f);
    return SX_CRYPTO_OK;
}

int sx_crypto_free_asym(sx_asym_keypair_t *kp){
    if(!kp) return SX_CRYPTO_ERR;
    if(kp->priv){ free(kp->priv); kp->priv = NULL; kp->priv_len = 0; }
    if(kp->pub){ free(kp->pub); kp->pub = NULL; kp->pub_len = 0; }
    return SX_CRYPTO_OK;
}

int sx_crypto_hash_sha256(const uint8_t *data, size_t dlen, uint8_t out[32]){
    if(!data || !out) return SX_CRYPTO_ERR;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(!ctx) return SX_CRYPTO_ERR;
    if(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1){ EVP_MD_CTX_free(ctx); return SX_CRYPTO_ERR; }
    if(EVP_DigestUpdate(ctx, data, dlen) != 1){ EVP_MD_CTX_free(ctx); return SX_CRYPTO_ERR; }
    unsigned int olen = 0;
    if(EVP_DigestFinal_ex(ctx, out, &olen) != 1){ EVP_MD_CTX_free(ctx); return SX_CRYPTO_ERR; }
    EVP_MD_CTX_free(ctx);
    return SX_CRYPTO_OK;
}

int sx_crypto_hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *data, size_t dlen, uint8_t out[32]){
    unsigned int len = 0;
    if(!HMAC(EVP_sha256(), key, (int)klen, data, dlen, out, &len)) return SX_CRYPTO_ERR;
    return SX_CRYPTO_OK;
}
