#ifndef SECUREXFER_CRYPTO_H
#define SECUREXFER_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SX_KEY_BYTES 32
#define SX_IV_BYTES 12
#define SX_TAG_BYTES 16
#define SX_PEM_MAX 4096

typedef enum {
    SX_CRYPTO_OK = 0,
    SX_CRYPTO_ERR = -1,
    SX_CRYPTO_INVALID_KEY = -2,
    SX_CRYPTO_AEAD_FAIL = -3
} sx_crypto_err_t;

typedef enum {
    SX_CIPHER_AES_GCM = 1,
    SX_CIPHER_CHACHA20_POLY1305 = 2
} sx_cipher_t;

typedef struct sx_sym_key {
    uint8_t key[SX_KEY_BYTES];
    uint8_t iv[SX_IV_BYTES];
    sx_cipher_t cipher;
    size_t key_len;
} sx_sym_key_t;

typedef struct sx_asym_keypair {
    uint8_t *priv;
    size_t priv_len;
    uint8_t *pub;
    size_t pub_len;
} sx_asym_keypair_t;

int sx_crypto_init(void);
int sx_crypto_generate_sym(sx_sym_key_t *out, sx_cipher_t cipher);
int sx_crypto_aead_encrypt(const sx_sym_key_t *k, const uint8_t *plaintext, size_t plen, const uint8_t *aad, size_t aad_len, uint8_t *out, size_t *out_len, uint8_t *tag);
int sx_crypto_aead_decrypt(const sx_sym_key_t *k, const uint8_t *ciphertext, size_t clen, const uint8_t *aad, size_t aad_len, const uint8_t *tag, uint8_t *out, size_t *out_len);
int sx_crypto_load_pem_key(const char *path, sx_asym_keypair_t *kp);
int sx_crypto_free_asym(sx_asym_keypair_t *kp);
int sx_crypto_hash_sha256(const uint8_t *data, size_t dlen, uint8_t out[32]);
int sx_crypto_hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *data, size_t dlen, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif
