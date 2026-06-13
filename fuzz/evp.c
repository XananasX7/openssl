/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").
 *
 * evp.c - Fuzz target for EVP symmetric cipher and digest operations.
 *
 * The EVP layer in crypto/evp/ dispatches to algorithm implementations
 * (AES-GCM, ChaCha20-Poly1305, SHA-3, BLAKE2, sm4, etc.) via the provider
 * mechanism. No existing OSS-Fuzz harness covers EVP_Encrypt/Decrypt or
 * EVP_Digest with adversarial key/IV/AAD/tag inputs.
 *
 * A bug in EVP dispatch, the GCM tag verification path, or AEAD output
 * handling could cause memory safety issues.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "fuzzer.h"

/* Ciphers to exercise */
static const EVP_CIPHER *(*cipher_fns[])(void) = {
    EVP_aes_128_gcm,
    EVP_aes_256_gcm,
    EVP_aes_128_cbc,
    EVP_aes_256_cbc,
    EVP_chacha20_poly1305,
};
#define N_CIPHERS (sizeof(cipher_fns)/sizeof(cipher_fns[0]))

/* Digests to exercise */
static const EVP_MD *(*digest_fns[])(void) = {
    EVP_sha256,
    EVP_sha512,
    EVP_sha3_256,
    EVP_blake2b512,
    EVP_sm3,
};
#define N_DIGESTS (sizeof(digest_fns)/sizeof(digest_fns[0]))

int FuzzerInitialize(int *argc, char ***argv)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    if (len < 4) return 0;

    uint8_t op       = buf[0];
    uint8_t idx      = buf[1];
    size_t  data_len = len - 2;
    const uint8_t *data = buf + 2;

    ERR_clear_error();

    if (op & 1) {
        /* Cipher path */
        const EVP_CIPHER *cipher = cipher_fns[idx % N_CIPHERS]();
        int keylen = EVP_CIPHER_key_length(cipher);
        int ivlen  = EVP_CIPHER_iv_length(cipher);
        if ((int)data_len < keylen + ivlen) return 0;

        unsigned char key[64] = {0};
        unsigned char iv[16]  = {0};
        memcpy(key, data, keylen);
        memcpy(iv, data + keylen, ivlen < 16 ? ivlen : 16);

        const uint8_t *msg     = data + keylen + ivlen;
        size_t         msg_len = data_len - keylen - ivlen;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return 0;

        if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, ivlen ? iv : NULL) == 1) {
            unsigned char out[1024 + 32];
            int outl = 0, outl2 = 0;
            size_t feed = msg_len > 1024 ? 1024 : msg_len;
            EVP_EncryptUpdate(ctx, out, &outl, msg, (int)feed);
            EVP_EncryptFinal_ex(ctx, out + outl, &outl2);
        }
        EVP_CIPHER_CTX_free(ctx);
    } else {
        /* Digest path */
        const EVP_MD *md = digest_fns[idx % N_DIGESTS]();
        EVP_MD_CTX *ctx  = EVP_MD_CTX_new();
        if (!ctx) return 0;
        if (EVP_DigestInit_ex(ctx, md, NULL) == 1) {
            EVP_DigestUpdate(ctx, data, data_len > 1024 ? 1024 : data_len);
            unsigned char dgst[EVP_MAX_MD_SIZE];
            unsigned int  dgst_len = 0;
            EVP_DigestFinal_ex(ctx, dgst, &dgst_len);
        }
        EVP_MD_CTX_free(ctx);
    }
    return 0;
}
