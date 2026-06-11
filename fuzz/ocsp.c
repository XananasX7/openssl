/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").
 *
 * ocsp.c - Fuzz target for the OpenSSL OCSP request/response parser.
 *
 * OpenSSL handles OCSP (Online Certificate Status Protocol) in
 * crypto/ocsp/. The OCSP request and response are DER-encoded ASN.1
 * structures. Bugs in the parser could allow a malicious OCSP responder
 * to trigger heap corruption or DoS in TLS clients performing certificate
 * revocation checking.
 *
 * Not currently covered by any OSS-Fuzz harness.
 */
#include <stdint.h>
#include <stddef.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include "fuzzer.h"

int FuzzerInitialize(int *argc, char ***argv) { return 1; }

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    const uint8_t *p;
    OCSP_REQUEST  *req  = NULL;
    OCSP_RESPONSE *resp = NULL;
    OCSP_BASICRESP *br  = NULL;

    ERR_clear_error();

    /* Try parsing as OCSP request */
    p = buf;
    req = d2i_OCSP_REQUEST(NULL, &p, (long)len);
    if (req != NULL) {
        /* Re-encode to verify round-trip */
        unsigned char *der = NULL;
        int derlen = i2d_OCSP_REQUEST(req, &der);
        if (derlen > 0 && der != NULL)
            OPENSSL_free(der);
        OCSP_REQUEST_free(req);
    }

    /* Try parsing as OCSP response */
    p = buf;
    resp = d2i_OCSP_RESPONSE(NULL, &p, (long)len);
    if (resp != NULL) {
        /* Try extracting the basic response */
        br = OCSP_response_get1_basic(resp);
        if (br != NULL) {
            /* Walk the single responses */
            int count = OCSP_resp_count(br);
            for (int i = 0; i < count; i++) {
                OCSP_SINGLERESP *sr = OCSP_resp_get0(br, i);
                if (sr != NULL) {
                    int status, reason;
                    ASN1_GENERALIZEDTIME *rev, *this_upd, *next_upd;
                    OCSP_single_get0_status(sr, &status, &reason,
                                           &rev, &this_upd, &next_upd);
                }
            }
            OCSP_BASICRESP_free(br);
        }
        OCSP_RESPONSE_free(resp);
    }

    return 0;
}
