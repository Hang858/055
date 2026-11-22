/* Copyright (c) 2026 Hang Zhang. */
#ifndef BIT_PRECOMP_H
#define BIT_PRECOMP_H
#include "parabola.h"

#define BIT_SIGN_PRECOMP_OK 0
#define BIT_SIGN_PRECOMP_REJECT 1
#define BIT_SIGN_PRECOMP_ERROR (-1)

/* Secret, single-use candidate. Do not copy, serialize, share or roll back it.
 * Input/output buffers must not overlap this object. */
typedef struct {
    union {
        bit_parabola_fixed mask;
        struct {
            polyvecm1 response;
            polyveck tail;
            polyveck hint;
        } accepted;
    } phase;
    polyveck w;
    unsigned char key_tag[BIT_TRBYTES];
    unsigned char seed[BIT_SEEDBYTES];
    uint16_t nonce;
    uint8_t b;
    uint8_t ready;
} bit_sign_precomp;

/* Prepare a message-independent candidate. Erases the object on failure. */
int bit_sig_sign_precompute(const unsigned char *sk, unsigned long long sklen,
                            bit_sign_precomp *candidate);
/* Every call consumes the candidate, including rejection and invalid inputs.
 * REJECT requires a new candidate; ERROR must not be retried with the old one.
 * Discard the signature buffer unless OK is returned. */
int bit_sig_sign_online(const unsigned char *sk, unsigned long long sklen,
                        const unsigned char *message, unsigned long long mlen,
                        bit_sign_precomp *candidate, unsigned char *sig,
                        unsigned long long *siglen);
void bit_sig_sign_precomp_clear(bit_sign_precomp *candidate);
#endif
