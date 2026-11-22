/* Copyright (c) 2026 Hang Zhang. */
#include <stddef.h>
#include <string.h>
#include "precomp.h"
#include "packing.h"
#include "sample.h"
#include "symmetric.h"
#include "drng.h"
#include "../../common/ct_audit.h"

#if BIT_SECURITY_BITS != 128 || BIT_IMPL_AVX
#error "Precomputed signing is available for the 128-bit C reference only"
#endif

extern DRNG_ctx drng_algorithm;

void bit_sig_sign_precomp_clear(bit_sign_precomp *candidate)
{
    if (candidate != NULL)
        bit_secure_zero(candidate, sizeof(*candidate));
}

static void round_mask(polyvecy *y, const bit_parabola_fixed *mask)
{
    for (int i = 0; i < BIT_PARABOLA_BLOCKS; i++)
        for (int j = 0; j < BIT_N; j++)
            y->vec[i].coeffs[j] = bit_round_q13_to_i16(mask->coeffs[i][j]);
}

static int key_binding_tag(unsigned char tag[BIT_TRBYTES], const unsigned char *sk)
{
    sha3_256incctx state;
    sha3_256_inc_init(&state);
    sha3_256_inc_absorb(&state, sk, BIT_SECRETKEYBYTES);
    sha3_256_inc_finalize(tag, &state);
    bit_secure_zero(&state, sizeof(state));
    return 0;
}

/* Separate frames keep key validation and Gaussian sampling disjoint. */
static __attribute__((noinline)) int
prepare_seed(const unsigned char *sk, bit_sign_precomp *candidate)
{
    static const unsigned char domain[BIT_MESSAGEBYTES] = "BiT-128 offline signing v1";
    unsigned char seed_A[BIT_SEEDBYTES], secret_seed[BIT_SEEDBYTES];
    unsigned char tr[BIT_TRBYTES], rnd[BIT_SEEDBYTES + 1];
    polyveck public_vector, e;
    polyvecl s;
    int result = -1;

    if (unpack_sk(seed_A, &public_vector, secret_seed, tr, &s, &e, sk) != 0 ||
        key_binding_tag(candidate->key_tag, sk) != 0 ||
        get_random_number(&drng_algorithm, rnd, sizeof(rnd) * 8ULL) != 0)
        goto cleanup;
    if (bit_xof256_3(candidate->seed, BIT_SEEDBYTES,
                     secret_seed, sizeof(secret_seed), rnd, BIT_SEEDBYTES,
                     domain, sizeof(domain)) != 0)
        goto cleanup;
    candidate->b = rnd[BIT_SEEDBYTES] & 1U;
    result = 0;
cleanup:
    bit_secure_zero(seed_A, sizeof(seed_A));
    bit_secure_zero(secret_seed, sizeof(secret_seed));
    bit_secure_zero(tr, sizeof(tr));
    bit_secure_zero(rnd, sizeof(rnd));
    bit_secure_zero(&s, sizeof(s));
    bit_secure_zero(&e, sizeof(e));
    return result;
}

static __attribute__((noinline)) int
prepare_commitment(const unsigned char *sk, bit_sign_precomp *candidate)
{
    unsigned char seed_A[BIT_SEEDBYTES];
    poly_matrix_ntt matrix;
    polyveck_ntt public_ntt;
    poly_ntt y0_ntt;
    polyvecy y;
    union {
        polyveck public_vector;
        polyvecl_ntt y1_ntt;
    } scratch;
    int result = -1;

    if (unpack_pk(seed_A, &scratch.public_vector, sk) != 0 ||
        poly_matrix_expand_ntt(&matrix, seed_A) != 0)
        goto cleanup;
    polyveck_public_to_ntt(&public_ntt, &scratch.public_vector);
    round_mask(&y, &candidate->phase.mask);
    polyvecy_y1_to_ntt(&scratch.y1_ntt, &y);
    poly_to_ntt(&y0_ntt, &y.vec[0]);
    polyveck_compute_w_ntt(&candidate->w, &matrix, &public_ntt,
                           &scratch.y1_ntt, &y0_ntt, &y);
    result = 0;
cleanup:
    bit_secure_zero(&y, sizeof(y));
    bit_secure_zero(&scratch, sizeof(scratch));
    bit_secure_zero(&y0_ntt, sizeof(y0_ntt));
    return result;
}

int bit_sig_sign_precompute(const unsigned char *sk, unsigned long long sklen,
                            bit_sign_precomp *candidate)
{
    if (candidate == NULL)
        return -1;
    bit_sig_sign_precomp_clear(candidate);
    if (sk == NULL || sklen != BIT_SECRETKEYBYTES ||
        prepare_seed(sk, candidate) != 0 ||
        bit_parabola_sample_fixed(&candidate->phase.mask, candidate->seed,
                                  &candidate->nonce) != 0 ||
        prepare_commitment(sk, candidate) != 0) {
        bit_sig_sign_precomp_clear(candidate);
        return -1;
    }
    candidate->ready = 1;
    return 0;
}

static __attribute__((noinline)) int
unpack_online(const unsigned char *sk, unsigned char tr[BIT_TRBYTES],
               polyvecl *s, polyveck *e)
{
    unsigned char seed_A[BIT_SEEDBYTES], secret_seed[BIT_SEEDBYTES];
    polyveck public_vector;
    int result = unpack_sk(seed_A, &public_vector, secret_seed, tr, s, e, sk);
    bit_secure_zero(secret_seed, sizeof(secret_seed));
    return result;
}

int bit_sig_sign_online(const unsigned char *sk, unsigned long long sklen,
                        const unsigned char *message, unsigned long long mlen,
                        bit_sign_precomp *candidate, unsigned char *sig,
                        unsigned long long *siglen)
{
    unsigned char key_tag[BIT_TRBYTES], tr[BIT_TRBYTES];
    unsigned char challenge[BIT_CHALLENGEBYTES];
    unsigned char hash_input[BIT_MESSAGEBYTES + BIT_POLYVECK_W1_BYTES];
    polyvecl s, c_s;
    polyveck e, c_e, w1;
    polyvecy y;
    poly c;
    sparse_challenge sparse;
    uint32_t mismatch = 0;
    int result = -1;
    int reject;

    if (siglen != NULL)
        *siglen = 0;
    if (candidate == NULL)
        return -1;
    if (candidate->ready != 1)
        goto cleanup;
    candidate->ready = 0;
    if (sk == NULL || sig == NULL || siglen == NULL ||
        sklen != BIT_SECRETKEYBYTES || (message == NULL && mlen != 0) ||
        mlen > SIZE_MAX - BIT_TRBYTES || candidate->b > 1)
        goto cleanup;
    if (message == NULL)
        message = (const unsigned char *)"";
    if (key_binding_tag(key_tag, sk) != 0)
        goto cleanup;
    for (size_t i = 0; i < sizeof(key_tag); i++)
        mismatch |= key_tag[i] ^ candidate->key_tag[i];
    if (mismatch != 0 || unpack_online(sk, tr, &s, &e) != 0)
        goto cleanup;
    if (bit_hash_message(hash_input, tr, sizeof(tr), message, (size_t)mlen) != 0)
        goto cleanup;
    polyveck_highbits(&w1, &candidate->w);
    polyveck_pack_w1(hash_input + BIT_MESSAGEBYTES, &w1);
    if (bit_hash(challenge, hash_input, sizeof(hash_input)) != 0 ||
        poly_challenge(&c, challenge) != 0)
        goto cleanup;
    poly_challenge_to_sparse(&sparse, &c);
    sparse.bflip = candidate->b;
    poly_cneg(&c, candidate->b);
    polyvecl_mul_challenge_no_reduce(&c_s, &s, &sparse);
    polyveck_mul_challenge_no_reduce(&c_e, &e, &sparse);
    round_mask(&y, &candidate->phase.mask);
    poly_add_no_reduce(&y.vec[0], &y.vec[0], &c);
    for (int i = 0; i < BIT_L; i++)
        poly_add_no_reduce(&y.vec[1 + i], &y.vec[1 + i], &c_s.vec[i]);
    for (int i = 0; i < BIT_K; i++)
        poly_add_no_reduce(&y.vec[1 + BIT_L + i], &y.vec[1 + BIT_L + i], &c_e.vec[i]);
    reject = bit_parabola_reject_response(&c, &c_s, &c_e,
                                         &candidate->phase.mask, candidate->seed,
                                         &candidate->nonce);
    if (reject < 0)
        goto cleanup;
    result = BIT_SIGN_PRECOMP_REJECT;
    if (reject || poly_reject_highbits_bimodal(&w1.vec[0], &candidate->w.vec[0], &sparse))
        goto cleanup;
    /* The Q13 mask is dead; reuse its storage for the public response and hint. */
    for (int i = 0; i < BIT_L + 1; i++)
        candidate->phase.accepted.response.vec[i] = y.vec[i];
    for (int i = 0; i < BIT_K; i++)
        candidate->phase.accepted.tail.vec[i] = y.vec[1 + BIT_L + i];
    polyveck_make_hint(&candidate->phase.accepted.hint, &w1, &candidate->w,
                       &candidate->phase.accepted.tail, &c, candidate->b);
    BIT_CT_HAETAE_PUBLIC(&candidate->phase.accepted.response, sizeof(candidate->phase.accepted.response));
    BIT_CT_HAETAE_PUBLIC(&candidate->phase.accepted.hint, sizeof(candidate->phase.accepted.hint));
    if (check_signature_bounds(&candidate->phase.accepted.response,
                               &candidate->phase.accepted.hint) ||
        pack_sig(sig, &candidate->phase.accepted.response,
                  &candidate->phase.accepted.hint, challenge) != 0)
        goto cleanup;
    *siglen = BIT_SIGNBYTES;
    result = 0;
cleanup:
    bit_secure_zero(key_tag, sizeof(key_tag));
    bit_secure_zero(tr, sizeof(tr));
    bit_secure_zero(challenge, sizeof(challenge));
    bit_secure_zero(hash_input, sizeof(hash_input));
    bit_secure_zero(&s, sizeof(s));
    bit_secure_zero(&e, sizeof(e));
    bit_secure_zero(&c_s, sizeof(c_s));
    bit_secure_zero(&c_e, sizeof(c_e));
    bit_secure_zero(&y, sizeof(y));
    bit_secure_zero(&w1, sizeof(w1));
    bit_secure_zero(&c, sizeof(c));
    bit_secure_zero(&sparse, sizeof(sparse));
    bit_sig_sign_precomp_clear(candidate);
    return result;
}
