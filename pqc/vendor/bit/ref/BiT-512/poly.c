/*
 * Copyright (c) 2026 Hang Zhang.
 * State Key Laboratory of Cyberspace Security Defense,
 * Institute of Information Engineering, CAS
 * School of Cyber Security, University of Chinese Academy of Sciences
 */
#include "../../common/ct_audit.h"
#include "poly.h"
#include "ntt.h"
#include "symmetric.h"
#include "endian.h"
#include <stddef.h>

#include "../../common/small_sample.h"

static void unpack_S1_4bit(int32_t *a, const uint8_t *buf)
{
    for (int i = 0; i < BIT_N / 2; i++) {
        uint8_t t = buf[i];
        a[2 * i + 0] = bit_small_sample(t & 0x0F);
        a[2 * i + 1] = bit_small_sample(t >> 4);
    }
}

inline void decompose_hint(int32_t *highbits, int32_t r)
{
    uint32_t val = reduce_barrett(r);
    uint32_t numerator = val + (BIT_GAMMA2 >> 1);
    int32_t hb =
        (int32_t)(((uint64_t)numerator * BIT_GAMMA2_BARRETT_MULT) >> BIT_GAMMA2_BARRETT_SHIFT);

    int32_t edgecase = (BIT_HINT_MODULUS - (hb + 1)) >> 31;
    hb -= BIT_HINT_MODULUS & edgecase;
    *highbits = (int32_t)hb;
}

uint32_t reduce_barrett(int64_t a)
{
    int64_t t;
    t = (a * BIT_BARRETT_MULT) >> BIT_BARRETT_SHIFT;
    a -= t * BIT_Q;
    /* Barrett estimate may be off by one; fold back into [0, q) */
    a += (a >> 63) & BIT_Q;
    a -= BIT_Q;
    a += (a >> 63) & BIT_Q;
    return (uint32_t)a;
}

int poly_sample_S1(poly *a, const uint8_t *seed, uint16_t *nonce)
{
    uint8_t buf[BIT_SAMPLE_S1_BUFLEN];

    if (bit_xof256_nonce(buf, sizeof(buf), seed, BIT_SEEDBYTES, *nonce) != 0) {
        bit_secure_zero(buf, sizeof(buf));
        return -1;
    }
    *nonce = (uint16_t)(*nonce + 1U);
    unpack_S1_4bit(a->coeffs, buf);
    bit_secure_zero(buf, sizeof(buf));
    return 0;
}

static inline void poly_to_ntt_impl(poly_ntt *result, const poly *a, poly *centered)
{
    for (int i = 0; i < BIT_N; i++) {
        result->coeffs[i] = (int32_t)reduce_barrett(a->coeffs[i]);
        if (centered != NULL)
            centered->coeffs[i] = reduce_to_signed(result->coeffs[i]);
    }
    ntt_forward(result->coeffs);
}

void poly_to_ntt(poly_ntt *result, const poly *a)
{
    poly_to_ntt_impl(result, a, NULL);
}

void poly_to_ntt_centered(poly_ntt *result, poly *a)
{
    poly_to_ntt_impl(result, a, a);
}

void poly_from_ntt(poly *result, const poly_ntt *a)
{
    poly_ntt tmp = *a;

    ntt_inverse(tmp.coeffs);
    for (int i = 0; i < BIT_N; i++) {
        result->coeffs[i] = reduce_to_signed((uint32_t)tmp.coeffs[i]);
    }
}

void poly_from_ntt_raw(poly *result, const poly_ntt *a)
{
    poly_ntt tmp = *a;

    ntt_inverse_raw(tmp.coeffs);
    for (int i = 0; i < BIT_N; i++) {
        result->coeffs[i] = reduce_to_signed((uint32_t)tmp.coeffs[i]);
    }
}

void poly_ntt_basemul_raw(poly_ntt *result, const poly_ntt *a, const poly_ntt *b)
{
    ntt_basemul_raw(result->coeffs, a->coeffs, b->coeffs);
}

void poly_ntt_basemul_acc_raw(poly_ntt *result, const poly_ntt *a, const poly_ntt *b)
{
    ntt_basemul_acc_raw(result->coeffs, a->coeffs, b->coeffs);
}

void poly_ntt_montgomery_lift(poly_ntt *result)
{
    ntt_montgomery_lift(result->coeffs);
}

void poly_ntt_zero(poly_ntt *result)
{
    for (int i = 0; i < BIT_N; i++) {
        result->coeffs[i] = 0;
    }
}

void poly_add(poly *result, const poly *a, const poly *b)
{
    for (int i = 0; i < BIT_N; i++) {
        result->coeffs[i] = reduce_signed_barrett((int64_t)a->coeffs[i] + b->coeffs[i]);
    }
}

void poly_add_no_reduce(poly *result, const poly *a, const poly *b)
{
    for (int i = 0; i < BIT_N; i++) {
        result->coeffs[i] = (int32_t)((int32_t)a->coeffs[i] + b->coeffs[i]);
    }
}

void poly_add_small(poly *result, const poly *a, const poly *small)
{
    for (int i = 0; i < BIT_N; i++) {
        int32_t val = (int32_t)a->coeffs[i] + small->coeffs[i];

        val += BIT_Q & ((val + BIT_Q_HALF) >> 31);
        val -= BIT_Q & ((BIT_Q_HALF - val) >> 31);
        result->coeffs[i] = (int32_t)val;
    }
}

void poly_highbits(poly *w1, const poly *w)
{
    for (int i = 0; i < BIT_N; i++) {
        decompose_hint(&w1->coeffs[i], w->coeffs[i]);
    }
}

void poly_canonicalize(poly *b)
{
    for (int i = 0; i < BIT_N; i++)
        b->coeffs[i] = reduce_to_unsigned(b->coeffs[i]);
}

void poly_pack_w1(unsigned char *r, const poly *a)
{
    uint64_t acc = 0;
    unsigned int acc_bits = 0;
    size_t out = 0;

    for (int i = 0; i < BIT_N; i++) {
        acc |= (uint64_t)(uint32_t)a->coeffs[i] << acc_bits;
        acc_bits += BIT_W1_BITS;
        while (acc_bits >= 8) {
            r[out++] = (uint8_t)acc;
            acc >>= 8;
            acc_bits -= 8;
        }
    }
    if (acc_bits != 0)
        r[out] = (uint8_t)acc;
}

int poly_challenge(poly *c, const unsigned char seed[BIT_CHALLENGEBYTES])
{
    unsigned int i, b, pos;
    uint8_t buf[BIT_XOF256_RATE];
    uint8_t sign_bits[(BIT_TAU + 7) / 8];
    bit_xof256_ctx ctx;

    bit_xof256_ctx_init(&ctx, seed, BIT_CHALLENGEBYTES);
    if (bit_xof256_ctx_squeezeblocks(&ctx, buf, 1) != 0) {
        bit_xof256_ctx_zeroize(&ctx);
        bit_secure_zero(buf, sizeof(buf));
        return -1;
    }
    for (size_t j = 0; j < sizeof(sign_bits); j++)
        sign_bits[j] = buf[j];
    BIT_CT_HAETAE_PUBLIC(sign_bits, sizeof sign_bits);
    pos = (unsigned int)sizeof(sign_bits);

    for (i = 0; i < BIT_N; ++i) {
        c->coeffs[i] = 0;
    }

    for (i = BIT_N - BIT_TAU; i < BIT_N; ++i) {
        do {
            if (pos + 2 > BIT_XOF256_RATE) {
                if (bit_xof256_ctx_squeezeblocks(&ctx, buf, 1) != 0) {
                    bit_xof256_ctx_zeroize(&ctx);
                    bit_secure_zero(buf, sizeof(buf));
                    return -1;
                }
                pos = 0;
            }
            b = load16_le(buf + pos) & (BIT_N - 1U);
            BIT_CT_HAETAE_PUBLIC(&b, sizeof b);
            pos += 2;
        } while (b > i);

        c->coeffs[i] = c->coeffs[b];
        {
            unsigned int t = i - (BIT_N - BIT_TAU);
            c->coeffs[b] = 1 - 2 * ((sign_bits[t >> 3] >> (t & 7)) & 1U);
        }
    }
    bit_xof256_ctx_zeroize(&ctx);
    return 0;
}

void poly_challenge_to_sparse(sparse_challenge *s, const poly *c)
{
    int ctr = 0;

    s->bflip = 0;

    for (int i = 0; i < BIT_N; i++) {
        if (c->coeffs[i] != 0) {
            s->pos[ctr] = (uint16_t)i;
            s->sign[ctr] = (int8_t)c->coeffs[i];
            ctr++;
            if (ctr == BIT_TAU) {
                break;
            }
        }
    }
}

void poly_cneg(poly *a, uint8_t b)
{
    const int32_t mask = -(int32_t)b;

    for (int i = 0; i < BIT_N; i++) {
        a->coeffs[i] = (int32_t)(((int32_t)a->coeffs[i] ^ mask) - mask);
    }
}

void poly_mul_challenge_no_reduce(poly *result, const poly *a, const sparse_challenge *c)
{
    int32_t acc[BIT_N];
    const int32_t mask = (int32_t)(-(int32_t)c->bflip);

    for (int i = 0; i < BIT_N; i++) {
        acc[i] = 0;
    }

    for (int t = 0; t < BIT_TAU; t++) {
        int i = c->pos[t];
        if (c->sign[t] > 0) {
            for (int j = 0; j < BIT_N - i; j++)
                acc[i + j] += a->coeffs[j];
            for (int j = BIT_N - i; j < BIT_N; j++)
                acc[i + j - BIT_N] -= a->coeffs[j];
        } else {
            for (int j = 0; j < BIT_N - i; j++)
                acc[i + j] -= a->coeffs[j];
            for (int j = BIT_N - i; j < BIT_N; j++)
                acc[i + j - BIT_N] += a->coeffs[j];
        }
    }

    for (int i = 0; i < BIT_N; i++) {
        result->coeffs[i] = (int32_t)((acc[i] ^ mask) - mask);
    }
}

int poly_reject_highbits_bimodal(const poly *w1, const poly *w0, const sparse_challenge *c)
{
    uint32_t reject_flag = 0;
    const int32_t signed_one = 1 - 2 * (int32_t)c->bflip;

    for (int t = 0; t < BIT_TAU; t++) {
        int i = c->pos[t];
        int32_t hb;
        int32_t w_prime_val = (int32_t)w0->coeffs[i] + (int32_t)c->sign[t] * signed_one;

        decompose_hint(&hb, w_prime_val);
        reject_flag |= (uint32_t)((uint32_t)w1->coeffs[i] ^ (uint32_t)hb);
    }

    return (reject_flag != 0) ? 1 : 0;
}
