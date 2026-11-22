/*
 * Copyright (c) 2026 Hang Zhang.
 * State Key Laboratory of Cyberspace Security Defense,
 * Institute of Information Engineering, CAS
 * School of Cyber Security, University of Chinese Academy of Sciences
 */
#include "packing.h"
#include "../../common/packing_checks.h"
#include "polyvec.h"
#include "endian.h"
#include <stdint.h>
#include <string.h>

static uint32_t load32_le_local(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32_le_local(unsigned char *p, uint32_t x)
{
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

#include "../../common/packing_public.h"

/* Offset encoding for the first response block. */
static void pack_poly_z0(unsigned char *r, const poly *a)
{
    uint64_t acc = 0;
    int acc_bits = 0;
    size_t wi = 0;

    for (int i = 0; i < BIT_N; i++) {
        uint32_t code = (uint32_t)(BIT_GAMMA1 - a->coeffs[i]);
        acc |= (uint64_t)code << acc_bits;
        acc_bits += BIT_Z0_BITS;
        while (acc_bits >= 8) {
            r[wi++] = (uint8_t)acc;
            acc >>= 8;
            acc_bits -= 8;
        }
    }
    if (acc_bits)
        r[wi++] = (uint8_t)acc;
}

static void unpack_poly_z0(poly *r, const unsigned char *a)
{
    uint64_t acc = 0;
    int acc_bits = 0;
    size_t ri = 0;
    const uint32_t mask = (1U << BIT_Z0_BITS) - 1U;

    for (int i = 0; i < BIT_N; i++) {
        while (acc_bits < BIT_Z0_BITS) {
            acc |= (uint64_t)a[ri++] << acc_bits;
            acc_bits += 8;
        }
        uint32_t code = (uint32_t)acc & mask;
        acc >>= BIT_Z0_BITS;
        acc_bits -= BIT_Z0_BITS;
        r->coeffs[i] = BIT_GAMMA1 - (int32_t)code;
    }
}

void pack_pk(unsigned char *pk, const unsigned char *seed_A, const polyveck *public_vector)
{
    memcpy(pk, seed_A, BIT_SEEDBYTES);
    pk += BIT_SEEDBYTES;
    for (int i = 0; i < BIT_K; i++) {
        pack_poly_public(pk + i * BIT_POLY_PUBLIC_BYTES, &public_vector->vec[i]);
    }
}

void pack_sk(unsigned char *sk, const unsigned char *seed_A, const polyveck *public_vector,
             const unsigned char *secret_seed, const unsigned char *tr, const polyvecl *s_0,
             const polyveck *e)
{
    memcpy(sk, seed_A, BIT_SEEDBYTES);
    sk += BIT_SEEDBYTES;
    for (int i = 0; i < BIT_K; i++) {
        pack_poly_public(sk + i * BIT_POLY_PUBLIC_BYTES, &public_vector->vec[i]);
    }
    sk += BIT_POLYVECK_PUBLIC_BYTES;
    memcpy(sk, secret_seed, BIT_SEEDBYTES);
    sk += BIT_SEEDBYTES;
    memcpy(sk, tr, BIT_TRBYTES);
    sk += BIT_TRBYTES;
    for (int i = 0; i < BIT_L; ++i) {
        const int32_t *coeffs = s_0->vec[i].coeffs;
        for (int j = 0; j < BIT_N; j += 4) {
            *sk++ = (unsigned char)((coeffs[j] & 0x03) | ((coeffs[j + 1] & 0x03) << 2) |
                                    ((coeffs[j + 2] & 0x03) << 4) | ((coeffs[j + 3] & 0x03) << 6));
        }
    }

    for (int i = 0; i < BIT_K; i++) {
        const int32_t *coeffs = e->vec[i].coeffs;
        for (int j = 0; j < BIT_N; j += 4) {
            *sk++ = (unsigned char)((coeffs[j] & 0x03) | ((coeffs[j + 1] & 0x03) << 2) |
                                    ((coeffs[j + 2] & 0x03) << 4) | ((coeffs[j + 3] & 0x03) << 6));
        }
    }
}

int unpack_sk(unsigned char *seed_A, polyveck *public_vector, unsigned char *secret_seed,
              unsigned char *tr, polyvecl *s_0, polyveck *e, const unsigned char *sk)
{
    const size_t small_offset = 2 * BIT_SEEDBYTES + BIT_POLYVECK_PUBLIC_BYTES + BIT_TRBYTES;
    if (small2_encoding_invalid(sk + small_offset))
        return -1;

    memcpy(seed_A, sk, BIT_SEEDBYTES);
    sk += BIT_SEEDBYTES;
    for (int i = 0; i < BIT_K; i++) {
        if (unpack_poly_public(&public_vector->vec[i], sk + i * BIT_POLY_PUBLIC_BYTES) != 0)
            return -1;
    }
    sk += BIT_POLYVECK_PUBLIC_BYTES;
    memcpy(secret_seed, sk, BIT_SEEDBYTES);
    sk += BIT_SEEDBYTES;
    memcpy(tr, sk, BIT_TRBYTES);
    sk += BIT_TRBYTES;

    for (int i = 0; i < BIT_L; ++i) {
        int32_t *coeffs = s_0->vec[i].coeffs;
        for (int j = 0; j < BIT_N; j += 4) {
            uint8_t byte = *sk++;
            coeffs[j] = (int32_t)((uint32_t)(byte & 0x03) << 30) >> 30;
            coeffs[j + 1] = (int32_t)((uint32_t)((byte >> 2) & 0x03) << 30) >> 30;
            coeffs[j + 2] = (int32_t)((uint32_t)((byte >> 4) & 0x03) << 30) >> 30;
            coeffs[j + 3] = (int32_t)((uint32_t)((byte >> 6) & 0x03) << 30) >> 30;
        }
    }

    for (int i = 0; i < BIT_K; i++) {
        int32_t *coeffs = e->vec[i].coeffs;
        for (int j = 0; j < BIT_N; j += 4) {
            uint8_t byte = *sk++;
            coeffs[j] = (int32_t)((uint32_t)(byte & 0x03) << 30) >> 30;
            coeffs[j + 1] = (int32_t)((uint32_t)((byte >> 2) & 0x03) << 30) >> 30;
            coeffs[j + 2] = (int32_t)((uint32_t)((byte >> 4) & 0x03) << 30) >> 30;
            coeffs[j + 3] = (int32_t)((uint32_t)((byte >> 6) & 0x03) << 30) >> 30;
        }
    }

    return 0;
}

int unpack_pk(unsigned char *seed_A, polyveck *public_vector, const unsigned char *pk)
{
    memcpy(seed_A, pk, BIT_SEEDBYTES);
    pk += BIT_SEEDBYTES;

    for (int i = 0; i < BIT_K; i++) {
        if (unpack_poly_public(&public_vector->vec[i], pk + i * BIT_POLY_PUBLIC_BYTES) != 0)
            return -1;
    }
    return 0;
}

/* Byte-aligned rANS with a full-support Q16 model.
 * Response coefficients have eleven centered low bits. */
#include "../../common/rans_decode.h"

#define RANS_SCALE_BITS 16
#define RANS_SCALE (1U << RANS_SCALE_BITS)
#define RANS_BYTE_L (1U << 23)
#define RANS_TMP_BYTES (2 * BIT_K * BIT_N + 256)
#define Z_HIGH_MAX ((BIT_RESPONSE_COEFF_BOUND + (1 << (BIT_Z1_LOW_BITS - 1))) >> BIT_Z1_LOW_BITS)
#define Z_HIGH_MIN (-Z_HIGH_MAX)
#define Z_HIGH_SYMBOLS (Z_HIGH_MAX - Z_HIGH_MIN + 1)

#if BIT_L != BIT_K
#error "The paired rANS decoder requires BIT_L == BIT_K"
#endif


/* Precomputed reciprocal form for byte-aligned rANS encoding. */
#include "rans_model.h"

static int rans_encode(unsigned char *out, size_t *out_len, const uint8_t *symbols, size_t count,
                       const rans_enc_symbol *model, unsigned int nsymbols)
{
    unsigned char tmp[RANS_TMP_BYTES];
    unsigned char *ptr = tmp + sizeof(tmp);
    uint32_t state = RANS_BYTE_L;

    for (size_t i = count; i > 0; i--) {
        unsigned int symbol = symbols[i - 1];
        const rans_enc_symbol *sym;
        uint32_t x, q;

        if (symbol >= nsymbols)
            return -1;
        sym = &model[symbol];
        x = state;
        while (x >= sym->x_max) {
            if (ptr == tmp)
                return -1;
            *--ptr = (uint8_t)x;
            x >>= 8;
        }
        q = (uint32_t)(((uint64_t)x * sym->rcp_freq) >> 32) >> sym->rcp_shift;
        state = x + sym->bias + q * sym->cmpl_freq;
    }
    if ((size_t)(ptr - tmp) < 4)
        return -1;
    ptr -= 4;
    store32_le_local(ptr, state);
    *out_len = (size_t)(tmp + sizeof(tmp) - ptr);
    memcpy(out, ptr, *out_len);
    return 0;
}

static int rans_decode_pair(uint8_t *z_symbols, uint8_t *h_symbols, size_t count,
                            const unsigned char *z_in, size_t z_len, const unsigned char *h_in,
                            size_t h_len)
{
    const unsigned char *z_ptr = z_in;
    const unsigned char *h_ptr = h_in;
    const unsigned char *z_end = z_in + z_len;
    const unsigned char *h_end = h_in + h_len;
    uint32_t z_state, h_state;

    if (z_len < 4 || h_len < 4)
        return -1;
    z_state = load32_le_local(z_ptr);
    h_state = load32_le_local(h_ptr);
    z_ptr += 4;
    h_ptr += 4;
    if (z_state < RANS_BYTE_L || z_state >= (RANS_BYTE_L << 8) || h_state < RANS_BYTE_L ||
        h_state >= (RANS_BYTE_L << 8))
        return -1;

    for (size_t i = 0; i < count; i++) {
        uint32_t z_slot = z_state & (RANS_SCALE - 1);
        uint32_t h_slot = h_state & (RANS_SCALE - 1);
        uint32_t z_base = 0, h_base = 0;
        unsigned int z_symbol, h_symbol;

        z_symbol = rans_find_symbol(z_slot, z_high_freq, z_high_start, z_high_lookup, &z_base);
        h_symbol = rans_find_symbol(h_slot, h_freq, h_start, h_lookup, &h_base);

        z_symbols[i] = (uint8_t)z_symbol;
        h_symbols[i] = (uint8_t)h_symbol;
        z_state = z_high_freq[z_symbol] * (z_state >> RANS_SCALE_BITS) + z_slot - z_base;
        h_state = h_freq[h_symbol] * (h_state >> RANS_SCALE_BITS) + h_slot - h_base;
        while (z_state < RANS_BYTE_L && z_ptr < z_end)
            z_state = (z_state << 8) | *z_ptr++;
        while (h_state < RANS_BYTE_L && h_ptr < h_end)
            h_state = (h_state << 8) | *h_ptr++;
    }
    return z_state == RANS_BYTE_L && h_state == RANS_BYTE_L && z_ptr == z_end && h_ptr == h_end
               ? 0
               : -1;
}

int pack_sig(unsigned char *sig, const polyvecm1 *z1, const polyveck *h,
             const unsigned char *challenge)
{
    uint8_t z_high[BIT_L * BIT_N];
    uint8_t h_symbols[BIT_K * BIT_N];
    unsigned char enc_z[RANS_TMP_BYTES], enc_h[RANS_TMP_BYTES];
    size_t z_len, h_len;
    unsigned char *p = sig;

    for (int i = 0; i < BIT_L + 1; i++)
        for (int j = 0; j < BIT_N; j++)
            if (z1->vec[i].coeffs[j] < -BIT_RESPONSE_COEFF_BOUND ||
                z1->vec[i].coeffs[j] > BIT_RESPONSE_COEFF_BOUND)
                return -1;

    memset(sig, 0, BIT_SIGNBYTES);
    memcpy(p, challenge, BIT_CHALLENGEBYTES);
    p += BIT_CHALLENGEBYTES;
    pack_poly_z0(p, &z1->vec[0]);
    p += BIT_POLY_Z0_BYTES;

    {
        uint64_t low_acc = 0;
        unsigned int low_bits = 0;

        for (int i = 0; i < BIT_L; i++) {
            for (int j = 0; j < BIT_N; j++) {
                int32_t z = z1->vec[i + 1].coeffs[j];
                uint32_t code = (uint32_t)z & ((1U << BIT_Z1_LOW_BITS) - 1U);
                int32_t low = (int32_t)(code << (32 - BIT_Z1_LOW_BITS)) >> (32 - BIT_Z1_LOW_BITS);
                int32_t high = (z - low) >> BIT_Z1_LOW_BITS;

                if (high < Z_HIGH_MIN || high > Z_HIGH_MAX)
                    return -1;
                low_acc |= (uint64_t)code << low_bits;
                low_bits += BIT_Z1_LOW_BITS;
                while (low_bits >= 8) {
                    *p++ = (uint8_t)low_acc;
                    low_acc >>= 8;
                    low_bits -= 8;
                }
                z_high[i * BIT_N + j] = (uint8_t)(high - Z_HIGH_MIN);
            }
        }
        if (low_bits != 0)
            *p++ = (uint8_t)low_acc;
    }
    for (int i = 0; i < BIT_K; i++) {
        for (int j = 0; j < BIT_N; j++) {
            int32_t v = h->vec[i].coeffs[j];
            if (v < -BIT_H_INF || v > BIT_H_INF)
                return -1;
            h_symbols[i * BIT_N + j] = (uint8_t)(v + BIT_H_INF);
        }
    }
    if (rans_encode(enc_z, &z_len, z_high, sizeof(z_high), z_high_enc, Z_HIGH_SYMBOLS) != 0 ||
        rans_encode(enc_h, &h_len, h_symbols, sizeof(h_symbols), h_enc, 2 * BIT_H_INF + 1) != 0)
        return -1;
    if (z_len > UINT16_MAX || h_len > UINT16_MAX || z_len + h_len > BIT_SIG_RANS_PAYLOAD_BYTES)
        return -1;

    store16_le(p, (uint16_t)z_len);
    store16_le(p + 2, (uint16_t)h_len);
    p += BIT_SIG_RANS_LENGTH_BYTES;
    memcpy(p, enc_z, z_len);
    p += z_len;
    memcpy(p, enc_h, h_len);
    return 0;
}

int unpack_sig(polyvecm1 *z1, polyveck *h, unsigned char *challenge, const unsigned char *sig)
{
    uint8_t z_high[BIT_L * BIT_N];
    uint8_t h_symbols[BIT_K * BIT_N];
    const unsigned char *p = sig;
    size_t z_len, h_len, used;

    memcpy(challenge, p, BIT_CHALLENGEBYTES);
    p += BIT_CHALLENGEBYTES;
    unpack_poly_z0(&z1->vec[0], p);
    p += BIT_POLY_Z0_BYTES;

    const unsigned char *low = p;
    p += BIT_Z1_LOW_BYTES;
    z_len = load16_le(p);
    h_len = load16_le(p + 2);
    p += BIT_SIG_RANS_LENGTH_BYTES;
    if (z_len < 4 || h_len < 4 || z_len + h_len > BIT_SIG_RANS_PAYLOAD_BYTES)
        return -1;
    if (rans_decode_pair(z_high, h_symbols, sizeof(z_high), p, z_len, p + z_len, h_len) != 0)
        return -1;
    p += z_len + h_len;

    {
        uint64_t low_acc = 0;
        unsigned int low_bits = 0;
        size_t low_pos = 0;

        for (int i = 0; i < BIT_L; i++) {
            for (int j = 0; j < BIT_N; j++) {
                uint32_t code;
                int32_t low_value;
                int32_t high = (int32_t)z_high[i * BIT_N + j] + Z_HIGH_MIN;

                while (low_bits < BIT_Z1_LOW_BITS) {
                    low_acc |= (uint64_t)low[low_pos++] << low_bits;
                    low_bits += 8;
                }
                code = (uint32_t)low_acc & ((1U << BIT_Z1_LOW_BITS) - 1U);
                low_acc >>= BIT_Z1_LOW_BITS;
                low_bits -= BIT_Z1_LOW_BITS;
                low_value = (int32_t)(code << (32 - BIT_Z1_LOW_BITS)) >> (32 - BIT_Z1_LOW_BITS);
                z1->vec[i + 1].coeffs[j] = high * (1 << BIT_Z1_LOW_BITS) + low_value;
            }
        }
    }
    for (int i = 0; i < BIT_K; i++)
        for (int j = 0; j < BIT_N; j++)
            h->vec[i].coeffs[j] = (int32_t)h_symbols[i * BIT_N + j] - BIT_H_INF;

    for (int i = 0; i < BIT_L + 1; i++)
        for (int j = 0; j < BIT_N; j++)
            if (z1->vec[i].coeffs[j] < -BIT_RESPONSE_COEFF_BOUND ||
                z1->vec[i].coeffs[j] > BIT_RESPONSE_COEFF_BOUND)
                return -1;

    used = (size_t)(p - sig);
    for (size_t i = used; i < BIT_SIGNBYTES; i++)
        if (sig[i] != 0)
            return -1;
    return 0;
}
