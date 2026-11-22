/*
 * Copyright (c) 2026 Hang Zhang.
 * State Key Laboratory of Cyberspace Security Defense,
 * Institute of Information Engineering, CAS
 * School of Cyber Security, University of Chinese Academy of Sciences
 */

#include <stdint.h>

#include "ntt.h"
#include "ntt_tables.h"

#if BIT_Q != 25601 || BIT_N != 1024
#error "ntt.c constants are generated for BIT_Q=25601 and BIT_N=1024"
#endif

/* R=2^32.  q^{-1} is used by the subtractive Montgomery reduction. */
#define MONT_QINV 3876559873U
#define INVERSE_COMPONENTS_MONT 17081
#define INVERSE_COMPONENTS_RAW 7449
#define MONT_R2 24940
#define NTT_COMPONENTS (BIT_N / 2)

static inline int32_t montgomery_reduce(int64_t a)
{
    uint32_t m = (uint32_t)a * MONT_QINV;
    int64_t r = (a - (int64_t)m * BIT_Q) >> 32;

    /* The documented NTT bounds put r in (-2q,2q). */
    r += (r >> 63) & BIT_Q;
    r += (r >> 63) & BIT_Q;
    r -= BIT_Q;
    r += (r >> 63) & BIT_Q;
    return (int32_t)r;
}

static inline int32_t mul_mod(int32_t a, int32_t b)
{
    return montgomery_reduce((int64_t)a * b);
}

/* The root multiplication canonicalizes one butterfly input.  Starting from
 * [0,q), each of the nine layers adds at most one q to the other path, so the
 * incomplete forward transform remains below 10q. */
static void ntt_forward_lazy(int32_t a[BIT_N])
{
    int t = BIT_N;

    for (int m = 1; m < NTT_COMPONENTS; m <<= 1) {
        t >>= 1;
        for (int i = 0; i < m; i++) {
            int s = (i * t) << 1;
            int e = s + t;
            int32_t root = ntt_roots[m + i];

            for (int j = s; j < e; j++) {
                int32_t u = a[j];
                int32_t v = mul_mod(a[j + t], root);

                a[j] = u + v;
                a[j + t] = u - v + BIT_Q;
            }
        }
    }
}

static inline int32_t canonicalize_forward(int32_t a)
{
    /* Forward outputs are in [0,10q).  Fixed-count subtraction avoids a
     * division and is used only by the ordinary round-trip inverse. */
    for (unsigned int i = 0; i < 9; i++) {
        a -= BIT_Q;
        a += (a >> 31) & BIT_Q;
    }
    return a;
}

static void ntt_inverse_lazy(int32_t a[BIT_N], int raw_domain)
{
    int t = BIT_N / NTT_COMPONENTS;

    if (!raw_domain) {
        for (int i = 0; i < BIT_N; i++)
            a[i] = canonicalize_forward(a[i]);
    }

    for (int m = NTT_COMPONENTS; m > 1; m >>= 1) {
        int s = 0;
        int h = m >> 1;

        for (int i = 0; i < h; i++) {
            int e = s + t;
            int32_t root = ntt_roots[m - 1 - i];
            root = root == 0 ? 0 : BIT_Q - root;

            for (int j = s; j < e; j++) {
                int32_t u = a[j];
                int32_t v = a[j + t];

                a[j] = u + v;
                a[j + t] = mul_mod(u - v, root);
            }
            s += 2 * t;
        }
        t <<= 1;
    }

    {
        int32_t scale = raw_domain ? INVERSE_COMPONENTS_RAW : INVERSE_COMPONENTS_MONT;
        for (int i = 0; i < BIT_N; i++)
            a[i] = mul_mod(a[i], scale);
    }
}

void ntt_forward(int32_t a[BIT_N])
{
    ntt_forward_lazy(a);
}

void ntt_inverse(int32_t a[BIT_N])
{
    ntt_inverse_lazy(a, 0);
}

void ntt_inverse_raw(int32_t a[BIT_N])
{
    ntt_inverse_lazy(a, 1);
}

static inline int32_t add_mod(int32_t a, int32_t b)
{
    int32_t r = a + b - BIT_Q;

    return r + ((r >> 31) & BIT_Q);
}

static inline void basemul_quadratic(int32_t r[2], const int32_t a[2], const int32_t b[2],
                                     int32_t zeta)
{
    int32_t a0b0 = mul_mod(a[0], b[0]);
    int32_t a1b1 = mul_mod(mul_mod(a[1], b[1]), zeta);
    int32_t a0b1 = mul_mod(a[0], b[1]);
    int32_t a1b0 = mul_mod(a[1], b[0]);

    r[0] = add_mod(a0b0, a1b1);
    r[1] = add_mod(a0b1, a1b0);
}

void ntt_basemul_raw(int32_t r[BIT_N], const int32_t a[BIT_N], const int32_t b[BIT_N])
{
    for (int i = 0; i < BIT_N; i += 4) {
        int32_t zeta = ntt_roots[BIT_N / 4 + i / 4];

        basemul_quadratic(r + i, a + i, b + i, zeta);
        basemul_quadratic(r + i + 2, a + i + 2, b + i + 2, BIT_Q - zeta);
    }
}

void ntt_basemul_acc_raw(int32_t r[BIT_N], const int32_t a[BIT_N], const int32_t b[BIT_N])
{
    int32_t product[4];

    for (int i = 0; i < BIT_N; i += 4) {
        int32_t zeta = ntt_roots[BIT_N / 4 + i / 4];

        basemul_quadratic(product, a + i, b + i, zeta);
        basemul_quadratic(product + 2, a + i + 2, b + i + 2, BIT_Q - zeta);
        for (int j = 0; j < 4; j++) {
            r[i + j] = add_mod(r[i + j], product[j]);
        }
    }
}

void ntt_montgomery_lift(int32_t r[BIT_N])
{
    for (int i = 0; i < BIT_N; i++)
        r[i] = mul_mod(r[i], MONT_R2);
}
