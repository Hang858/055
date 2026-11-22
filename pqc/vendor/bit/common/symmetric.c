/*
 * Copyright (c) 2026 Hang Zhang.
 * State Key Laboratory of Cyberspace Security Defense,
 * Institute of Information Engineering, CAS
 * School of Cyber Security, University of Chinese Academy of Sciences
 */
/* SHA3 hashes and SHAKE streams. */
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "symmetric.h"
#include "fips202.h"
#include "params.h"
#include "endian.h"

void bit_secure_zero(void *ptr, size_t len)
{
#if defined(__GNUC__) || defined(__clang__)
    memset(ptr, 0, len);
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--)
        *p++ = 0;
#endif
}


int bit_hash(uint8_t out[BIT_TRBYTES], const uint8_t *in, size_t inlen)
{
#if BIT_TRBYTES == 32
    sha3_256(out, in, inlen);
#else
    sha3_512(out, in, inlen);
#endif
    return 0;
}

int bit_hash_message(uint8_t out[BIT_MESSAGEBYTES], const uint8_t *in0, size_t inlen0,
                     const uint8_t *in1, size_t inlen1)
{
#if BIT_MESSAGEBYTES == 32
    sha3_256incctx state;
    sha3_256_inc_init(&state);
    sha3_256_inc_absorb(&state, in0, inlen0);
    sha3_256_inc_absorb(&state, in1, inlen1);
    sha3_256_inc_finalize(out, &state);
#else
    sha3_512incctx state;
    sha3_512_inc_init(&state);
    sha3_512_inc_absorb(&state, in0, inlen0);
    sha3_512_inc_absorb(&state, in1, inlen1);
    sha3_512_inc_finalize(out, &state);
#endif
    return 0;
}

#if BIT_SECURITY_BITS == 512
int bit_challenge_init(bit_challenge_ctx *ctx, const uint8_t tr[BIT_TRBYTES],
                       const uint8_t *message, size_t message_len)
{
    uint8_t length[8];
    if (ctx == NULL)
        return -1;
    memset(ctx, 0, sizeof(*ctx));
    if (tr == NULL || (message == NULL && message_len != 0))
        return -1;
    store64_le(length, (uint64_t)message_len);
    sha3_512_inc_init(&ctx->prefix);
    sha3_512_inc_absorb(&ctx->prefix, tr, BIT_TRBYTES);
    sha3_512_inc_absorb(&ctx->prefix, length, sizeof(length));
    if (message_len != 0)
        sha3_512_inc_absorb(&ctx->prefix, message, message_len);
    return 0;
}

int bit_challenge_hash(uint8_t out[BIT_CHALLENGEBYTES], const bit_challenge_ctx *ctx,
                       const uint8_t commitment[BIT_POLYVECK_W1_BYTES])
{
    sha3_512incctx state;
    sha3_512_inc_ctx_clone(&state, &ctx->prefix);
    sha3_512_inc_absorb(&state, commitment, BIT_POLYVECK_W1_BYTES);
    sha3_512_inc_finalize(out, &state);
    bit_secure_zero(&state, sizeof(state));
    return 0;
}

void bit_challenge_release(bit_challenge_ctx *ctx)
{
    bit_secure_zero(ctx, sizeof(*ctx));
}
#endif

int bit_xof256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    shake256(out, outlen, in, inlen);
    return 0;
}

/* One-shot XOF over seed || nonce (16-bit little-endian nonce). */
int bit_xof256_nonce(uint8_t *out, size_t outlen, const uint8_t *seed, size_t seedlen,
                     uint16_t nonce)
{
    if (seedlen != BIT_SEEDBYTES)
        return -1;
    uint8_t extseed[BIT_SEEDBYTES + sizeof(uint16_t)];

    memcpy(extseed, seed, seedlen);
    store16_le(extseed + seedlen, nonce);
    shake256(out, outlen, extseed, seedlen + sizeof(uint16_t));
    bit_secure_zero(extseed, sizeof(extseed));
    return 0;
}

/* One-shot XOF absorbing three inputs in sequence (in0 || in1 || in2). */
int bit_xof256_3(uint8_t *out, size_t outlen, const uint8_t *in0, size_t inlen0, const uint8_t *in1,
                 size_t inlen1, const uint8_t *in2, size_t inlen2)
{
    if (inlen0 != BIT_SEEDBYTES || inlen1 != BIT_SEEDBYTES || inlen2 != BIT_MESSAGEBYTES)
        return -1;
    shake256incctx state;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, in0, inlen0);
    shake256_inc_absorb(&state, in1, inlen1);
    shake256_inc_absorb(&state, in2, inlen2);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(out, outlen, &state);
    bit_secure_zero(state.ctx, PQC_SHAKEINCCTX_BYTES);
    shake256_inc_ctx_release(&state);
    return 0;
}

/* Initialize a block stream keyed by seed || nonce. */

void bit_xof256_init(bit_xof256_state *st, const uint8_t *seed, size_t seedlen, uint16_t nonce)
{
    uint8_t extseed[seedlen + sizeof(uint16_t)];

    memcpy(extseed, seed, seedlen);
    store16_le(extseed + seedlen, nonce);
    shake256_absorb(&st->state, extseed, sizeof(extseed));
    bit_secure_zero(extseed, sizeof(extseed));
    st->leftover_len = 0;
    st->leftover_pos = 0;
    st->nonce = nonce;
}

/* Produce complete backend blocks for the generic XOF256 stream. */
static int bit_xof256_stream_blocks(bit_xof256_state *st, uint8_t *out, size_t nblocks)
{
    shake256_squeezeblocks(out, nblocks, &st->state);
    return 0;
}

int bit_xof256_squeeze(bit_xof256_state *st, uint8_t *out, size_t outlen)
{
    if (st->leftover_pos < st->leftover_len) {
        size_t available = st->leftover_len - st->leftover_pos;
        size_t take = outlen < available ? outlen : available;
        memcpy(out, st->leftover + st->leftover_pos, take);
        st->leftover_pos += take;
        out += take;
        outlen -= take;
    }

    if (outlen >= BIT_XOF256_STREAM_BLOCKBYTES) {
        size_t nblocks = outlen / BIT_XOF256_STREAM_BLOCKBYTES;
        size_t nbytes = nblocks * BIT_XOF256_STREAM_BLOCKBYTES;
        if (bit_xof256_stream_blocks(st, out, nblocks) != 0) {
            return -1;
        }
        out += nbytes;
        outlen -= nbytes;
    }

    if (outlen != 0) {
        if (bit_xof256_stream_blocks(st, st->leftover, 1) != 0) {
            return -1;
        }
        memcpy(out, st->leftover, outlen);
        st->leftover_pos = outlen;
        st->leftover_len = BIT_XOF256_STREAM_BLOCKBYTES;
    } else if (st->leftover_pos == st->leftover_len) {
        st->leftover_pos = 0;
        st->leftover_len = 0;
    }
    return 0;
}

void bit_xof256_zeroize(bit_xof256_state *st)
{
    bit_secure_zero(st->state.ctx, PQC_SHAKECTX_BYTES);
    shake256_ctx_release(&st->state);
    bit_secure_zero(st->leftover, sizeof(st->leftover));
    st->leftover_len = 0;
    st->leftover_pos = 0;
    st->nonce = 0;
}

void bit_xof256_ctx_init(bit_xof256_ctx *ctx, const uint8_t *seed, size_t seedlen)
{
    shake256_absorb(&ctx->state, seed, seedlen);
}

int bit_xof256_ctx_squeezeblocks(bit_xof256_ctx *ctx, uint8_t *out, size_t nblocks)
{
    shake256_squeezeblocks(out, nblocks, &ctx->state);
    return 0;
}

void bit_xof256_ctx_zeroize(bit_xof256_ctx *ctx)
{
    bit_secure_zero(ctx->state.ctx, PQC_SHAKECTX_BYTES);
    shake256_ctx_release(&ctx->state);
}

void bit_xof128_init(bit_xof128_state *st, const uint8_t *in, size_t inlen)
{
    shake128_absorb(&st->state, in, inlen);
    st->leftover_len = 0;
    st->leftover_pos = 0;
}

int bit_xof128_squeeze(bit_xof128_state *st, uint8_t *out, size_t outlen)
{
    if (st->leftover_pos < st->leftover_len) {
        size_t left = st->leftover_len - st->leftover_pos;
        size_t take = outlen < left ? outlen : left;
        memcpy(out, st->leftover + st->leftover_pos, take);
        st->leftover_pos += take;
        out += take;
        outlen -= take;
    }

    size_t nblocks = outlen / SHAKE128_RATE;
    if (nblocks != 0) {
        shake128_squeezeblocks(out, nblocks, &st->state);
        out += nblocks * SHAKE128_RATE;
        outlen -= nblocks * SHAKE128_RATE;
    }

    if (outlen != 0) {
        shake128_squeezeblocks(st->leftover, 1, &st->state);
        memcpy(out, st->leftover, outlen);
        st->leftover_pos = outlen;
        st->leftover_len = SHAKE128_RATE;
    } else if (st->leftover_pos == st->leftover_len) {
        st->leftover_pos = 0;
        st->leftover_len = 0;
    }
    return 0;
}

void bit_xof128_zeroize(bit_xof128_state *st)
{
    bit_secure_zero(st->state.ctx, PQC_SHAKECTX_BYTES);
    bit_secure_zero(st->leftover, sizeof(st->leftover));
    st->leftover_len = 0;
    st->leftover_pos = 0;
    shake128_ctx_release(&st->state);
}
