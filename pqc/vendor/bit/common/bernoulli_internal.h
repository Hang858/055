/* Copyright (c) 2026 Hang Zhang. */
#ifndef BIT_BERNOULLI_INTERNAL_H
#define BIT_BERNOULLI_INTERNAL_H

#include <stdint.h>
#include "params.h"
#include "endian.h"
#include "symmetric.h"

/* Return the next base-2^32 digit of rem/den and update the remainder. */
static uint32_t ratio_digit32(uint64_t *rem, uint64_t den)
{
    uint32_t digit = 0;
    for (unsigned int i = 0; i < 32; i++) {
        uint64_t carry = *rem >> 63;
        *rem <<= 1;
        digit <<= 1;
        uint64_t take = carry | (uint64_t)(*rem >= den);
        /* Keep the subtraction mask opaque to the optimizer. */
        __asm__ __volatile__("" : "+r"(take));
        *rem -= den & (UINT64_C(0) - take);
        digit |= (uint32_t)take;
    }
    return digit;
}

/* Fixed BIT_SECURITY_BITS-bit Bernoulli; error < 2^-BIT_SECURITY_BITS.
 * zero and unit probabilities are exact. Return -1 on stream failure. */
static int sample_bernoulli_ratio(const uint8_t *seed, uint16_t *nonce, uint64_t num, uint64_t den)
{
    bit_xof256_state st;
    uint8_t buf[BIT_SECURITY_BITS / 8];
    uint32_t accept = (uint32_t)(num >= den);
    uint32_t undecided = 1;
    uint64_t rem = num & (UINT64_C(0) - (uint64_t)(num < den));

    if (*nonce == UINT16_MAX)
        return -1;
    bit_xof256_init(&st, seed, BIT_SEEDBYTES, *nonce);
    *nonce = (uint16_t)(*nonce + 1U);
    if (bit_xof256_squeeze(&st, buf, sizeof(buf)) != 0) {
        bit_secure_zero(buf, sizeof(buf));
        bit_xof256_zeroize(&st);
        return -1;
    }
    for (unsigned int i = 0; i < BIT_SECURITY_BITS / 32; i++) {
        uint32_t digit = ratio_digit32(&rem, den);
        uint32_t r = (uint32_t)load16_le(buf + 4 * i) |
                     ((uint32_t)load16_le(buf + 4 * i + 2) << 16);
        accept |= undecided & (uint32_t)(r < digit);
        undecided &= (uint32_t)(r == digit);
    }
    bit_secure_zero(buf, sizeof(buf));
    bit_xof256_zeroize(&st);
    return (int)accept;
}

#endif
