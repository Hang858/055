/* Copyright (c) 2026 Hang Zhang. */
#ifndef BIT_RANS_TYPES_H
#define BIT_RANS_TYPES_H

#include <stdint.h>

typedef struct {
    uint32_t x_max;
    uint32_t rcp_freq;
    uint32_t bias;
    uint16_t cmpl_freq;
    uint8_t rcp_shift;
} rans_enc_symbol;

#endif
