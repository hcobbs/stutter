/*
 * aes256.c - AES-256 implementation (FIPS 197)
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] Generated with human review
 *
 * Note: This implementation prioritizes clarity and correctness over speed.
 * For production use with high throughput requirements, consider hardware
 * AES-NI intrinsics (not C89 compatible).
 */

#include "stutter_internal.h"
#include <string.h>

/* S-box (substitution values) */
static const unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* Round constants */
static const unsigned char rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* Multiply by 2 in GF(2^8) */
static unsigned char xtime(unsigned char x)
{
    unsigned char result;
    result = (unsigned char)(x << 1);
    if (x & 0x80) {
        result ^= 0x1b;
    }
    return result;
}

/* Key expansion for AES-256 (14 rounds) */
void aes256_init(aes256_ctx_t *ctx, const unsigned char key[32])
{
    unsigned long *rk = ctx->rk;
    int i;

    /* Copy initial key */
    for (i = 0; i < 8; i++) {
        rk[i] = ((unsigned long)key[4 * i] << 24) |
                ((unsigned long)key[4 * i + 1] << 16) |
                ((unsigned long)key[4 * i + 2] << 8) |
                ((unsigned long)key[4 * i + 3]);
    }

    /* Expand key */
    for (i = 8; i < 60; i++) {
        unsigned long temp = rk[i - 1];

        if ((i % 8) == 0) {
            /* RotWord + SubWord + Rcon */
            temp = ((unsigned long)sbox[(temp >> 16) & 0xff] << 24) |
                   ((unsigned long)sbox[(temp >> 8) & 0xff] << 16) |
                   ((unsigned long)sbox[temp & 0xff] << 8) |
                   ((unsigned long)sbox[(temp >> 24) & 0xff]);
            temp ^= ((unsigned long)rcon[i / 8 - 1] << 24);
        } else if ((i % 8) == 4) {
            /* SubWord only for AES-256 */
            temp = ((unsigned long)sbox[(temp >> 24) & 0xff] << 24) |
                   ((unsigned long)sbox[(temp >> 16) & 0xff] << 16) |
                   ((unsigned long)sbox[(temp >> 8) & 0xff] << 8) |
                   ((unsigned long)sbox[temp & 0xff]);
        }

        rk[i] = rk[i - 8] ^ temp;
    }
}

/* Encrypt a single 16-byte block */
void aes256_encrypt(const aes256_ctx_t *ctx,
                    const unsigned char in[16],
                    unsigned char out[16])
{
    const unsigned long *rk = ctx->rk;
    unsigned char state[16];
    unsigned char tmp[16];
    int round;
    int i;

    /* Copy input to state */
    for (i = 0; i < 16; i++) {
        state[i] = in[i];
    }

    /* Initial round key addition */
    for (i = 0; i < 4; i++) {
        state[4 * i] ^= (unsigned char)(rk[i] >> 24);
        state[4 * i + 1] ^= (unsigned char)(rk[i] >> 16);
        state[4 * i + 2] ^= (unsigned char)(rk[i] >> 8);
        state[4 * i + 3] ^= (unsigned char)(rk[i]);
    }

    /* Main rounds */
    for (round = 1; round < 14; round++) {
        /* SubBytes */
        for (i = 0; i < 16; i++) {
            tmp[i] = sbox[state[i]];
        }

        /* ShiftRows */
        state[0] = tmp[0];
        state[1] = tmp[5];
        state[2] = tmp[10];
        state[3] = tmp[15];
        state[4] = tmp[4];
        state[5] = tmp[9];
        state[6] = tmp[14];
        state[7] = tmp[3];
        state[8] = tmp[8];
        state[9] = tmp[13];
        state[10] = tmp[2];
        state[11] = tmp[7];
        state[12] = tmp[12];
        state[13] = tmp[1];
        state[14] = tmp[6];
        state[15] = tmp[11];

        /* MixColumns */
        for (i = 0; i < 4; i++) {
            unsigned char a = state[4 * i];
            unsigned char b = state[4 * i + 1];
            unsigned char c = state[4 * i + 2];
            unsigned char d = state[4 * i + 3];
            unsigned char xa = xtime(a);
            unsigned char xb = xtime(b);
            unsigned char xc = xtime(c);
            unsigned char xd = xtime(d);

            tmp[4 * i] = xa ^ xb ^ b ^ c ^ d;
            tmp[4 * i + 1] = a ^ xb ^ xc ^ c ^ d;
            tmp[4 * i + 2] = a ^ b ^ xc ^ xd ^ d;
            tmp[4 * i + 3] = xa ^ a ^ b ^ c ^ xd;
        }

        /* AddRoundKey */
        for (i = 0; i < 4; i++) {
            state[4 * i] = tmp[4 * i] ^ (unsigned char)(rk[4 * round + i] >> 24);
            state[4 * i + 1] = tmp[4 * i + 1] ^ (unsigned char)(rk[4 * round + i] >> 16);
            state[4 * i + 2] = tmp[4 * i + 2] ^ (unsigned char)(rk[4 * round + i] >> 8);
            state[4 * i + 3] = tmp[4 * i + 3] ^ (unsigned char)(rk[4 * round + i]);
        }
    }

    /* Final round (no MixColumns) */
    /* SubBytes */
    for (i = 0; i < 16; i++) {
        tmp[i] = sbox[state[i]];
    }

    /* ShiftRows */
    state[0] = tmp[0];
    state[1] = tmp[5];
    state[2] = tmp[10];
    state[3] = tmp[15];
    state[4] = tmp[4];
    state[5] = tmp[9];
    state[6] = tmp[14];
    state[7] = tmp[3];
    state[8] = tmp[8];
    state[9] = tmp[13];
    state[10] = tmp[2];
    state[11] = tmp[7];
    state[12] = tmp[12];
    state[13] = tmp[1];
    state[14] = tmp[6];
    state[15] = tmp[11];

    /* AddRoundKey (final) */
    for (i = 0; i < 4; i++) {
        out[4 * i] = state[4 * i] ^ (unsigned char)(rk[56 + i] >> 24);
        out[4 * i + 1] = state[4 * i + 1] ^ (unsigned char)(rk[56 + i] >> 16);
        out[4 * i + 2] = state[4 * i + 2] ^ (unsigned char)(rk[56 + i] >> 8);
        out[4 * i + 3] = state[4 * i + 3] ^ (unsigned char)(rk[56 + i]);
    }
}

void aes256_done(aes256_ctx_t *ctx)
{
    /* Zero key schedule */
    platform_secure_zero(ctx, sizeof(*ctx));
}
