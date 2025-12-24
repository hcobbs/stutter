/*
 * aes256.c - AES-256 constant-time implementation (FIPS 197)
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] Generated with human review
 *
 * SECURITY: This implementation uses a constant-time S-box computation
 * based on algebraic operations in GF(2^8), avoiding table lookups that
 * would create cache-timing side channels.
 *
 * The S-box is computed as: S(x) = A * (x^-1 in GF(2^8)) + c
 * where A is the affine transformation matrix and c = 0x63.
 * Inversion uses Fermat's little theorem: x^-1 = x^254 in GF(2^8).
 */

#include "stutter_internal.h"
#include <string.h>

/* ============================================================================
 * Constant-time GF(2^8) arithmetic
 * ============================================================================ */

/*
 * Multiply in GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1.
 * Constant-time implementation using only bitwise operations.
 */
static unsigned char gf_mul(unsigned char a, unsigned char b)
{
    unsigned char result = 0;
    unsigned char hi_bit;
    int i;

    for (i = 0; i < 8; i++) {
        /* Add a to result if low bit of b is set (constant-time) */
        result ^= a & (unsigned char)(-(b & 1));

        /* Remember high bit of a before shift */
        hi_bit = (unsigned char)((a >> 7) & 1);

        /* Shift a left by 1 */
        a = (unsigned char)(a << 1);

        /* Reduce modulo x^8 + x^4 + x^3 + x + 1 if high bit was set */
        a ^= (unsigned char)(0x1b & -(hi_bit));

        /* Shift b right by 1 */
        b = (unsigned char)(b >> 1);
    }

    return result;
}

/*
 * Square in GF(2^8). Optimized version of gf_mul(x, x).
 */
static unsigned char gf_sq(unsigned char x)
{
    return gf_mul(x, x);
}

/*
 * Compute multiplicative inverse in GF(2^8) using Fermat's little theorem.
 * x^-1 = x^254 = x^(2^8 - 2)
 *
 * We compute this as: x^254 = x^128 * x^64 * x^32 * x^16 * x^8 * x^4 * x^2
 * Using repeated squaring.
 *
 * Returns 0 for input 0 (which is correct for AES S-box).
 */
static unsigned char gf_inv(unsigned char x)
{
    unsigned char x2, x4, x8, x16, x32, x64, x128;

    /* x^2 */
    x2 = gf_sq(x);
    /* x^4 */
    x4 = gf_sq(x2);
    /* x^8 */
    x8 = gf_sq(x4);
    /* x^16 */
    x16 = gf_sq(x8);
    /* x^32 */
    x32 = gf_sq(x16);
    /* x^64 */
    x64 = gf_sq(x32);
    /* x^128 */
    x128 = gf_sq(x64);

    /* x^254 = x^128 * x^64 * x^32 * x^16 * x^8 * x^4 * x^2 */
    return gf_mul(gf_mul(gf_mul(gf_mul(gf_mul(gf_mul(x128, x64), x32), x16), x8), x4), x2);
}

/*
 * AES S-box: affine transformation over GF(2).
 * S(x) = A * gf_inv(x) + 0x63
 *
 * The affine transformation matrix A is:
 * [1 0 0 0 1 1 1 1]
 * [1 1 0 0 0 1 1 1]
 * [1 1 1 0 0 0 1 1]
 * [1 1 1 1 0 0 0 1]
 * [1 1 1 1 1 0 0 0]
 * [0 1 1 1 1 1 0 0]
 * [0 0 1 1 1 1 1 0]
 * [0 0 0 1 1 1 1 1]
 *
 * This can be computed as: y_i = x_i XOR x_{i+4} XOR x_{i+5} XOR x_{i+6} XOR x_{i+7} XOR c_i
 * where indices are mod 8 and c = 0x63.
 */
static unsigned char sbox_compute(unsigned char x)
{
    unsigned char inv = gf_inv(x);
    unsigned char result = 0;
    unsigned char bit;
    int i;

    for (i = 0; i < 8; i++) {
        /* y_i = x_i XOR x_{(i+4)%8} XOR x_{(i+5)%8} XOR x_{(i+6)%8} XOR x_{(i+7)%8} */
        bit = (unsigned char)(
            ((inv >> i) & 1) ^
            ((inv >> ((i + 4) % 8)) & 1) ^
            ((inv >> ((i + 5) % 8)) & 1) ^
            ((inv >> ((i + 6) % 8)) & 1) ^
            ((inv >> ((i + 7) % 8)) & 1)
        );
        result |= (unsigned char)(bit << i);
    }

    /* Add constant 0x63 */
    return result ^ 0x63;
}

/* ============================================================================
 * AES round operations
 * ============================================================================ */

/* Round constants for key expansion */
static const unsigned char rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* Multiply by 2 in GF(2^8) - constant time version */
static unsigned char xtime(unsigned char x)
{
    unsigned char hi_bit = (unsigned char)((x >> 7) & 1);
    unsigned char shifted = (unsigned char)(x << 1);
    return shifted ^ (unsigned char)(0x1b & -(hi_bit));
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
            temp = ((unsigned long)sbox_compute((unsigned char)((temp >> 16) & 0xff)) << 24) |
                   ((unsigned long)sbox_compute((unsigned char)((temp >> 8) & 0xff)) << 16) |
                   ((unsigned long)sbox_compute((unsigned char)(temp & 0xff)) << 8) |
                   ((unsigned long)sbox_compute((unsigned char)((temp >> 24) & 0xff)));
            temp ^= ((unsigned long)rcon[i / 8 - 1] << 24);
        } else if ((i % 8) == 4) {
            /* SubWord only for AES-256 */
            temp = ((unsigned long)sbox_compute((unsigned char)((temp >> 24) & 0xff)) << 24) |
                   ((unsigned long)sbox_compute((unsigned char)((temp >> 16) & 0xff)) << 16) |
                   ((unsigned long)sbox_compute((unsigned char)((temp >> 8) & 0xff)) << 8) |
                   ((unsigned long)sbox_compute((unsigned char)(temp & 0xff)));
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
        /* SubBytes - constant time computation */
        for (i = 0; i < 16; i++) {
            tmp[i] = sbox_compute(state[i]);
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
    /* SubBytes - constant time computation */
    for (i = 0; i < 16; i++) {
        tmp[i] = sbox_compute(state[i]);
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
