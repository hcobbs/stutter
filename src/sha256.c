/*
 * sha256.c - SHA-256 implementation (FIPS 180-4)
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] Generated with human review
 */

#include "stutter_internal.h"
#include <string.h>

/* SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes) */
static const unsigned long K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

/* Utility macros */
#define ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

/* Process a single 64-byte block */
static void sha256_transform(sha256_ctx_t *ctx, const unsigned char block[64])
{
    unsigned long a, b, c, d, e, f, g, h;
    unsigned long t1, t2;
    unsigned long W[64];
    int i;

    /* Prepare message schedule */
    for (i = 0; i < 16; i++) {
        W[i] = ((unsigned long)block[i * 4] << 24) |
               ((unsigned long)block[i * 4 + 1] << 16) |
               ((unsigned long)block[i * 4 + 2] << 8) |
               ((unsigned long)block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16];
        W[i] &= 0xffffffffUL;
    }

    /* Initialize working variables */
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    /* Main loop */
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + W[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = (d + t1) & 0xffffffffUL;
        d = c;
        c = b;
        b = a;
        a = (t1 + t2) & 0xffffffffUL;
    }

    /* Add compressed chunk to current hash */
    ctx->state[0] = (ctx->state[0] + a) & 0xffffffffUL;
    ctx->state[1] = (ctx->state[1] + b) & 0xffffffffUL;
    ctx->state[2] = (ctx->state[2] + c) & 0xffffffffUL;
    ctx->state[3] = (ctx->state[3] + d) & 0xffffffffUL;
    ctx->state[4] = (ctx->state[4] + e) & 0xffffffffUL;
    ctx->state[5] = (ctx->state[5] + f) & 0xffffffffUL;
    ctx->state[6] = (ctx->state[6] + g) & 0xffffffffUL;
    ctx->state[7] = (ctx->state[7] + h) & 0xffffffffUL;
}

void sha256_init(sha256_ctx_t *ctx)
{
    ctx->state[0] = 0x6a09e667UL;
    ctx->state[1] = 0xbb67ae85UL;
    ctx->state[2] = 0x3c6ef372UL;
    ctx->state[3] = 0xa54ff53aUL;
    ctx->state[4] = 0x510e527fUL;
    ctx->state[5] = 0x9b05688cUL;
    ctx->state[6] = 0x1f83d9abUL;
    ctx->state[7] = 0x5be0cd19UL;
    ctx->count[0] = 0;
    ctx->count[1] = 0;
    ctx->buf_len = 0;
}

void sha256_update(sha256_ctx_t *ctx, const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    size_t fill;
    size_t left;

    if (len == 0) {
        return;
    }

    left = ctx->buf_len;
    fill = 64 - left;

    /* Update bit count */
    ctx->count[0] += (unsigned long)(len << 3);
    if (ctx->count[0] < (unsigned long)(len << 3)) {
        ctx->count[1]++;
    }
    ctx->count[1] += (unsigned long)(len >> 29);

    /* Handle any pending data in buffer */
    if (left > 0 && len >= fill) {
        memcpy(ctx->buffer + left, p, fill);
        sha256_transform(ctx, ctx->buffer);
        p += fill;
        len -= fill;
        left = 0;
        ctx->buf_len = 0;
    }

    /* Process complete blocks */
    while (len >= 64) {
        sha256_transform(ctx, p);
        p += 64;
        len -= 64;
    }

    /* Buffer remaining data */
    if (len > 0) {
        memcpy(ctx->buffer + left, p, len);
        ctx->buf_len = left + len;
    }
}

void sha256_final(sha256_ctx_t *ctx, unsigned char digest[32])
{
    unsigned char pad[64];
    unsigned char len_bits[8];
    size_t pad_len;
    int i;

    /* Encode bit length (big-endian) */
    len_bits[0] = (unsigned char)(ctx->count[1] >> 24);
    len_bits[1] = (unsigned char)(ctx->count[1] >> 16);
    len_bits[2] = (unsigned char)(ctx->count[1] >> 8);
    len_bits[3] = (unsigned char)(ctx->count[1]);
    len_bits[4] = (unsigned char)(ctx->count[0] >> 24);
    len_bits[5] = (unsigned char)(ctx->count[0] >> 16);
    len_bits[6] = (unsigned char)(ctx->count[0] >> 8);
    len_bits[7] = (unsigned char)(ctx->count[0]);

    /* Pad message */
    pad[0] = 0x80;
    memset(pad + 1, 0, 63);

    if (ctx->buf_len < 56) {
        pad_len = 56 - ctx->buf_len;
    } else {
        pad_len = 120 - ctx->buf_len;
    }

    sha256_update(ctx, pad, pad_len);
    sha256_update(ctx, len_bits, 8);

    /* Output digest (big-endian) */
    for (i = 0; i < 8; i++) {
        digest[i * 4] = (unsigned char)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (unsigned char)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (unsigned char)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (unsigned char)(ctx->state[i]);
    }

    /* Zero sensitive state */
    platform_secure_zero(ctx, sizeof(*ctx));
}

void sha256(const void *data, size_t len, unsigned char digest[32])
{
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}
