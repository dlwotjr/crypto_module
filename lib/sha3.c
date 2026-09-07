#include "sha3.h"
#include <string.h>

#define KECCAK_SPONGE_BIT   1600
#define KECCAK_ROUND        24
#define KECCAK_STATE_SIZE   SHA3_STATE_SIZE

#define KECCAK_SHA3_SUFFIX  0x06
#define KECCAK_SHAKE_SUFFIX 0x1F

typedef enum { SHA3_OK = 0, SHA3_PARAMETER_ERROR = 1 } SHA3_RETURN;

static const uint32_t keccakf_rndc[KECCAK_ROUND][2] =
{
    {0x00000001, 0x00000000}, {0x00008082, 0x00000000},
    {0x0000808a, 0x80000000}, {0x80008000, 0x80000000},
    {0x0000808b, 0x00000000}, {0x80000001, 0x00000000},
    {0x80008081, 0x80000000}, {0x00008009, 0x80000000},
    {0x0000008a, 0x00000000}, {0x00000088, 0x00000000},
    {0x80008009, 0x00000000}, {0x8000000a, 0x00000000},
    {0x8000808b, 0x00000000}, {0x0000008b, 0x80000000},
    {0x00008089, 0x80000000}, {0x00008003, 0x80000000},
    {0x00008002, 0x80000000}, {0x00000080, 0x80000000},
    {0x0000800a, 0x00000000}, {0x8000000a, 0x80000000},
    {0x80008081, 0x80000000}, {0x00008080, 0x80000000},
    {0x80000001, 0x00000000}, {0x80008008, 0x80000000}
};

static const unsigned keccakf_rotc[KECCAK_ROUND] =
{
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const unsigned keccakf_piln[KECCAK_ROUND] =
{
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};


static void ROL64(uint32_t *in, uint32_t *out, int offset)
{
    int shift;

    if (offset == 0) {
        out[1] = in[1];
        out[0] = in[0];
    } else if (offset < 32) {
        shift = offset;
        out[1] = (uint32_t)((in[1] << shift) ^ (in[0] >> (32 - shift)));
        out[0] = (uint32_t)((in[0] << shift) ^ (in[1] >> (32 - shift)));
    } else if (offset < 64) {
        shift = offset - 32;
        out[1] = (uint32_t)((in[0] << shift) ^ (in[1] >> (32 - shift)));
        out[0] = (uint32_t)((in[1] << shift) ^ (in[0] >> (32 - shift)));
    } else {
        out[1] = in[1];
        out[0] = in[0];
    }
}


static void keccakf(uint8_t *state)
{
    uint32_t t[2], bc[5][2], s[25][2] = { { 0 } };
    int i, j, round;

    for (i = 0; i < 25; i++) {
        s[i][0] = (uint32_t)(state[i*8+0])       |
                  (uint32_t)(state[i*8+1] << 8)  |
                  (uint32_t)(state[i*8+2] << 16) |
                  (uint32_t)(state[i*8+3] << 24);
        s[i][1] = (uint32_t)(state[i*8+4])       |
                  (uint32_t)(state[i*8+5] << 8)  |
                  (uint32_t)(state[i*8+6] << 16) |
                  (uint32_t)(state[i*8+7] << 24);
    }

    for (round = 0; round < KECCAK_ROUND; round++) {
        /* Theta */
        for (i = 0; i < 5; i++) {
            bc[i][0] = s[i][0] ^ s[i+5][0] ^ s[i+10][0] ^ s[i+15][0] ^ s[i+20][0];
            bc[i][1] = s[i][1] ^ s[i+5][1] ^ s[i+10][1] ^ s[i+15][1] ^ s[i+20][1];
        }
        for (i = 0; i < 5; i++) {
            ROL64(bc[(i+1)%5], t, 1);
            t[0] ^= bc[(i+4)%5][0];
            t[1] ^= bc[(i+4)%5][1];
            for (j = 0; j < 25; j += 5) {
                s[j+i][0] ^= t[0];
                s[j+i][1] ^= t[1];
            }
        }

        /* Rho & Pi */
        t[0] = s[1][0];
        t[1] = s[1][1];
        for (i = 0; i < KECCAK_ROUND; i++) {
            j = keccakf_piln[i];
            bc[0][0] = s[j][0];
            bc[0][1] = s[j][1];
            ROL64(t, s[j], keccakf_rotc[i]);
            t[0] = bc[0][0];
            t[1] = bc[0][1];
        }

        /* Chi */
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) {
                bc[i][0] = s[j+i][0];
                bc[i][1] = s[j+i][1];
            }
            for (i = 0; i < 5; i++) {
                s[j+i][0] ^= (~bc[(i+1)%5][0]) & bc[(i+2)%5][0];
                s[j+i][1] ^= (~bc[(i+1)%5][1]) & bc[(i+2)%5][1];
            }
        }

        /* Iota */
        s[0][0] ^= keccakf_rndc[round][0];
        s[0][1] ^= keccakf_rndc[round][1];
    }

    for (i = 0; i < 25; i++) {
        state[i*8+0] = (uint8_t)(s[i][0]);
        state[i*8+1] = (uint8_t)(s[i][0] >> 8);
        state[i*8+2] = (uint8_t)(s[i][0] >> 16);
        state[i*8+3] = (uint8_t)(s[i][0] >> 24);
        state[i*8+4] = (uint8_t)(s[i][1]);
        state[i*8+5] = (uint8_t)(s[i][1] >> 8);
        state[i*8+6] = (uint8_t)(s[i][1] >> 16);
        state[i*8+7] = (uint8_t)(s[i][1] >> 24);
    }
}


static int keccak_absorb(SHA3_CTX *ctx, const uint8_t *input, int inLen)
{
    const uint8_t *buf = input;
    int iLen = inLen;
    int rateInBytes = (int)ctx->rate / 8;
    int blockSize = 0;
    int i;

    if ((ctx->rate + ctx->capacity) != KECCAK_SPONGE_BIT)
        return SHA3_PARAMETER_ERROR;
    if (((ctx->rate % 8) != 0) || (ctx->rate < 1))
        return SHA3_PARAMETER_ERROR;

    while (iLen > 0) {
        if ((ctx->end_offset != 0) && (ctx->end_offset < rateInBytes)) {
            blockSize = (((iLen + ctx->end_offset) < rateInBytes) ?
                         (iLen + ctx->end_offset) : rateInBytes);
            for (i = ctx->end_offset; i < blockSize; i++)
                ctx->state[i] ^= buf[i - ctx->end_offset];
            buf  += blockSize - ctx->end_offset;
            iLen -= blockSize - ctx->end_offset;
        } else {
            blockSize = (iLen < rateInBytes) ? iLen : rateInBytes;
            for (i = 0; i < blockSize; i++)
                ctx->state[i] ^= buf[i];
            buf  += blockSize;
            iLen -= blockSize;
        }

        if (blockSize == rateInBytes) {
            keccakf(ctx->state);
            blockSize = 0;
        }
        ctx->end_offset = blockSize;
    }

    return SHA3_OK;
}


static int keccak_squeeze(SHA3_CTX *ctx, uint8_t *output, int outLen)
{
    uint8_t *buf = output;
    int oLen = outLen;
    int rateInBytes = (int)ctx->rate / 8;
    int blockSize = ctx->end_offset;
    int i;

    ctx->state[blockSize] ^= ctx->suffix;

    if (((ctx->suffix & 0x80) != 0) && (blockSize == (rateInBytes - 1)))
        keccakf(ctx->state);

    ctx->state[rateInBytes - 1] ^= 0x80;
    keccakf(ctx->state);

    while (oLen > 0) {
        blockSize = (oLen < rateInBytes) ? oLen : rateInBytes;
        for (i = 0; i < blockSize; i++)
            buf[i] = ctx->state[i];
        buf  += blockSize;
        oLen -= blockSize;
        if (oLen > 0)
            keccakf(ctx->state);
    }

    return SHA3_OK;
}


static void secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;

    while (len-- > 0)
        *p++ = 0;
}

int sha3_init(SHA3_CTX *ctx, int bitSize, int useSHAKE)
{
    if (ctx == NULL)
        return SHA3_PARAMETER_ERROR;
    secure_zero(ctx, sizeof(*ctx));
    if (useSHAKE != SHA3_SHAKE_NONE && useSHAKE != SHA3_SHAKE_USE)
        return SHA3_PARAMETER_ERROR;
    if (useSHAKE == SHA3_SHAKE_USE) {
        if (bitSize != KECCAK_SHAKE128 && bitSize != KECCAK_SHAKE256)
            return SHA3_PARAMETER_ERROR;
    } else if (bitSize != KECCAK_SHA3_224 &&
               bitSize != KECCAK_SHA3_256 &&
               bitSize != KECCAK_SHA3_384 &&
               bitSize != KECCAK_SHA3_512) {
        return SHA3_PARAMETER_ERROR;
    }

    ctx->capacity = (unsigned int)(bitSize * 2);
    ctx->rate = KECCAK_SPONGE_BIT - ctx->capacity;
    ctx->suffix = useSHAKE == SHA3_SHAKE_USE ?
        KECCAK_SHAKE_SUFFIX : KECCAK_SHA3_SUFFIX;
    ctx->initialized = 1;
    ctx->use_shake = useSHAKE;
    ctx->bit_size = bitSize;
    return SHA3_OK;
}

int sha3_update(SHA3_CTX *ctx, const uint8_t *input, int inLen)
{
    if (ctx == NULL || !ctx->initialized || inLen < 0 ||
        (inLen > 0 && input == NULL))
        return SHA3_PARAMETER_ERROR;
    if (inLen == 0)
        return SHA3_OK;
    return keccak_absorb(ctx, input, inLen);
}

int sha3_final(SHA3_CTX *ctx, uint8_t *output, int outLen)
{
    int result;

    if (ctx == NULL || !ctx->initialized || output == NULL || outLen <= 0)
        return SHA3_PARAMETER_ERROR;
    if (ctx->use_shake == SHA3_SHAKE_NONE && outLen != ctx->bit_size / 8)
        return SHA3_PARAMETER_ERROR;

    result = keccak_squeeze(ctx, output, outLen);
    secure_zero(ctx, sizeof(*ctx));
    return result;
}

int sha3_hash(uint8_t *output, int outLen,
              const uint8_t *input, int inLen,
              int bitSize, int useSHAKE)
{
    SHA3_CTX ctx;
    int result;

    if (output == NULL || outLen <= 0 || inLen < 0 ||
        (inLen > 0 && input == NULL))
        return SHA3_PARAMETER_ERROR;
    result = sha3_init(&ctx, bitSize, useSHAKE);
    if (result == SHA3_OK)
        result = sha3_update(&ctx, input, inLen);
    if (result == SHA3_OK)
        result = sha3_final(&ctx, output, outLen);
    else
        secure_zero(&ctx, sizeof(ctx));
    return result;
}
