#include "KISA_HMAC_SHA3.h"
#include "sha3.h"
#include <string.h>

/*
 * Return the Keccak rate (block size) in bytes for a given SHA-3 bit width.
 * rate = (1600 - 2*bitSize) / 8
 */
static int block_size(int bitSize)
{
    return (1600 - 2 * bitSize) / 8;
}

static int digest_size(int bitSize)
{
    return bitSize / 8;
}


void HMAC_SHA3(const uint8_t *message, uint32_t mlen,
               const uint8_t *key, uint32_t klen,
               uint8_t *hmac, int bitSize)
{
    const uint8_t ipad = 0x36;
    const uint8_t opad = 0x5c;
    int i;
    int blockLen  = block_size(bitSize);
    int digestLen = digest_size(bitSize);
    SHA3_CTX ctx;

    /* Buffers sized for the largest variant (SHA3-224, block=144, digest=64) */
    uint8_t tk[HMAC_SHA3_MAX_DIGEST_SIZE];   /* hashed key (when key > blockLen) */
    uint8_t tb[HMAC_SHA3_MAX_BLOCK_SIZE];    /* padded key XOR ipad / opad       */
    uint8_t inner[HMAC_SHA3_MAX_DIGEST_SIZE];/* result of inner hash              */

    /* Step 1: if key is longer than the block size, hash it first */
    if ((int)klen > blockLen) {
        sha3_hash(tk, digestLen, (uint8_t *)key, (int)klen, bitSize, SHA3_SHAKE_NONE);
        key  = tk;
        klen = (uint32_t)digestLen;
    }

    /* Step 2: inner hash  SHA3( (key XOR ipad) || message ) */
    for (i = 0;           i < (int)klen;   i++) tb[i] = ipad ^ key[i];
    for (i = (int)klen;   i < blockLen;    i++) tb[i] = ipad;

    sha3_init(&ctx, bitSize, SHA3_SHAKE_NONE);
    sha3_update(&ctx, tb, blockLen);
    sha3_update(&ctx, message, (int)mlen);
    sha3_final(&ctx, inner, digestLen);

    /* Step 3: outer hash  SHA3( (key XOR opad) || inner ) */
    for (i = 0;           i < (int)klen;   i++) tb[i] = opad ^ key[i];
    for (i = (int)klen;   i < blockLen;    i++) tb[i] = opad;

    sha3_init(&ctx, bitSize, SHA3_SHAKE_NONE);
    sha3_update(&ctx, tb, blockLen);
    sha3_update(&ctx, inner, digestLen);
    sha3_final(&ctx, hmac, digestLen);
}


int Verify_HMAC_SHA3(const uint8_t *message, uint32_t mlen,
                     const uint8_t *key, uint32_t klen,
                     const uint8_t *hmac, int bitSize)
{
    uint8_t computed[HMAC_SHA3_MAX_DIGEST_SIZE];
    int digestLen = digest_size(bitSize);
    int diff = 0;
    int i;

    HMAC_SHA3(message, mlen, key, klen, computed, bitSize);

    /* Constant-time comparison */
    for (i = 0; i < digestLen; i++)
        diff |= (hmac[i] ^ computed[i]);

    return (diff != 0) ? 1 : 0;
}
