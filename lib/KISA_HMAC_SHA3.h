#ifndef _KISA_HMAC_SHA3_H_
#define _KISA_HMAC_SHA3_H_

#include <stdint.h>

/*
 * HMAC-SHA3 block sizes (Keccak rate in bytes = (1600 - 2*bitSize) / 8)
 *   SHA3-224 : 1152 / 8 = 144
 *   SHA3-256 : 1088 / 8 = 136
 *   SHA3-384 :  832 / 8 = 104
 *   SHA3-512 :  576 / 8 =  72
 */
#define HMAC_SHA3_224_BLOCK_SIZE  144
#define HMAC_SHA3_256_BLOCK_SIZE  136
#define HMAC_SHA3_384_BLOCK_SIZE  104
#define HMAC_SHA3_512_BLOCK_SIZE   72

/* SHA3 digest sizes in bytes */
#define SHA3_224_DIGEST_SIZE  28
#define SHA3_256_DIGEST_SIZE  32
#define SHA3_384_DIGEST_SIZE  48
#define SHA3_512_DIGEST_SIZE  64

/* Maximum values for static buffer sizing */
#define HMAC_SHA3_MAX_BLOCK_SIZE   144
#define HMAC_SHA3_MAX_DIGEST_SIZE   64

/*
 * HMAC_SHA3 - compute HMAC using the specified SHA-3 variant.
 *
 * bitSize : 224, 256, 384, or 512
 * hmac    : output buffer; caller must allocate (bitSize/8) bytes.
 */
void HMAC_SHA3(const uint8_t *message, uint32_t mlen,
               const uint8_t *key,     uint32_t klen,
               uint8_t *hmac, int bitSize);

/*
 * Verify_HMAC_SHA3 - constant-time comparison.
 * Returns 0 on match, 1 on mismatch.
 * hmac must contain exactly (bitSize/8) bytes.
 */
int Verify_HMAC_SHA3(const uint8_t *message, uint32_t mlen,
                     const uint8_t *key,     uint32_t klen,
                     const uint8_t *hmac, int bitSize);

#endif /* _KISA_HMAC_SHA3_H_ */
