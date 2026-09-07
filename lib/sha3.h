#ifndef _SHA3_H_
#define _SHA3_H_

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SHA-3 / SHAKE bit-size constants */
#define KECCAK_SHA3_224   224
#define KECCAK_SHA3_256   256
#define KECCAK_SHA3_384   384
#define KECCAK_SHA3_512   512
#define KECCAK_SHAKE128   128
#define KECCAK_SHAKE256   256

/* useSHAKE flag values */
#define SHA3_SHAKE_NONE   0
#define SHA3_SHAKE_USE    1

#define SHA3_STATE_SIZE   200

typedef struct {
    uint8_t state[SHA3_STATE_SIZE];
    unsigned int rate;
    unsigned int capacity;
    unsigned int suffix;
    int end_offset;
    int initialized;
    int use_shake;
    int bit_size;
} SHA3_CTX;

/* Streaming interface */
int sha3_init(SHA3_CTX *ctx, int bitSize, int useSHAKE);
int sha3_update(SHA3_CTX *ctx, const uint8_t *input, int inLen);
int sha3_final(SHA3_CTX *ctx, uint8_t *output, int outLen);

/* One-shot interface */
int sha3_hash(uint8_t *output, int outLen,
              const uint8_t *input, int inLen,
              int bitSize, int useSHAKE);

#ifdef __cplusplus
}
#endif

#endif /* _SHA3_H_ */
