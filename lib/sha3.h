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

/* Streaming interface */
void sha3_init(int bitSize, int useSHAKE);
int  sha3_update(uint8_t *input, int inLen);
int  sha3_final(uint8_t *output, int outLen);

/* One-shot interface */
int  sha3_hash(uint8_t *output, int outLen,
               uint8_t *input, int inLen,
               int bitSize, int useSHAKE);

#ifdef __cplusplus
}
#endif

#endif /* _SHA3_H_ */
