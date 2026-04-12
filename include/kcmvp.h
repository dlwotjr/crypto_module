#pragma once

typedef unsigned char Byte;

/* Return codes */
#define SUCCESS   1
#define NOT_INIT  0
#define FAIL     -1

/* Module states */
enum KCMVP_CRYPTO_MODULE_STATE {
    KCMVP_CM_LOAD           = 1000,
    KCMVP_CM_PRE_SELFTEST,
    KCMVP_CM_NORMAL,
    KCMVP_CM_COND_SELFTEST,
    KCMVP_CM_EXECUTION,
    KCMVP_CM_DEGRADED,
    KCMVP_CM_NORMAL_ERROR,
    KCMVP_CM_CRITICAL_ERROR,
    KCMVP_CM_EXIT
};

/* ARIA operation modes */
enum ARIA_MODE {
    ARIA_ECB_MODE,
    ARIA_CBC_MODE,
    ARIA_CTR_MODE
};

/* ARIA direction */
enum ARIA_DIRECTION {
    ARIA_ENCRYPT,
    ARIA_DECRYPT
};

/* Module initialization and state */
int KCMVP_Initialize(void);
int KCMVP_GetState(void);
int KCMVP_PreSelfTest(void);
int KCMVP_AlgKATSelfTest(void);

/* ARIA key setup */
int KCMVP_ARIA_EncKeySetup(const Byte *key, Byte *roundKeys, int keyBits);
int KCMVP_ARIA_DecKeySetup(const Byte *key, Byte *roundKeys, int keyBits);

/* ARIA encryption / decryption */
void KCMVP_ARIA_Crypt(int dir, int mode, const Byte *iv,
                      const Byte *in, int inSize,
                      const Byte *key, int keyBit, Byte *out);
void KCMVP_ARIA_Crypt_Basic(const Byte *in, int rounds,
                             const Byte *roundKeys, Byte *out);

/* Debug output */
void KCMVP_ARIA_printBlock(Byte *b, int size);
void KCMVP_ARIA_printBlockOfLength(Byte *b, int len);

/* Test APIs */
int  plus(int a, int b);
int  minus(int a, int b);
int  times(int a, int b);
int  divide(int a, int b);
void updateGVar(int a);
int  getGVar(void);
void incGVar(void);
void decGVar(void);

/* ------------------------------------------------------------------ */
/* SHA-3                                                                */
/* ------------------------------------------------------------------ */
#include <stdint.h>

/* useSHAKE flag */
#define SHA3_SHAKE_NONE  0
#define SHA3_SHAKE_USE   1

/* One-shot SHA-3 / SHAKE hash
 *   bitSize : 224 / 256 / 384 / 512 (SHA-3) or 128 / 256 (SHAKE)
 *   outLen  : digest length in bytes (must equal bitSize/8 for SHA-3)
 *   Returns 0 on success.
 */
int sha3_hash(uint8_t *output, int outLen,
              uint8_t *input,  int inLen,
              int bitSize, int useSHAKE);

/* ------------------------------------------------------------------ */
/* HMAC-SHA3                                                            */
/* ------------------------------------------------------------------ */

/* Compute HMAC using the specified SHA-3 variant.
 *   bitSize : 224 / 256 / 384 / 512
 *   hmac    : caller-allocated output buffer of (bitSize/8) bytes
 */
void HMAC_SHA3(const uint8_t *message, uint32_t mlen,
               const uint8_t *key,     uint32_t klen,
               uint8_t *hmac, int bitSize);

/* Verify an HMAC tag (constant-time).
 *   Returns 0 on match, 1 on mismatch.
 *   hmac must hold exactly (bitSize/8) bytes.
 */
int Verify_HMAC_SHA3(const uint8_t *message, uint32_t mlen,
                     const uint8_t *key,     uint32_t klen,
                     const uint8_t *hmac, int bitSize);

/* ------------------------------------------------------------------ */
/* KCMVP-wrapped SHA-3 / HMAC-SHA3 API                                 */
/* (check module state and KAT flag before delegating)                 */
/* ------------------------------------------------------------------ */

/* KCMVP one-shot SHA-3 hash.
 *   bitSize : 224 / 256 / 384 / 512
 *   Returns 0 on success, -1 if module not ready or KAT not passed.
 */
int KCMVP_SHA3_Hash(uint8_t *output, int outLen,
                    const uint8_t *input, int inLen,
                    int bitSize);

/* KCMVP HMAC-SHA3.
 *   bitSize : 224 / 256 / 384 / 512
 *   hmac    : caller-allocated buffer of (bitSize/8) bytes
 *   Returns 0 on success, -1 if module not ready or KAT not passed.
 */
int KCMVP_HMAC_SHA3(const uint8_t *message, uint32_t mlen,
                    const uint8_t *key,     uint32_t klen,
                    uint8_t *hmac, int bitSize);
