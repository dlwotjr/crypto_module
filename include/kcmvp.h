#ifndef KCMVP_H
#define KCMVP_H

#include <stdint.h>

typedef unsigned char Byte;

/* Public return codes. Algorithm-specific successful values may be positive. */
enum KCMVP_ERROR_CODE {
    KCMVP_SUCCESS               = 0,
    KCMVP_ERROR_GENERIC         = -1,
    KCMVP_ERROR_NOT_INITIALIZED = -2,
    KCMVP_ERROR_INVALID_STATE   = -3,
    KCMVP_ERROR_SELF_TEST       = -4,
    KCMVP_ERROR_INVALID_PARAM   = -5,
    KCMVP_ERROR_CRYPTO          = -6,
    KCMVP_ERROR_RESEED_REQUIRED = -7,
    KCMVP_ERROR_INVALID_PUBLIC_KEY = -8,
    KCMVP_ERROR_CONDITIONAL_TEST = -9
};

/* Compatibility names used by the existing course application. */
#define SUCCESS  KCMVP_SUCCESS
#define NOT_INIT KCMVP_ERROR_NOT_INITIALIZED
#define FAIL     KCMVP_ERROR_GENERIC

typedef enum KCMVP_CRYPTO_MODULE_STATE {
    KCMVP_CM_LOAD = 1000,
    KCMVP_CM_PRE_SELFTEST,
    KCMVP_CM_NORMAL,
    KCMVP_CM_COND_SELFTEST,
    KCMVP_CM_EXECUTION,
    KCMVP_CM_DEGRADED,
    KCMVP_CM_NORMAL_ERROR,
    KCMVP_CM_CRITICAL_ERROR,
    KCMVP_CM_EXIT
} KCMVP_MODULE_STATE;

typedef struct KCMVP_MODULE_STATUS {
    KCMVP_MODULE_STATE state;
    int initialized;
    int operational;
} KCMVP_MODULE_STATUS;

#ifndef KCMVP_INTERNAL_ARIA_TYPES
enum ARIA_MODE {
    ARIA_ECB_MODE,
    ARIA_CBC_MODE,
    ARIA_CTR_MODE
};

enum ARIA_DIRECTION {
    ARIA_ENCRYPT,
    ARIA_DECRYPT
};
#endif

int KCMVP_Initialize(void);
int KCMVP_GetState(void);
int KCMVP_GetStatus(KCMVP_MODULE_STATUS *status);
int KCMVP_Zeroize(void);
int KCMVP_Shutdown(void);

/* Existing self-test entry points retained for course-code compatibility. */
int KCMVP_PreSelfTest(void);
int KCMVP_AlgKATSelfTest(void);

int KCMVP_ARIA_EncKeySetup(const Byte *key, Byte *roundKeys, int keyBits);
int KCMVP_ARIA_DecKeySetup(const Byte *key, Byte *roundKeys, int keyBits);
int KCMVP_ARIA_Crypt(int dir, int mode, const Byte *iv,
                     const Byte *in, int inSize,
                     const Byte *key, int keyBit, Byte *out);
int KCMVP_ARIA_Crypt_Basic(const Byte *in, int rounds,
                           const Byte *roundKeys, Byte *out);

int KCMVP_SHA3_Hash(uint8_t *output, int outLen,
                    const uint8_t *input, int inLen,
                    int bitSize);
int KCMVP_HMAC_SHA3(const uint8_t *message, uint32_t mlen,
                    const uint8_t *key, uint32_t klen,
                    uint8_t *hmac, int bitSize);

int KCMVP_RNG_Generate(uint8_t *output, uint32_t output_len);
int KCMVP_RNG_Reseed(void);
int KCMVP_RNG_Uninstantiate(void);

#define KCMVP_ECC_P256_PRIVATE_KEY_BYTES 32
#define KCMVP_ECC_P256_PUBLIC_KEY_BYTES 64
#define KCMVP_ECC_P256_SHARED_SECRET_BYTES 32

int KCMVP_ECC_GenerateKeyPair(uint8_t *public_key, uint32_t public_key_len,
                              uint8_t *private_key, uint32_t private_key_len);
int KCMVP_ECC_ComputeSharedSecret(const uint8_t *private_key,
                                  uint32_t private_key_len,
                                  const uint8_t *peer_public_key,
                                  uint32_t peer_public_key_len,
                                  uint8_t *shared_secret,
                                  uint32_t shared_secret_len);

#define KCMVP_MLKEM768_PUBLIC_KEY_BYTES 1184
#define KCMVP_MLKEM768_SECRET_KEY_BYTES 2400
#define KCMVP_MLKEM768_CIPHERTEXT_BYTES 1088
#define KCMVP_MLKEM768_SHARED_SECRET_BYTES 32

int KCMVP_MLKEM_Keypair(uint8_t *public_key, uint32_t public_key_len,
                        uint8_t *secret_key, uint32_t secret_key_len);
int KCMVP_MLKEM_Encaps(uint8_t *ciphertext, uint32_t ciphertext_len,
                       uint8_t *shared_secret, uint32_t shared_secret_len,
                       const uint8_t *public_key, uint32_t public_key_len);
int KCMVP_MLKEM_Decaps(uint8_t *shared_secret, uint32_t shared_secret_len,
                       const uint8_t *ciphertext, uint32_t ciphertext_len,
                       const uint8_t *secret_key, uint32_t secret_key_len);

#endif
