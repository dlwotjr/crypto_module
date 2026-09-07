#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define KCMVP_INTERNAL_ARIA_TYPES
#include "KCMVP_Crypto.h"
#include "KISA_HMAC_SHA3.h"
#include "aria.h"
#include "ecc.h"
#include "entropy.h"
#include "hash_drbg.h"
#include "integrity.h"
#include "module_state.h"
#include "mlkem.h"
#include "selftest.h"
#include "sha3.h"

#define EXPORT __attribute__((visibility("default")))

static IS_ALG_TESTED algTestedFlag;
static HASH_DRBG_CTX module_drbg;

int kcmvp_internal_randombytes(uint8_t *output, size_t output_len)
{
    return hash_drbg_generate(&module_drbg, output, output_len) ==
        KCMVP_SUCCESS ? 0 : -1;
}

static void secure_zero(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;

    while (len-- > 0)
        *p++ = 0;
}

static void reset_module_data(void)
{
    secure_zero(&algTestedFlag, sizeof(algTestedFlag));
    hash_drbg_uninstantiate(&module_drbg);
}

static int pre_self_test(void)
{
    return integrity_verify();
}

static int finish_service(int result)
{
    int transition_result = module_complete_service();

    if (transition_result != KCMVP_SUCCESS)
        return transition_result;
    return result;
}

static int authorize_algorithm(unsigned char kat_passed)
{
    int result = module_authorize_service();

    if (result != KCMVP_SUCCESS)
        return result;
    if (!kat_passed)
        return finish_service(KCMVP_ERROR_SELF_TEST);
    return KCMVP_SUCCESS;
}

EXPORT int KCMVP_GetState(void)
{
    return module_state_get();
}

EXPORT int KCMVP_GetStatus(KCMVP_MODULE_STATUS *status)
{
    int state;

    if (status == NULL)
        return KCMVP_ERROR_INVALID_PARAM;

    state = module_state_get();
    status->state = (KCMVP_MODULE_STATE)state;
    status->initialized = (state != KCMVP_CM_LOAD && state != KCMVP_CM_EXIT);
    status->operational = (state == KCMVP_CM_NORMAL);
    return KCMVP_SUCCESS;
}

EXPORT int KCMVP_PreSelfTest(void)
{
    if (module_state_get() != KCMVP_CM_PRE_SELFTEST)
        return KCMVP_ERROR_INVALID_STATE;
    return pre_self_test();
}

EXPORT int KCMVP_AlgKATSelfTest(void)
{
    if (module_state_get() != KCMVP_CM_PRE_SELFTEST)
        return KCMVP_ERROR_INVALID_STATE;
    return selftest_run_startup(&algTestedFlag.startup);
}

EXPORT int KCMVP_Initialize(void)
{
    int result;

    if (module_state_get() != KCMVP_CM_LOAD)
        return KCMVP_ERROR_INVALID_STATE;

    reset_module_data();
    result = module_state_transition(KCMVP_EVENT_BEGIN_SELFTEST);
    if (result != KCMVP_SUCCESS)
        return result;

    result = pre_self_test();
    if (result == KCMVP_SUCCESS)
        result = entropy_startup_health_test();
    if (result == KCMVP_SUCCESS)
        result = selftest_run_startup(&algTestedFlag.startup);
    if (result == KCMVP_SUCCESS)
        result = hash_drbg_instantiate(&module_drbg, NULL, 0);

    if (result != KCMVP_SUCCESS) {
        reset_module_data();
        module_state_transition(KCMVP_EVENT_FATAL_ERROR);
        return KCMVP_ERROR_SELF_TEST;
    }

    return module_state_transition(KCMVP_EVENT_SELFTEST_PASSED);
}

EXPORT int KCMVP_Zeroize(void)
{
    int state = module_state_get();

    if (state == KCMVP_CM_EXIT)
        return KCMVP_ERROR_INVALID_STATE;

    reset_module_data();
    if (state == KCMVP_CM_CRITICAL_ERROR)
        return KCMVP_SUCCESS;

    return module_state_transition(KCMVP_EVENT_FATAL_ERROR);
}

EXPORT int KCMVP_Shutdown(void)
{
    int state = module_state_get();
    int result;

    if (state == KCMVP_CM_EXIT)
        return KCMVP_ERROR_INVALID_STATE;

    reset_module_data();
    if (state != KCMVP_CM_LOAD && state != KCMVP_CM_CRITICAL_ERROR) {
        result = module_state_transition(KCMVP_EVENT_FATAL_ERROR);
        if (result != KCMVP_SUCCESS)
            return result;
    }

    return module_state_transition(KCMVP_EVENT_SHUTDOWN);
}

EXPORT int KCMVP_ARIA_EncKeySetup(const Byte *key, Byte *roundKeys,
                                  int keyBits)
{
    int result = authorize_algorithm(algTestedFlag.startup.aria_passed);

    if (result != KCMVP_SUCCESS)
        return result;
    if (key == NULL || roundKeys == NULL ||
        (keyBits != 128 && keyBits != 192 && keyBits != 256))
        return finish_service(KCMVP_ERROR_INVALID_PARAM);

    result = EncKeySetup(key, roundKeys, keyBits);
    return finish_service(result > 0 ? result : KCMVP_ERROR_CRYPTO);
}

EXPORT int KCMVP_ARIA_DecKeySetup(const Byte *key, Byte *roundKeys,
                                  int keyBits)
{
    int result = authorize_algorithm(algTestedFlag.startup.aria_passed);

    if (result != KCMVP_SUCCESS)
        return result;
    if (key == NULL || roundKeys == NULL ||
        (keyBits != 128 && keyBits != 192 && keyBits != 256))
        return finish_service(KCMVP_ERROR_INVALID_PARAM);

    result = DecKeySetup(key, roundKeys, keyBits);
    return finish_service(result > 0 ? result : KCMVP_ERROR_CRYPTO);
}

EXPORT int KCMVP_ARIA_Crypt(int dir, int mode, const Byte *iv,
                            const Byte *in, int inSize,
                            const Byte *key, int keyBit, Byte *out)
{
    int mode_result;
    int result = authorize_algorithm(algTestedFlag.startup.aria_passed);

    if (result != KCMVP_SUCCESS)
        return result;
    if (in == NULL || key == NULL || out == NULL || inSize <= 0 ||
        (dir != ARIA_ENCRYPT && dir != ARIA_DECRYPT) ||
        (mode < ARIA_ECB_MODE || mode > ARIA_CTR_MODE) ||
        (mode != ARIA_ECB_MODE && iv == NULL) ||
        (mode != ARIA_CTR_MODE && (inSize % 16) != 0) ||
        (keyBit != 128 && keyBit != 192 && keyBit != 256))
        return finish_service(KCMVP_ERROR_INVALID_PARAM);

    switch (mode) {
    case ARIA_ECB_MODE:
        mode_result = ARIA_ECB(dir, in, inSize, key, keyBit, out);
        break;
    case ARIA_CBC_MODE:
        mode_result = ARIA_CBC(dir, iv, in, inSize, key, keyBit, out);
        break;
    case ARIA_CTR_MODE:
        mode_result = ARIA_CTR(dir, iv, in, inSize, key, keyBit, out);
        break;
    default:
        return finish_service(KCMVP_ERROR_INVALID_PARAM);
    }

    return finish_service(mode_result == ARIA_MODE_SUCCESS ?
                          KCMVP_SUCCESS : KCMVP_ERROR_CRYPTO);
}

EXPORT int KCMVP_ARIA_Crypt_Basic(const Byte *in, int rounds,
                                  const Byte *roundKeys, Byte *out)
{
    int result = authorize_algorithm(algTestedFlag.startup.aria_passed);

    if (result != KCMVP_SUCCESS)
        return result;
    if (in == NULL || roundKeys == NULL || out == NULL ||
        (rounds != 12 && rounds != 14 && rounds != 16))
        return finish_service(KCMVP_ERROR_INVALID_PARAM);

    Crypt(in, rounds, roundKeys, out);
    return finish_service(KCMVP_SUCCESS);
}

EXPORT int KCMVP_SHA3_Hash(uint8_t *output, int outLen,
                           const uint8_t *input, int inLen,
                           int bitSize)
{
    int result = authorize_algorithm(algTestedFlag.startup.sha3_passed);

    if (result != KCMVP_SUCCESS)
        return result;
    if (output == NULL || inLen < 0 || (inLen > 0 && input == NULL))
        return finish_service(KCMVP_ERROR_INVALID_PARAM);

    result = sha3_hash(output, outLen, (uint8_t *)input, inLen,
                       bitSize, SHA3_SHAKE_NONE);
    return finish_service(result == 0 ? KCMVP_SUCCESS : KCMVP_ERROR_INVALID_PARAM);
}

EXPORT int KCMVP_HMAC_SHA3(const uint8_t *message, uint32_t mlen,
                           const uint8_t *key, uint32_t klen,
                           uint8_t *hmac, int bitSize)
{
    int result = authorize_algorithm(algTestedFlag.startup.hmac_sha3_passed);

    if (result != KCMVP_SUCCESS)
        return result;
    if (hmac == NULL || (mlen > 0 && message == NULL) ||
        (klen > 0 && key == NULL) ||
        (bitSize != 224 && bitSize != 256 &&
         bitSize != 384 && bitSize != 512))
        return finish_service(KCMVP_ERROR_INVALID_PARAM);

    HMAC_SHA3(message, mlen, key, klen, hmac, bitSize);
    return finish_service(KCMVP_SUCCESS);
}

EXPORT int KCMVP_RNG_Generate(uint8_t *output, uint32_t output_len)
{
    int result = authorize_algorithm(algTestedFlag.startup.hash_drbg_passed);

    if (result != KCMVP_SUCCESS)
        return result;
    result = hash_drbg_generate(&module_drbg, output, output_len);
    return finish_service(result);
}

EXPORT int KCMVP_RNG_Reseed(void)
{
    int result = authorize_algorithm(algTestedFlag.startup.hash_drbg_passed);

    if (result != KCMVP_SUCCESS)
        return result;
    result = hash_drbg_reseed(&module_drbg, NULL, 0);
    if (result == KCMVP_ERROR_SELF_TEST || result == KCMVP_ERROR_CRYPTO) {
        hash_drbg_uninstantiate(&module_drbg);
        reset_module_data();
        module_state_transition(KCMVP_EVENT_FATAL_ERROR);
        return result;
    }
    return finish_service(result);
}

EXPORT int KCMVP_RNG_Uninstantiate(void)
{
    int result = authorize_algorithm(algTestedFlag.startup.hash_drbg_passed);

    if (result != KCMVP_SUCCESS)
        return result;
    hash_drbg_uninstantiate(&module_drbg);
    return finish_service(KCMVP_SUCCESS);
}

EXPORT int KCMVP_ECC_GenerateKeyPair(uint8_t *public_key,
                                     uint32_t public_key_len,
                                     uint8_t *private_key,
                                     uint32_t private_key_len)
{
    unsigned int attempt;
    int result;

    if (public_key == NULL || private_key == NULL ||
        public_key_len != KCMVP_ECC_P256_PUBLIC_KEY_SIZE ||
        private_key_len != KCMVP_ECC_P256_PRIVATE_KEY_SIZE)
        return KCMVP_ERROR_INVALID_PARAM;
    if (module_state_get() == KCMVP_CM_LOAD)
        return KCMVP_ERROR_NOT_INITIALIZED;
    if (module_state_get() != KCMVP_CM_NORMAL)
        return KCMVP_ERROR_INVALID_STATE;
    if (!algTestedFlag.startup.ecc_p256_passed)
        return KCMVP_ERROR_SELF_TEST;

    for (attempt = 0; attempt < 64; attempt++) {
        result = KCMVP_RNG_Generate(private_key, private_key_len);
        if (result != KCMVP_SUCCESS)
            goto fail;
        result = ecc_p256_compute_public_key(private_key, public_key);
        if (result == KCMVP_SUCCESS)
            break;
    }
    if (attempt == 64) {
        result = KCMVP_ERROR_CRYPTO;
        goto fail;
    }

    result = module_state_transition(KCMVP_EVENT_BEGIN_COND_SELFTEST);
    if (result != KCMVP_SUCCESS)
        goto fail;
    result = ecc_p256_pairwise_test(private_key, public_key);
    if (result != KCMVP_SUCCESS) {
        secure_zero(private_key, private_key_len);
        secure_zero(public_key, public_key_len);
        reset_module_data();
        module_state_transition(KCMVP_EVENT_FATAL_ERROR);
        return KCMVP_ERROR_CONDITIONAL_TEST;
    }

    result = module_state_transition(KCMVP_EVENT_COND_SELFTEST_PASSED);
    if (result != KCMVP_SUCCESS)
        goto fail;
    return KCMVP_SUCCESS;

fail:
    secure_zero(private_key, private_key_len);
    secure_zero(public_key, public_key_len);
    return result;
}

EXPORT int KCMVP_ECC_ComputeSharedSecret(const uint8_t *private_key,
                                         uint32_t private_key_len,
                                         const uint8_t *peer_public_key,
                                         uint32_t peer_public_key_len,
                                         uint8_t *shared_secret,
                                         uint32_t shared_secret_len)
{
    int result = authorize_algorithm(algTestedFlag.startup.ecc_p256_passed);

    if (result != KCMVP_SUCCESS)
        return result;
    if (private_key == NULL || peer_public_key == NULL || shared_secret == NULL ||
        private_key_len != KCMVP_ECC_P256_PRIVATE_KEY_SIZE ||
        peer_public_key_len != KCMVP_ECC_P256_PUBLIC_KEY_SIZE ||
        shared_secret_len != KCMVP_ECC_P256_SHARED_SECRET_SIZE)
        return finish_service(KCMVP_ERROR_INVALID_PARAM);

    result = ecc_p256_shared_secret(private_key, peer_public_key, shared_secret);
    if (result != KCMVP_SUCCESS)
        secure_zero(shared_secret, shared_secret_len);
    return finish_service(result);
}

EXPORT int KCMVP_MLKEM_Keypair(uint8_t *public_key, uint32_t public_key_len,
                               uint8_t *secret_key, uint32_t secret_key_len)
{
    int result;

    if (public_key == NULL || secret_key == NULL ||
        public_key_len != KCMVP_MLKEM768_PUBLIC_KEY_SIZE ||
        secret_key_len != KCMVP_MLKEM768_SECRET_KEY_SIZE)
        return KCMVP_ERROR_INVALID_PARAM;
    if (module_state_get() == KCMVP_CM_LOAD)
        return KCMVP_ERROR_NOT_INITIALIZED;
    if (module_state_get() != KCMVP_CM_NORMAL)
        return KCMVP_ERROR_INVALID_STATE;
    if (!algTestedFlag.startup.mlkem768_passed)
        return KCMVP_ERROR_SELF_TEST;

    result = mlkem768_keypair(public_key, secret_key);
    if (result != KCMVP_SUCCESS)
        goto fail;
    result = module_state_transition(KCMVP_EVENT_BEGIN_COND_SELFTEST);
    if (result != KCMVP_SUCCESS)
        goto fail;
    result = mlkem768_pairwise_test(public_key, secret_key);
    if (result != KCMVP_SUCCESS) {
        secure_zero(public_key, public_key_len);
        secure_zero(secret_key, secret_key_len);
        reset_module_data();
        module_state_transition(KCMVP_EVENT_FATAL_ERROR);
        return KCMVP_ERROR_CONDITIONAL_TEST;
    }
    result = module_state_transition(KCMVP_EVENT_COND_SELFTEST_PASSED);
    if (result == KCMVP_SUCCESS)
        return KCMVP_SUCCESS;

fail:
    secure_zero(public_key, public_key_len);
    secure_zero(secret_key, secret_key_len);
    return result;
}

EXPORT int KCMVP_MLKEM_Encaps(uint8_t *ciphertext, uint32_t ciphertext_len,
                              uint8_t *shared_secret,
                              uint32_t shared_secret_len,
                              const uint8_t *public_key,
                              uint32_t public_key_len)
{
    int result = authorize_algorithm(algTestedFlag.startup.mlkem768_passed);

    if (result != KCMVP_SUCCESS)
        return result;
    if (ciphertext == NULL || shared_secret == NULL || public_key == NULL ||
        ciphertext_len != KCMVP_MLKEM768_CIPHERTEXT_SIZE ||
        shared_secret_len != KCMVP_MLKEM768_SHARED_SECRET_SIZE ||
        public_key_len != KCMVP_MLKEM768_PUBLIC_KEY_SIZE)
        return finish_service(KCMVP_ERROR_INVALID_PARAM);

    result = mlkem768_encaps(ciphertext, shared_secret, public_key);
    if (result != KCMVP_SUCCESS) {
        secure_zero(ciphertext, ciphertext_len);
        secure_zero(shared_secret, shared_secret_len);
    }
    return finish_service(result);
}

EXPORT int KCMVP_MLKEM_Decaps(uint8_t *shared_secret,
                              uint32_t shared_secret_len,
                              const uint8_t *ciphertext,
                              uint32_t ciphertext_len,
                              const uint8_t *secret_key,
                              uint32_t secret_key_len)
{
    int result = authorize_algorithm(algTestedFlag.startup.mlkem768_passed);

    if (result != KCMVP_SUCCESS)
        return result;
    if (shared_secret == NULL || ciphertext == NULL || secret_key == NULL ||
        shared_secret_len != KCMVP_MLKEM768_SHARED_SECRET_SIZE ||
        ciphertext_len != KCMVP_MLKEM768_CIPHERTEXT_SIZE ||
        secret_key_len != KCMVP_MLKEM768_SECRET_KEY_SIZE)
        return finish_service(KCMVP_ERROR_INVALID_PARAM);

    result = mlkem768_decaps(shared_secret, ciphertext, secret_key);
    if (result != KCMVP_SUCCESS)
        secure_zero(shared_secret, shared_secret_len);
    return finish_service(result);
}
