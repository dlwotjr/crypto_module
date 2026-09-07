#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "mlkem.h"
#include "../include/kcmvp.h"
#include "../third_party/PQClean/crypto_kem/ml-kem-768/clean/kem.h"

#ifdef KCMVP_MLKEM_TESTING
static int force_conditional_failure;

void mlkem_force_conditional_failure(int enabled)
{
    force_conditional_failure = enabled != 0;
}
#endif

static void secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;

    while (len-- > 0)
        *p++ = 0;
}

int mlkem768_keypair(uint8_t *public_key, uint8_t *secret_key)
{
    if (public_key == NULL || secret_key == NULL)
        return KCMVP_ERROR_INVALID_PARAM;
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(public_key, secret_key) != 0)
        return KCMVP_ERROR_CRYPTO;
    return KCMVP_SUCCESS;
}

int mlkem768_encaps(uint8_t *ciphertext, uint8_t *shared_secret,
                    const uint8_t *public_key)
{
    if (ciphertext == NULL || shared_secret == NULL || public_key == NULL)
        return KCMVP_ERROR_INVALID_PARAM;
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ciphertext, shared_secret,
                                              public_key) != 0)
        return KCMVP_ERROR_CRYPTO;
    return KCMVP_SUCCESS;
}

int mlkem768_decaps(uint8_t *shared_secret, const uint8_t *ciphertext,
                    const uint8_t *secret_key)
{
    if (shared_secret == NULL || ciphertext == NULL || secret_key == NULL)
        return KCMVP_ERROR_INVALID_PARAM;
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(shared_secret, ciphertext,
                                              secret_key) != 0)
        return KCMVP_ERROR_CRYPTO;
    return KCMVP_SUCCESS;
}

int mlkem768_pairwise_test(const uint8_t *public_key,
                           const uint8_t *secret_key)
{
    static const uint8_t coins[32] = {
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
    };
    uint8_t ciphertext[KCMVP_MLKEM768_CIPHERTEXT_SIZE];
    uint8_t encapsulated[KCMVP_MLKEM768_SHARED_SECRET_SIZE];
    uint8_t decapsulated[KCMVP_MLKEM768_SHARED_SECRET_SIZE];
    int result = KCMVP_ERROR_CONDITIONAL_TEST;

    if (public_key == NULL || secret_key == NULL)
        return KCMVP_ERROR_INVALID_PARAM;
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(
            ciphertext, encapsulated, public_key, coins) != 0 ||
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(
            decapsulated, ciphertext, secret_key) != 0)
        goto out;
    if (memcmp(encapsulated, decapsulated, sizeof(encapsulated)) == 0) {
#ifdef KCMVP_MLKEM_TESTING
        if (!force_conditional_failure)
#endif
            result = KCMVP_SUCCESS;
    }

out:
    secure_zero(ciphertext, sizeof(ciphertext));
    secure_zero(encapsulated, sizeof(encapsulated));
    secure_zero(decapsulated, sizeof(decapsulated));
    return result;
}

int mlkem768_kat(void)
{
    static const uint8_t key_coins[64] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
    };
    static const uint8_t encaps_coins[32] = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
        0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
        0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
        0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f
    };
    static const uint8_t expected_shared_secret[32] = {
        0x9c,0xdd,0xd0,0x89,0xff,0xe7,0x0e,0x39,
        0x96,0xe7,0x6f,0x7c,0x8d,0x06,0x74,0x6d,
        0xf3,0x4d,0x07,0xe8,0x65,0x7b,0xc0,0xfc,
        0xf2,0xbb,0x0e,0x1c,0x30,0x84,0xae,0xa1
    };
    uint8_t public_key[KCMVP_MLKEM768_PUBLIC_KEY_SIZE];
    uint8_t secret_key[KCMVP_MLKEM768_SECRET_KEY_SIZE];
    uint8_t ciphertext[KCMVP_MLKEM768_CIPHERTEXT_SIZE];
    uint8_t encapsulated[KCMVP_MLKEM768_SHARED_SECRET_SIZE];
    uint8_t decapsulated[KCMVP_MLKEM768_SHARED_SECRET_SIZE];
    int result = KCMVP_ERROR_SELF_TEST;

    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(
            public_key, secret_key, key_coins) != 0 ||
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(
            ciphertext, encapsulated, public_key, encaps_coins) != 0 ||
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(
            decapsulated, ciphertext, secret_key) != 0)
        goto out;
    if (memcmp(encapsulated, expected_shared_secret,
               sizeof(encapsulated)) == 0 &&
        memcmp(decapsulated, expected_shared_secret,
               sizeof(decapsulated)) == 0)
        result = KCMVP_SUCCESS;

out:
    secure_zero(public_key, sizeof(public_key));
    secure_zero(secret_key, sizeof(secret_key));
    secure_zero(ciphertext, sizeof(ciphertext));
    secure_zero(encapsulated, sizeof(encapsulated));
    secure_zero(decapsulated, sizeof(decapsulated));
    return result;
}
