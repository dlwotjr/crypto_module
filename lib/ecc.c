#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ecc.h"
#include "../include/kcmvp.h"
#include "../third_party/micro-ecc/uECC.h"

#ifdef KCMVP_ECC_TESTING
static int force_conditional_failure;

void ecc_force_conditional_failure(int enabled)
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

static uECC_Curve p256_curve(void)
{
    /* Do not permit micro-ecc to bypass the module RNG boundary. */
    uECC_set_rng(NULL);
    return uECC_secp256r1();
}

int ecc_p256_compute_public_key(const uint8_t private_key[32],
                                uint8_t public_key[64])
{
    if (private_key == NULL || public_key == NULL)
        return KCMVP_ERROR_INVALID_PARAM;
    if (!uECC_compute_public_key(private_key, public_key, p256_curve()))
        return KCMVP_ERROR_INVALID_PARAM;
    return KCMVP_SUCCESS;
}

int ecc_p256_validate_public_key(const uint8_t public_key[64])
{
    if (public_key == NULL)
        return KCMVP_ERROR_INVALID_PARAM;
    if (!uECC_valid_public_key(public_key, p256_curve()))
        return KCMVP_ERROR_INVALID_PUBLIC_KEY;
    return KCMVP_SUCCESS;
}

int ecc_p256_shared_secret(const uint8_t private_key[32],
                           const uint8_t peer_public_key[64],
                           uint8_t shared_secret[32])
{
    int result;

    if (private_key == NULL || peer_public_key == NULL || shared_secret == NULL)
        return KCMVP_ERROR_INVALID_PARAM;

    result = ecc_p256_validate_public_key(peer_public_key);
    if (result != KCMVP_SUCCESS)
        return result;
    if (!uECC_shared_secret(peer_public_key, private_key, shared_secret,
                            p256_curve())) {
        secure_zero(shared_secret, KCMVP_ECC_P256_SHARED_SECRET_SIZE);
        return KCMVP_ERROR_CRYPTO;
    }
    return KCMVP_SUCCESS;
}

int ecc_p256_pairwise_test(const uint8_t private_key[32],
                           const uint8_t public_key[64])
{
    static const uint8_t peer_private[32] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02
    };
    static const uint8_t peer_public[64] = {
        0x7c,0xf2,0x7b,0x18,0x8d,0x03,0x4f,0x7e,
        0x8a,0x52,0x38,0x03,0x04,0xb5,0x1a,0xc3,
        0xc0,0x89,0x69,0xe2,0x77,0xf2,0x1b,0x35,
        0xa6,0x0b,0x48,0xfc,0x47,0x66,0x99,0x78,
        0x07,0x77,0x55,0x10,0xdb,0x8e,0xd0,0x40,
        0x29,0x3d,0x9a,0xc6,0x9f,0x74,0x30,0xdb,
        0xba,0x7d,0xad,0xe6,0x3c,0xe9,0x82,0x29,
        0x9e,0x04,0xb7,0x9d,0x22,0x78,0x73,0xd1
    };
    uint8_t local_secret[32];
    uint8_t peer_secret[32];
    int result = KCMVP_ERROR_CONDITIONAL_TEST;

    if (ecc_p256_shared_secret(private_key, peer_public, local_secret) !=
            KCMVP_SUCCESS ||
        ecc_p256_shared_secret(peer_private, public_key, peer_secret) !=
            KCMVP_SUCCESS)
        goto out;

    if (memcmp(local_secret, peer_secret, sizeof(local_secret)) == 0) {
#ifdef KCMVP_ECC_TESTING
        if (!force_conditional_failure)
#endif
            result = KCMVP_SUCCESS;
    }

out:
    secure_zero(local_secret, sizeof(local_secret));
    secure_zero(peer_secret, sizeof(peer_secret));
    return result;
}
