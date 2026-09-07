#ifndef KCMVP_ECC_H
#define KCMVP_ECC_H

#include <stdint.h>

#define KCMVP_ECC_P256_PRIVATE_KEY_SIZE 32
#define KCMVP_ECC_P256_PUBLIC_KEY_SIZE 64
#define KCMVP_ECC_P256_SHARED_SECRET_SIZE 32

int ecc_p256_compute_public_key(const uint8_t private_key[32],
                                uint8_t public_key[64]);
int ecc_p256_validate_public_key(const uint8_t public_key[64]);
int ecc_p256_shared_secret(const uint8_t private_key[32],
                           const uint8_t peer_public_key[64],
                           uint8_t shared_secret[32]);
int ecc_p256_pairwise_test(const uint8_t private_key[32],
                           const uint8_t public_key[64]);

#ifdef KCMVP_ECC_TESTING
void ecc_force_conditional_failure(int enabled);
#endif

#endif
