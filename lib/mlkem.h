#ifndef KCMVP_MLKEM_H
#define KCMVP_MLKEM_H

#include <stdint.h>

#define KCMVP_MLKEM768_PUBLIC_KEY_SIZE 1184
#define KCMVP_MLKEM768_SECRET_KEY_SIZE 2400
#define KCMVP_MLKEM768_CIPHERTEXT_SIZE 1088
#define KCMVP_MLKEM768_SHARED_SECRET_SIZE 32

int mlkem768_keypair(uint8_t *public_key, uint8_t *secret_key);
int mlkem768_encaps(uint8_t *ciphertext, uint8_t *shared_secret,
                    const uint8_t *public_key);
int mlkem768_decaps(uint8_t *shared_secret, const uint8_t *ciphertext,
                    const uint8_t *secret_key);
int mlkem768_kat(void);
int mlkem768_pairwise_test(const uint8_t *public_key,
                           const uint8_t *secret_key);

#ifdef KCMVP_MLKEM_TESTING
void mlkem_force_conditional_failure(int enabled);
#endif

#endif
