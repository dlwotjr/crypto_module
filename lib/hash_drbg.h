#ifndef KCMVP_HASH_DRBG_H
#define KCMVP_HASH_DRBG_H

#include <stddef.h>
#include <stdint.h>

#define HASH_DRBG_SEED_LENGTH 55
#define HASH_DRBG_ENTROPY_LENGTH 32
#define HASH_DRBG_NONCE_LENGTH 16
#define HASH_DRBG_MAX_REQUEST 65536
#define HASH_DRBG_RESEED_INTERVAL (UINT64_C(1) << 48)

typedef struct {
    uint8_t v[HASH_DRBG_SEED_LENGTH];
    uint8_t c[HASH_DRBG_SEED_LENGTH];
    uint64_t reseed_counter;
    int instantiated;
} HASH_DRBG_CTX;

int hash_drbg_instantiate(HASH_DRBG_CTX *ctx,
                          const uint8_t *personalization,
                          size_t personalization_len);
int hash_drbg_instantiate_seed(HASH_DRBG_CTX *ctx,
                               const uint8_t *seed_material,
                               size_t seed_material_len);
int hash_drbg_generate(HASH_DRBG_CTX *ctx, uint8_t *out, size_t len);
int hash_drbg_reseed(HASH_DRBG_CTX *ctx,
                     const uint8_t *additional_input,
                     size_t additional_input_len);
void hash_drbg_uninstantiate(HASH_DRBG_CTX *ctx);

#endif
