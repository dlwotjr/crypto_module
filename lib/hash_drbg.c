#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "entropy.h"
#include "hash_drbg.h"
#include "sha3.h"
#include "../include/kcmvp.h"

#define SHA3_256_DIGEST_LENGTH 32

static void secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;

    while (len-- > 0)
        *p++ = 0;
}

static void add_bytes(uint8_t *value, const uint8_t *addend, size_t addend_len)
{
    size_t value_index = HASH_DRBG_SEED_LENGTH;
    size_t addend_index = addend_len;
    unsigned int carry = 0;

    while (value_index > 0) {
        unsigned int sum = value[--value_index] + carry;

        if (addend_index > 0)
            sum += addend[--addend_index];
        value[value_index] = (uint8_t)sum;
        carry = sum >> 8;
    }
}

static void increment(uint8_t value[HASH_DRBG_SEED_LENGTH])
{
    size_t i = HASH_DRBG_SEED_LENGTH;

    while (i > 0) {
        i--;
        value[i]++;
        if (value[i] != 0)
            break;
    }
}

static int hash_df(const uint8_t *input, size_t input_len,
                   uint8_t output[HASH_DRBG_SEED_LENGTH])
{
    uint8_t digest[SHA3_256_DIGEST_LENGTH];
    uint8_t counter = 1;
    uint8_t bit_length[4] = { 0x00, 0x00, 0x01, 0xb8 };
    size_t produced = 0;
    SHA3_CTX sha3_ctx;

    while (produced < HASH_DRBG_SEED_LENGTH) {
        size_t copy_len;

        if (sha3_init(&sha3_ctx, 256, SHA3_SHAKE_NONE) != 0 ||
            sha3_update(&sha3_ctx, &counter, 1) != 0 ||
            sha3_update(&sha3_ctx, bit_length, sizeof(bit_length)) != 0 ||
            sha3_update(&sha3_ctx, input, (int)input_len) != 0 ||
            sha3_final(&sha3_ctx, digest, sizeof(digest)) != 0) {
            secure_zero(&sha3_ctx, sizeof(sha3_ctx));
            secure_zero(digest, sizeof(digest));
            return KCMVP_ERROR_CRYPTO;
        }

        copy_len = HASH_DRBG_SEED_LENGTH - produced;
        if (copy_len > sizeof(digest))
            copy_len = sizeof(digest);
        memcpy(output + produced, digest, copy_len);
        produced += copy_len;
        counter++;
    }

    secure_zero(digest, sizeof(digest));
    return KCMVP_SUCCESS;
}

static int hash_with_prefix(uint8_t prefix,
                            const uint8_t *input, size_t input_len,
                            uint8_t output[SHA3_256_DIGEST_LENGTH])
{
    SHA3_CTX sha3_ctx;

    if (sha3_init(&sha3_ctx, 256, SHA3_SHAKE_NONE) != 0 ||
        sha3_update(&sha3_ctx, &prefix, 1) != 0 ||
        sha3_update(&sha3_ctx, input, (int)input_len) != 0 ||
        sha3_final(&sha3_ctx, output, SHA3_256_DIGEST_LENGTH) != 0) {
        secure_zero(&sha3_ctx, sizeof(sha3_ctx));
        return KCMVP_ERROR_CRYPTO;
    }
    return KCMVP_SUCCESS;
}

static int hashgen(const uint8_t v[HASH_DRBG_SEED_LENGTH],
                   uint8_t *output, size_t output_len)
{
    uint8_t data[HASH_DRBG_SEED_LENGTH];
    uint8_t digest[SHA3_256_DIGEST_LENGTH];
    size_t produced = 0;

    memcpy(data, v, sizeof(data));
    while (produced < output_len) {
        size_t copy_len = output_len - produced;

        if (sha3_hash(digest, sizeof(digest), data, sizeof(data),
                      256, SHA3_SHAKE_NONE) != 0) {
            secure_zero(data, sizeof(data));
            secure_zero(digest, sizeof(digest));
            return KCMVP_ERROR_CRYPTO;
        }
        if (copy_len > sizeof(digest))
            copy_len = sizeof(digest);
        memcpy(output + produced, digest, copy_len);
        produced += copy_len;
        increment(data);
    }

    secure_zero(data, sizeof(data));
    secure_zero(digest, sizeof(digest));
    return KCMVP_SUCCESS;
}

int hash_drbg_instantiate_seed(HASH_DRBG_CTX *ctx,
                               const uint8_t *seed_material,
                               size_t seed_material_len)
{
    uint8_t c_input[1 + HASH_DRBG_SEED_LENGTH];
    int result;

    if (ctx == NULL || seed_material == NULL || seed_material_len == 0)
        return KCMVP_ERROR_INVALID_PARAM;

    hash_drbg_uninstantiate(ctx);
    result = hash_df(seed_material, seed_material_len, ctx->v);
    if (result != KCMVP_SUCCESS)
        goto fail;

    c_input[0] = 0x00;
    memcpy(c_input + 1, ctx->v, sizeof(ctx->v));
    result = hash_df(c_input, sizeof(c_input), ctx->c);
    if (result != KCMVP_SUCCESS)
        goto fail;

    ctx->reseed_counter = 1;
    ctx->instantiated = 1;
    secure_zero(c_input, sizeof(c_input));
    return KCMVP_SUCCESS;

fail:
    secure_zero(c_input, sizeof(c_input));
    hash_drbg_uninstantiate(ctx);
    return result;
}

int hash_drbg_instantiate(HASH_DRBG_CTX *ctx,
                          const uint8_t *personalization,
                          size_t personalization_len)
{
    uint8_t seed_material[HASH_DRBG_ENTROPY_LENGTH +
                          HASH_DRBG_NONCE_LENGTH + 64];
    size_t base_len = HASH_DRBG_ENTROPY_LENGTH + HASH_DRBG_NONCE_LENGTH;
    int result;

    if (ctx == NULL || personalization_len > 64 ||
        (personalization_len > 0 && personalization == NULL))
        return KCMVP_ERROR_INVALID_PARAM;

    result = entropy_get(seed_material, base_len);
    if (result != KCMVP_SUCCESS)
        goto out;
    if (personalization_len > 0)
        memcpy(seed_material + base_len, personalization, personalization_len);

    result = hash_drbg_instantiate_seed(ctx, seed_material,
                                        base_len + personalization_len);

out:
    secure_zero(seed_material, sizeof(seed_material));
    return result;
}

int hash_drbg_generate(HASH_DRBG_CTX *ctx, uint8_t *out, size_t len)
{
    uint8_t h[SHA3_256_DIGEST_LENGTH];
    uint8_t counter[8];
    uint64_t value;
    size_t i;
    int result;

    if (ctx == NULL || !ctx->instantiated)
        return KCMVP_ERROR_NOT_INITIALIZED;
    if (out == NULL || len == 0 || len > HASH_DRBG_MAX_REQUEST)
        return KCMVP_ERROR_INVALID_PARAM;
    if (ctx->reseed_counter > HASH_DRBG_RESEED_INTERVAL)
        return KCMVP_ERROR_RESEED_REQUIRED;

    result = hashgen(ctx->v, out, len);
    if (result != KCMVP_SUCCESS)
        return result;

    result = hash_with_prefix(0x03, ctx->v, sizeof(ctx->v), h);
    if (result != KCMVP_SUCCESS) {
        secure_zero(out, len);
        return result;
    }
    add_bytes(ctx->v, h, sizeof(h));
    add_bytes(ctx->v, ctx->c, sizeof(ctx->c));

    value = ctx->reseed_counter;
    for (i = sizeof(counter); i > 0; i--) {
        counter[i - 1] = (uint8_t)value;
        value >>= 8;
    }
    add_bytes(ctx->v, counter, sizeof(counter));
    ctx->reseed_counter++;

    secure_zero(h, sizeof(h));
    secure_zero(counter, sizeof(counter));
    return KCMVP_SUCCESS;
}

int hash_drbg_reseed(HASH_DRBG_CTX *ctx,
                     const uint8_t *additional_input,
                     size_t additional_input_len)
{
    uint8_t seed_material[1 + HASH_DRBG_SEED_LENGTH +
                          HASH_DRBG_ENTROPY_LENGTH + 64];
    size_t offset = 0;
    int result;

    if (ctx == NULL || !ctx->instantiated)
        return KCMVP_ERROR_NOT_INITIALIZED;
    if (additional_input_len > 64 ||
        (additional_input_len > 0 && additional_input == NULL))
        return KCMVP_ERROR_INVALID_PARAM;

    seed_material[offset++] = 0x01;
    memcpy(seed_material + offset, ctx->v, sizeof(ctx->v));
    offset += sizeof(ctx->v);
    result = entropy_get(seed_material + offset, HASH_DRBG_ENTROPY_LENGTH);
    if (result != KCMVP_SUCCESS)
        goto out;
    offset += HASH_DRBG_ENTROPY_LENGTH;
    if (additional_input_len > 0) {
        memcpy(seed_material + offset, additional_input, additional_input_len);
        offset += additional_input_len;
    }

    result = hash_drbg_instantiate_seed(ctx, seed_material, offset);

out:
    secure_zero(seed_material, sizeof(seed_material));
    return result;
}

void hash_drbg_uninstantiate(HASH_DRBG_CTX *ctx)
{
    if (ctx != NULL)
        secure_zero(ctx, sizeof(*ctx));
}
