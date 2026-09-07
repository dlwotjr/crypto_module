#include <stdio.h>
#include <string.h>

#include "integrity.h"
#include "integrity_manifest.h"
#include "sha3.h"
#include "../include/kcmvp.h"

#ifdef KCMVP_INTEGRITY_TESTING
static int force_manifest_failure;

void integrity_force_manifest_failure(int enabled)
{
    force_manifest_failure = enabled != 0;
}
#endif

static void secure_zero(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;

    while (len-- > 0)
        *p++ = 0;
}

static int constant_time_equal(const uint8_t *left, const uint8_t *right,
                               size_t len)
{
    uint8_t difference = 0;
    size_t i;

    for (i = 0; i < len; i++)
        difference |= left[i] ^ right[i];
    return difference == 0;
}

static int hash_file(const char *path, uint8_t digest[KCMVP_INTEGRITY_DIGEST_SIZE])
{
    uint8_t buffer[4096];
    FILE *file;
    size_t bytes_read;
    int result = KCMVP_ERROR_SELF_TEST;
    SHA3_CTX sha3_ctx;

    file = fopen(path, "rb");
    if (file == NULL)
        return KCMVP_ERROR_SELF_TEST;

    if (sha3_init(&sha3_ctx, 256, SHA3_SHAKE_NONE) != 0)
        goto out;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (sha3_update(&sha3_ctx, buffer, (int)bytes_read) != 0)
            goto out;
    }
    if (ferror(file))
        goto out;
    if (sha3_final(&sha3_ctx, digest, KCMVP_INTEGRITY_DIGEST_SIZE) != 0)
        goto out;

    result = KCMVP_SUCCESS;

out:
    fclose(file);
    secure_zero(&sha3_ctx, sizeof(sha3_ctx));
    secure_zero(buffer, sizeof(buffer));
    return result;
}

int integrity_verify(void)
{
    uint8_t actual[KCMVP_INTEGRITY_DIGEST_SIZE];
    uint8_t expected[KCMVP_INTEGRITY_DIGEST_SIZE];
    size_t i;
    int result = KCMVP_ERROR_SELF_TEST;

    for (i = 0; i < KCMVP_INTEGRITY_FILE_COUNT; i++) {
        memcpy(expected, kcmvp_integrity_manifest[i].digest, sizeof(expected));
#ifdef KCMVP_INTEGRITY_TESTING
        if (force_manifest_failure && i == 0)
            expected[0] ^= 0x01;
#endif
        if (hash_file(kcmvp_integrity_manifest[i].path, actual) != KCMVP_SUCCESS ||
            !constant_time_equal(actual, expected, sizeof(actual)))
            goto out;
    }

    result = KCMVP_SUCCESS;

out:
    secure_zero(actual, sizeof(actual));
    secure_zero(expected, sizeof(expected));
    return result;
}
