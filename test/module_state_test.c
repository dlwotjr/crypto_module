#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/kcmvp.h"
#include "../lib/ecc.h"
#include "../lib/entropy.h"
#include "../lib/hash_drbg.h"
#include "../lib/integrity.h"
#include "../lib/mlkem.h"
#include "../lib/selftest.h"
#include "../lib/sha3.h"

static int failures;

static int passing_entropy(uint8_t *out, size_t len, void *context)
{
    size_t i;

    (void)context;
    for (i = 0; i < len; i++)
        out[i] = (uint8_t)(i % 251);
    return KCMVP_SUCCESS;
}

static int repeated_entropy(uint8_t *out, size_t len, void *context)
{
    (void)context;
    memset(out, 0x55, len);
    return KCMVP_SUCCESS;
}

static int biased_entropy(uint8_t *out, size_t len, void *context)
{
    size_t i;

    (void)context;
    for (i = 0; i < len; i++) {
        size_t window_offset = i % KCMVP_ENTROPY_APT_WINDOW;

        out[i] = (window_offset % 4 == 0) ? 0xaa :
                 (uint8_t)(window_offset + 1);
    }
    return KCMVP_SUCCESS;
}

static int failing_entropy(uint8_t *out, size_t len, void *context)
{
    (void)out;
    (void)len;
    (void)context;
    return KCMVP_ERROR_SELF_TEST;
}

typedef struct {
    unsigned int calls;
} FAILING_RESEED_CONTEXT;

static int reseed_failing_entropy(uint8_t *out, size_t len, void *context)
{
    FAILING_RESEED_CONTEXT *state = (FAILING_RESEED_CONTEXT *)context;
    size_t i;

    state->calls++;
    if (state->calls >= 3)
        return KCMVP_ERROR_SELF_TEST;
    for (i = 0; i < len; i++)
        out[i] = (uint8_t)((i + state->calls * 17) % 251);
    return KCMVP_SUCCESS;
}

static void expect(int condition, const char *name)
{
    if (condition) {
        printf("PASS: %s\n", name);
    } else {
        printf("FAIL: %s\n", name);
        failures++;
    }
}

static int is_all_zero(const uint8_t *data, size_t len)
{
    uint8_t value = 0;
    size_t i;

    for (i = 0; i < len; i++)
        value |= data[i];
    return value == 0;
}

static int entropy_failure_child(KCMVP_ENTROPY_PROVIDER provider,
                                 const uint8_t *message, size_t message_len)
{
    uint8_t output[32];
    int result;

    entropy_set_test_provider(provider, NULL);
    result = KCMVP_Initialize();
    if (result != KCMVP_ERROR_SELF_TEST ||
        KCMVP_GetState() != KCMVP_CM_CRITICAL_ERROR ||
        KCMVP_SHA3_Hash(output, sizeof(output), message, (int)message_len, 256) !=
            KCMVP_ERROR_INVALID_STATE)
        return 1;
    return 0;
}

int main(void)
{
    static const uint8_t abc[3] = { 0x61, 0x62, 0x63 };
    static const uint8_t expected[32] = {
        0x3a,0x98,0x5d,0xa7,0x4f,0xe2,0x25,0xb2,
        0x04,0x5c,0x17,0x2d,0x6b,0xd3,0x90,0xbd,
        0x85,0x5f,0x08,0x6e,0x3e,0x9d,0x52,0x5b,
        0x46,0xbf,0xe2,0x45,0x11,0x43,0x15,0x32
    };
    static const uint8_t hmac_key[20] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b
    };
    static const uint8_t hmac_message[8] = {
        0x48,0x69,0x20,0x54,0x68,0x65,0x72,0x65
    };
    static const uint8_t hmac_expected[28] = {
        0x3b,0x16,0x54,0x6b,0xbc,0x7b,0xe2,0x70,
        0x6a,0x03,0x1d,0xca,0xfd,0x56,0x37,0x3d,
        0x98,0x84,0x36,0x76,0x41,0xd8,0xc5,0x9a,
        0xf3,0xc8,0x60,0xf7
    };
    static const uint8_t aria_input[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    static const uint8_t aria_key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t aria_expected[16] = {
        0xd7,0x18,0xfb,0xd6,0xab,0x64,0x4c,0x73,
        0x9d,0xa9,0x5f,0x3b,0xe6,0x45,0x17,0x78
    };
    static const uint8_t mode_key[16] = { 0 };
    static const uint8_t cbc_iv[16] = { 0 };
    static const uint8_t cbc_input[16] = { 0x80 };
    static const uint8_t cbc_expected[16] = {
        0x92,0xe5,0x1e,0x73,0x7d,0xab,0xb6,0xbf,
        0xd0,0xea,0xbc,0x8d,0x32,0x22,0x4f,0x77
    };
    static const uint8_t ctr_iv[16] = { 0x80 };
    static const uint8_t ctr_input[23] = { 0 };
    uint8_t output[32] = { 0 };
    uint8_t independent_output[32] = { 0 };
    uint8_t hmac[32] = { 0 };
    uint8_t aria_output[16] = { 0 };
    uint8_t mode_output[23] = { 0 };
    uint8_t mode_plaintext[23] = { 0 };
    uint8_t random_output[64] = { 0 };
    uint8_t random_output_after_reseed[64] = { 0 };
    uint8_t private_a[32] = { 0 };
    uint8_t private_b[32] = { 0 };
    uint8_t public_a[64] = { 0 };
    uint8_t public_b[64] = { 0 };
    uint8_t shared_a[32] = { 0 };
    uint8_t shared_b[32] = { 0 };
    uint8_t invalid_public[64] = { 0 };
    uint8_t mlkem_public[KCMVP_MLKEM768_PUBLIC_KEY_BYTES] = { 0 };
    uint8_t mlkem_secret[KCMVP_MLKEM768_SECRET_KEY_BYTES] = { 0 };
    uint8_t mlkem_ciphertext[KCMVP_MLKEM768_CIPHERTEXT_BYTES] = { 0 };
    uint8_t mlkem_shared_a[KCMVP_MLKEM768_SHARED_SECRET_BYTES] = { 0 };
    uint8_t mlkem_shared_b[KCMVP_MLKEM768_SHARED_SECRET_BYTES] = { 0 };
    KCMVP_MODULE_STATUS status;
    int result;
    int child_status;
    pid_t child;
    SHA3_CTX sha3_a;
    SHA3_CTX sha3_b;

    expect(sha3_init(&sha3_a, 256, SHA3_SHAKE_NONE) == 0 &&
           sha3_update(&sha3_a, abc, 1) == 0 &&
           sha3_init(&sha3_b, 256, SHA3_SHAKE_NONE) == 0 &&
           sha3_update(&sha3_b, abc, sizeof(abc)) == 0 &&
           sha3_update(&sha3_a, abc + 1, sizeof(abc) - 1) == 0 &&
           sha3_final(&sha3_a, output, sizeof(output)) == 0 &&
           sha3_final(&sha3_b, independent_output,
                      sizeof(independent_output)) == 0 &&
           memcmp(output, expected, sizeof(expected)) == 0 &&
           memcmp(independent_output, expected, sizeof(expected)) == 0,
           "caller-owned SHA3 contexts operate independently");
    expect(sha3_init(NULL, 256, SHA3_SHAKE_NONE) != 0 &&
           sha3_init(&sha3_a, 123, SHA3_SHAKE_NONE) != 0 &&
           sha3_init(&sha3_a, 256, 7) != 0 &&
           sha3_init(&sha3_a, 256, SHA3_SHAKE_NONE) == 0 &&
           sha3_update(&sha3_a, NULL, 1) != 0 &&
           sha3_update(&sha3_a, abc, -1) != 0 &&
           sha3_final(&sha3_a, NULL, sizeof(output)) != 0 &&
           sha3_final(&sha3_a, output, sizeof(output) - 1) != 0 &&
           sha3_final(&sha3_a, output, sizeof(output)) == 0 &&
           sha3_update(&sha3_a, abc, sizeof(abc)) != 0,
           "SHA3 context API rejects invalid input and finalized reuse");

    entropy_set_test_provider(passing_entropy, NULL);
    expect(entropy_startup_health_test() == KCMVP_SUCCESS,
           "normal entropy passes startup health tests");
    entropy_clear_test_provider();

    child = fork();
    if (child == 0)
        _exit(entropy_failure_child(repeated_entropy, abc, sizeof(abc)));
    expect(child > 0 && waitpid(child, &child_status, 0) == child &&
           WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0,
           "repetition count failure blocks initialization and services");

    child = fork();
    if (child == 0)
        _exit(entropy_failure_child(biased_entropy, abc, sizeof(abc)));
    expect(child > 0 && waitpid(child, &child_status, 0) == child &&
           WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0,
           "adaptive proportion failure blocks initialization and services");

    child = fork();
    if (child == 0)
        _exit(entropy_failure_child(failing_entropy, abc, sizeof(abc)));
    expect(child > 0 && waitpid(child, &child_status, 0) == child &&
           WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0,
           "entropy provider failure blocks initialization and services");

    expect(integrity_verify() == KCMVP_SUCCESS,
           "normal integrity manifest passes");

    child = fork();
    if (child == 0) {
        integrity_force_manifest_failure(1);
        result = KCMVP_Initialize();
        if (result != KCMVP_ERROR_SELF_TEST ||
            KCMVP_GetState() != KCMVP_CM_CRITICAL_ERROR ||
            KCMVP_SHA3_Hash(output, sizeof(output), abc, sizeof(abc), 256) !=
                KCMVP_ERROR_INVALID_STATE)
            _exit(1);
        _exit(0);
    }
    expect(child > 0 && waitpid(child, &child_status, 0) == child &&
           WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0,
           "corrupt integrity manifest blocks initialization and services");

    child = fork();
    if (child == 0) {
        selftest_force_failure(KCMVP_SELFTEST_FORCE_ARIA);
        result = KCMVP_Initialize();
        if (result != KCMVP_ERROR_SELF_TEST ||
            KCMVP_GetState() != KCMVP_CM_CRITICAL_ERROR ||
            KCMVP_SHA3_Hash(output, sizeof(output), abc, sizeof(abc), 256) !=
                KCMVP_ERROR_INVALID_STATE)
            _exit(1);
        _exit(0);
    }
    expect(child > 0 && waitpid(child, &child_status, 0) == child &&
           WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0,
           "forced KAT failure enters CRITICAL_ERROR and blocks services");

    child = fork();
    if (child == 0) {
        entropy_set_test_provider(passing_entropy, NULL);
        selftest_force_failure(KCMVP_SELFTEST_FORCE_HASH_DRBG);
        result = KCMVP_Initialize();
        if (result != KCMVP_ERROR_SELF_TEST ||
            KCMVP_GetState() != KCMVP_CM_CRITICAL_ERROR ||
            KCMVP_RNG_Generate(random_output, sizeof(random_output)) !=
                KCMVP_ERROR_INVALID_STATE)
            _exit(1);
        _exit(0);
    }
    expect(child > 0 && waitpid(child, &child_status, 0) == child &&
           WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0,
           "forced DRBG KAT failure blocks initialization and RNG");

    child = fork();
    if (child == 0) {
        entropy_set_test_provider(passing_entropy, NULL);
        selftest_force_failure(KCMVP_SELFTEST_FORCE_ECC_P256);
        result = KCMVP_Initialize();
        if (result != KCMVP_ERROR_SELF_TEST ||
            KCMVP_GetState() != KCMVP_CM_CRITICAL_ERROR ||
            KCMVP_ECC_GenerateKeyPair(public_a, sizeof(public_a),
                                      private_a, sizeof(private_a)) !=
                KCMVP_ERROR_INVALID_STATE)
            _exit(1);
        _exit(0);
    }
    expect(child > 0 && waitpid(child, &child_status, 0) == child &&
           WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0,
           "forced ECC KAT failure blocks initialization and ECC");

    child = fork();
    if (child == 0) {
        entropy_set_test_provider(passing_entropy, NULL);
        selftest_force_failure(KCMVP_SELFTEST_FORCE_MLKEM768);
        result = KCMVP_Initialize();
        if (result != KCMVP_ERROR_SELF_TEST ||
            KCMVP_GetState() != KCMVP_CM_CRITICAL_ERROR ||
            KCMVP_MLKEM_Keypair(mlkem_public, sizeof(mlkem_public),
                                mlkem_secret, sizeof(mlkem_secret)) !=
                KCMVP_ERROR_INVALID_STATE)
            _exit(1);
        _exit(0);
    }
    expect(child > 0 && waitpid(child, &child_status, 0) == child &&
           WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0,
           "forced ML-KEM KAT failure blocks initialization and ML-KEM");

    child = fork();
    if (child == 0) {
        entropy_set_test_provider(passing_entropy, NULL);
        if (KCMVP_Initialize() != KCMVP_SUCCESS)
            _exit(1);
        ecc_force_conditional_failure(1);
        result = KCMVP_ECC_GenerateKeyPair(public_a, sizeof(public_a),
                                           private_a, sizeof(private_a));
        if (result != KCMVP_ERROR_CONDITIONAL_TEST ||
            KCMVP_GetState() != KCMVP_CM_CRITICAL_ERROR ||
            !is_all_zero(public_a, sizeof(public_a)) ||
            !is_all_zero(private_a, sizeof(private_a)) ||
            KCMVP_ECC_ComputeSharedSecret(private_b, sizeof(private_b),
                                          public_b, sizeof(public_b),
                                          shared_b, sizeof(shared_b)) !=
                KCMVP_ERROR_INVALID_STATE)
            _exit(1);
        _exit(0);
    }
    expect(child > 0 && waitpid(child, &child_status, 0) == child &&
           WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0,
           "ECC conditional-test failure zeroizes keys and locks module");

    child = fork();
    if (child == 0) {
        entropy_set_test_provider(passing_entropy, NULL);
        if (KCMVP_Initialize() != KCMVP_SUCCESS)
            _exit(1);
        mlkem_force_conditional_failure(1);
        result = KCMVP_MLKEM_Keypair(mlkem_public, sizeof(mlkem_public),
                                     mlkem_secret, sizeof(mlkem_secret));
        if (result != KCMVP_ERROR_CONDITIONAL_TEST ||
            KCMVP_GetState() != KCMVP_CM_CRITICAL_ERROR ||
            !is_all_zero(mlkem_public, sizeof(mlkem_public)) ||
            !is_all_zero(mlkem_secret, sizeof(mlkem_secret)) ||
            KCMVP_MLKEM_Encaps(mlkem_ciphertext,
                               sizeof(mlkem_ciphertext), mlkem_shared_a,
                               sizeof(mlkem_shared_a), mlkem_public,
                               sizeof(mlkem_public)) !=
                KCMVP_ERROR_INVALID_STATE)
            _exit(1);
        _exit(0);
    }
    expect(child > 0 && waitpid(child, &child_status, 0) == child &&
           WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0,
           "ML-KEM conditional-test failure zeroizes keys and locks module");

    child = fork();
    if (child == 0) {
        FAILING_RESEED_CONTEXT entropy_context = { 0 };

        entropy_set_test_provider(reseed_failing_entropy, &entropy_context);
        if (KCMVP_Initialize() != KCMVP_SUCCESS ||
            KCMVP_RNG_Reseed() != KCMVP_ERROR_SELF_TEST ||
            KCMVP_GetState() != KCMVP_CM_CRITICAL_ERROR ||
            KCMVP_RNG_Generate(random_output, sizeof(random_output)) !=
                KCMVP_ERROR_INVALID_STATE)
            _exit(1);
        _exit(0);
    }
    expect(child > 0 && waitpid(child, &child_status, 0) == child &&
           WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0,
           "forced reseed entropy failure enters CRITICAL_ERROR");

    result = KCMVP_SHA3_Hash(output, sizeof(output), abc, sizeof(abc), 256);
    expect(result == KCMVP_ERROR_NOT_INITIALIZED,
           "SHA3 call before initialization fails");
    expect(KCMVP_HMAC_SHA3(abc, sizeof(abc), abc, sizeof(abc), hmac, 256) ==
           KCMVP_ERROR_NOT_INITIALIZED,
           "HMAC call before initialization fails");
    expect(KCMVP_ARIA_Crypt(ARIA_ENCRYPT, ARIA_ECB_MODE, NULL,
                            aria_input, sizeof(aria_input), aria_key, 128,
                            aria_output) == KCMVP_ERROR_NOT_INITIALIZED,
           "ARIA call before initialization fails");
    expect(KCMVP_ARIA_Crypt(ARIA_DECRYPT, ARIA_CBC_MODE, cbc_iv,
                            cbc_expected, sizeof(cbc_expected), mode_key, 128,
                            mode_output) == KCMVP_ERROR_NOT_INITIALIZED,
           "ARIA CBC decrypt before initialization fails");
    expect(KCMVP_ARIA_Crypt(ARIA_DECRYPT, ARIA_CTR_MODE, ctr_iv,
                            ctr_input, sizeof(ctr_input), mode_key, 128,
                            mode_output) == KCMVP_ERROR_NOT_INITIALIZED,
           "ARIA CTR decrypt before initialization fails");
    expect(KCMVP_RNG_Generate(random_output, sizeof(random_output)) ==
           KCMVP_ERROR_NOT_INITIALIZED,
           "RNG call before initialization fails");
    expect(KCMVP_ECC_GenerateKeyPair(public_a, sizeof(public_a),
                                     private_a, sizeof(private_a)) ==
           KCMVP_ERROR_NOT_INITIALIZED,
           "ECC key generation before initialization fails");
    expect(KCMVP_ECC_ComputeSharedSecret(private_a, sizeof(private_a),
                                         public_b, sizeof(public_b),
                                         shared_a, sizeof(shared_a)) ==
           KCMVP_ERROR_NOT_INITIALIZED,
           "ECDH before initialization fails");
    expect(KCMVP_MLKEM_Keypair(mlkem_public, sizeof(mlkem_public),
                               mlkem_secret, sizeof(mlkem_secret)) ==
               KCMVP_ERROR_NOT_INITIALIZED,
           "ML-KEM key generation before initialization fails");

    expect(KCMVP_Initialize() == KCMVP_SUCCESS,
           "initialization succeeds");
    expect(KCMVP_GetStatus(&status) == KCMVP_SUCCESS &&
           status.state == KCMVP_CM_NORMAL && status.operational,
           "initialization enters NORMAL state");

    expect(KCMVP_SHA3_Hash(output, sizeof(output), abc, sizeof(abc), 256) ==
           KCMVP_SUCCESS &&
           KCMVP_SHA3_Hash(independent_output, sizeof(independent_output),
                           abc, sizeof(abc), 256) == KCMVP_SUCCESS &&
           memcmp(output, expected, sizeof(expected)) == 0 &&
           memcmp(independent_output, expected, sizeof(expected)) == 0,
           "repeated independent SHA3 service calls produce the KAT result");
    expect(KCMVP_SHA3_Hash(NULL, sizeof(output), abc, sizeof(abc), 256) ==
               KCMVP_ERROR_INVALID_PARAM &&
           KCMVP_SHA3_Hash(output, sizeof(output), NULL, 1, 256) ==
               KCMVP_ERROR_INVALID_PARAM &&
           KCMVP_SHA3_Hash(output, sizeof(output) - 1, abc, sizeof(abc), 256) ==
               KCMVP_ERROR_INVALID_PARAM,
           "SHA3 service rejects invalid input and output parameters");
    expect(KCMVP_HMAC_SHA3(hmac_message, sizeof(hmac_message),
                           hmac_key, sizeof(hmac_key), hmac, 224) ==
           KCMVP_SUCCESS &&
           memcmp(hmac, hmac_expected, sizeof(hmac_expected)) == 0,
           "successful HMAC KAT enables HMAC service");
    expect(KCMVP_ARIA_Crypt(ARIA_ENCRYPT, ARIA_ECB_MODE, NULL,
                            aria_input, sizeof(aria_input), aria_key, 128,
                            aria_output) == KCMVP_SUCCESS &&
           memcmp(aria_output, aria_expected, sizeof(aria_expected)) == 0,
           "successful ARIA KAT enables ARIA service");
    expect(KCMVP_ARIA_Crypt(ARIA_ENCRYPT, ARIA_CBC_MODE, cbc_iv,
                            cbc_input, sizeof(cbc_input), mode_key, 128,
                            mode_output) == KCMVP_SUCCESS &&
           memcmp(mode_output, cbc_expected, sizeof(cbc_expected)) == 0 &&
           KCMVP_ARIA_Crypt(ARIA_DECRYPT, ARIA_CBC_MODE, cbc_iv,
                            mode_output, sizeof(cbc_input), mode_key, 128,
                            mode_plaintext) == KCMVP_SUCCESS &&
           memcmp(mode_plaintext, cbc_input, sizeof(cbc_input)) == 0,
           "ARIA CBC encrypt and decrypt match the course vector");
    memset(mode_output, 0, sizeof(mode_output));
    memset(mode_plaintext, 0xff, sizeof(mode_plaintext));
    expect(KCMVP_ARIA_Crypt(ARIA_ENCRYPT, ARIA_CTR_MODE, ctr_iv,
                            ctr_input, sizeof(ctr_input), mode_key, 128,
                            mode_output) == KCMVP_SUCCESS &&
           memcmp(mode_output, cbc_expected, sizeof(cbc_expected)) == 0 &&
           KCMVP_ARIA_Crypt(ARIA_DECRYPT, ARIA_CTR_MODE, ctr_iv,
                            mode_output, sizeof(mode_output), mode_key, 128,
                            mode_plaintext) == KCMVP_SUCCESS &&
           memcmp(mode_plaintext, ctr_input, sizeof(ctr_input)) == 0,
           "ARIA CTR encrypt and decrypt support a trailing partial block");
    expect(KCMVP_ARIA_Crypt(ARIA_ENCRYPT, ARIA_CBC_MODE, cbc_iv,
                            cbc_input, 15, mode_key, 128, mode_output) ==
               KCMVP_ERROR_INVALID_PARAM,
           "ARIA CBC rejects non-block-multiple input");
    expect(KCMVP_ARIA_Crypt(ARIA_ENCRYPT, ARIA_CBC_MODE, cbc_iv,
                            NULL, sizeof(cbc_input), mode_key, 128,
                            mode_output) == KCMVP_ERROR_INVALID_PARAM &&
           KCMVP_ARIA_Crypt(ARIA_ENCRYPT, ARIA_CBC_MODE, NULL,
                            cbc_input, sizeof(cbc_input), mode_key, 128,
                            mode_output) == KCMVP_ERROR_INVALID_PARAM &&
           KCMVP_ARIA_Crypt(ARIA_ENCRYPT, ARIA_CBC_MODE, cbc_iv,
                            cbc_input, sizeof(cbc_input), NULL, 128,
                            mode_output) == KCMVP_ERROR_INVALID_PARAM &&
           KCMVP_ARIA_Crypt(ARIA_ENCRYPT, ARIA_CBC_MODE, cbc_iv,
                            cbc_input, sizeof(cbc_input), mode_key, 128,
                            NULL) == KCMVP_ERROR_INVALID_PARAM,
           "ARIA modes reject null input, IV, key, and output pointers");
    expect(KCMVP_ARIA_Crypt(7, ARIA_CBC_MODE, cbc_iv,
                            cbc_input, sizeof(cbc_input), mode_key, 128,
                            mode_output) == KCMVP_ERROR_INVALID_PARAM &&
           KCMVP_ARIA_Crypt(ARIA_ENCRYPT, ARIA_CBC_MODE, cbc_iv,
                            cbc_input, sizeof(cbc_input), mode_key, 64,
                            mode_output) == KCMVP_ERROR_INVALID_PARAM &&
           KCMVP_ARIA_Crypt(ARIA_ENCRYPT, ARIA_CBC_MODE, cbc_iv,
                            cbc_input, 0, mode_key, 128, mode_output) ==
               KCMVP_ERROR_INVALID_PARAM,
           "ARIA modes reject invalid direction, key size, and length");
    expect(KCMVP_RNG_Generate(random_output, sizeof(random_output)) ==
           KCMVP_SUCCESS,
           "successful DRBG KAT enables RNG generation");
    expect(KCMVP_RNG_Generate(random_output, HASH_DRBG_MAX_REQUEST + 1) ==
           KCMVP_ERROR_INVALID_PARAM,
           "RNG request size limit is enforced");
    expect(KCMVP_RNG_Reseed() == KCMVP_SUCCESS &&
           KCMVP_RNG_Generate(random_output_after_reseed,
                              sizeof(random_output_after_reseed)) ==
               KCMVP_SUCCESS &&
           memcmp(random_output, random_output_after_reseed,
                  sizeof(random_output)) != 0,
           "RNG reseed succeeds and refreshes output");
    expect(KCMVP_ECC_GenerateKeyPair(public_a, sizeof(public_a),
                                     private_a, sizeof(private_a)) ==
               KCMVP_SUCCESS &&
           KCMVP_ECC_GenerateKeyPair(public_b, sizeof(public_b),
                                     private_b, sizeof(private_b)) ==
               KCMVP_SUCCESS,
           "P-256 keypair generation succeeds");
    expect(KCMVP_ECC_ComputeSharedSecret(private_a, sizeof(private_a),
                                         public_b, sizeof(public_b),
                                         shared_a, sizeof(shared_a)) ==
               KCMVP_SUCCESS &&
           KCMVP_ECC_ComputeSharedSecret(private_b, sizeof(private_b),
                                         public_a, sizeof(public_a),
                                         shared_b, sizeof(shared_b)) ==
               KCMVP_SUCCESS &&
           memcmp(shared_a, shared_b, sizeof(shared_a)) == 0,
           "P-256 ECDH shared secrets match");
    expect(KCMVP_ECC_ComputeSharedSecret(private_a, sizeof(private_a),
                                         invalid_public,
                                         sizeof(invalid_public), shared_a,
                                         sizeof(shared_a)) ==
               KCMVP_ERROR_INVALID_PUBLIC_KEY &&
           is_all_zero(shared_a, sizeof(shared_a)),
           "invalid P-256 public key is rejected");
    expect(KCMVP_MLKEM_Keypair(mlkem_public, sizeof(mlkem_public),
                               mlkem_secret, sizeof(mlkem_secret)) ==
               KCMVP_SUCCESS &&
           KCMVP_MLKEM_Encaps(mlkem_ciphertext, sizeof(mlkem_ciphertext),
                              mlkem_shared_a, sizeof(mlkem_shared_a),
                              mlkem_public, sizeof(mlkem_public)) ==
               KCMVP_SUCCESS &&
           KCMVP_MLKEM_Decaps(mlkem_shared_b, sizeof(mlkem_shared_b),
                              mlkem_ciphertext, sizeof(mlkem_ciphertext),
                              mlkem_secret, sizeof(mlkem_secret)) ==
               KCMVP_SUCCESS &&
           memcmp(mlkem_shared_a, mlkem_shared_b,
                  sizeof(mlkem_shared_a)) == 0,
           "ML-KEM-768 keypair, encapsulation, and decapsulation agree");
    expect(KCMVP_MLKEM_Keypair(NULL, sizeof(mlkem_public), mlkem_secret,
                               sizeof(mlkem_secret)) ==
               KCMVP_ERROR_INVALID_PARAM &&
           KCMVP_MLKEM_Encaps(mlkem_ciphertext,
                              sizeof(mlkem_ciphertext) - 1, mlkem_shared_a,
                              sizeof(mlkem_shared_a), mlkem_public,
                              sizeof(mlkem_public)) ==
               KCMVP_ERROR_INVALID_PARAM &&
           KCMVP_MLKEM_Decaps(mlkem_shared_b, sizeof(mlkem_shared_b),
                              NULL, sizeof(mlkem_ciphertext), mlkem_secret,
                              sizeof(mlkem_secret)) ==
               KCMVP_ERROR_INVALID_PARAM,
           "ML-KEM services reject invalid pointers and lengths");
    expect(KCMVP_RNG_Uninstantiate() == KCMVP_SUCCESS &&
           KCMVP_RNG_Generate(random_output, sizeof(random_output)) ==
               KCMVP_ERROR_NOT_INITIALIZED,
           "RNG uninstantiate zeroizes and disables generation");

    expect(KCMVP_Zeroize() == KCMVP_SUCCESS &&
           KCMVP_GetState() == KCMVP_CM_CRITICAL_ERROR,
           "zeroize enters CRITICAL_ERROR state");

    result = KCMVP_SHA3_Hash(output, sizeof(output), abc, sizeof(abc), 256);
    expect(result == KCMVP_ERROR_INVALID_STATE,
           "error state blocks SHA3");
    expect(KCMVP_HMAC_SHA3(abc, sizeof(abc), abc, sizeof(abc), hmac, 256) ==
           KCMVP_ERROR_INVALID_STATE,
           "error state blocks HMAC");
    expect(KCMVP_ARIA_Crypt(ARIA_ENCRYPT, ARIA_ECB_MODE, NULL,
                            aria_input, sizeof(aria_input), aria_key, 128,
                            aria_output) == KCMVP_ERROR_INVALID_STATE,
           "error state blocks ARIA");
    expect(KCMVP_ECC_ComputeSharedSecret(private_a, sizeof(private_a),
                                         public_b, sizeof(public_b),
                                         shared_a, sizeof(shared_a)) ==
           KCMVP_ERROR_INVALID_STATE,
           "error state blocks ECDH");
    expect(KCMVP_MLKEM_Decaps(mlkem_shared_b, sizeof(mlkem_shared_b),
                              mlkem_ciphertext, sizeof(mlkem_ciphertext),
                              mlkem_secret, sizeof(mlkem_secret)) ==
               KCMVP_ERROR_INVALID_STATE,
           "error state blocks ML-KEM");

    expect(KCMVP_Shutdown() == KCMVP_SUCCESS &&
           KCMVP_GetState() == KCMVP_CM_EXIT,
           "shutdown enters EXIT state");
    expect(KCMVP_GetStatus(&status) == KCMVP_SUCCESS &&
           !status.initialized && !status.operational,
           "shutdown status is non-operational");

    printf("\nmodule state tests: %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}
