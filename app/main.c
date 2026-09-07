#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/kcmvp.h"
#include "kat.h"

static int module_initialized;
static int module_finished;

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    size_t i;

    printf("    %-20s", label);
    for (i = 0; i < len; i++)
        printf("%02x", data[i]);
    putchar('\n');
}

static int report(const char *name, int passed)
{
    printf("[%s] %s\n", passed ? "PASS" : "FAIL", name);
    return passed ? 0 : 1;
}

static int ensure_initialized(void)
{
    int result;

    if (module_finished)
        return 0;
    if (module_initialized)
        return 1;

    result = KCMVP_Initialize();
    if (result == KCMVP_SUCCESS) {
        module_initialized = 1;
        return 1;
    }
    printf("    KCMVP_Initialize returned %d\n", result);
    return 0;
}

static int demo_initialize(void)
{
    static const uint8_t message[3] = { 0x61, 0x62, 0x63 };
    uint8_t digest[32];
    int preinit_result;
    int passed;

    puts("\n1. Module initialization and startup self-tests");
    if (module_initialized) {
        puts("    Module is already initialized; startup tests previously passed.");
        return report("module initialization and startup self-tests", 1);
    }
    if (module_finished)
        return report("module initialization and startup self-tests", 0);

    preinit_result = KCMVP_SHA3_Hash(digest, sizeof(digest), message,
                                      sizeof(message), 256);
    passed = preinit_result == KCMVP_ERROR_NOT_INITIALIZED &&
             ensure_initialized();
    printf("    Pre-init service result: %d (expected %d)\n",
           preinit_result, KCMVP_ERROR_NOT_INITIALIZED);
    puts("    KCMVP_Initialize runs integrity, entropy, algorithm KATs, and DRBG setup.");
    return report("module initialization and startup self-tests", passed);
}

static int demo_status(void)
{
    KCMVP_MODULE_STATUS status;
    int passed;

    puts("\n2. FSM and status query");
    passed = ensure_initialized() &&
             KCMVP_GetStatus(&status) == KCMVP_SUCCESS &&
             KCMVP_GetState() == KCMVP_CM_NORMAL &&
             status.state == KCMVP_CM_NORMAL && status.initialized &&
             status.operational;
    if (passed)
        printf("    state=%d initialized=%d operational=%d\n",
               status.state, status.initialized, status.operational);
    return report("FSM is in NORMAL and operational", passed);
}

static int demo_aria(void)
{
    static const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t plaintext[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    static const uint8_t expected[16] = {
        0xd7,0x18,0xfb,0xd6,0xab,0x64,0x4c,0x73,
        0x9d,0xa9,0x5f,0x3b,0xe6,0x45,0x17,0x78
    };
    uint8_t ciphertext[16];
    uint8_t recovered[16];
    int passed;

    puts("\n3. ARIA-128 ECB encryption and decryption");
    passed = ensure_initialized() &&
             KCMVP_ARIA_Crypt(ARIA_ENCRYPT, ARIA_ECB_MODE, NULL,
                              plaintext, sizeof(plaintext), key, 128,
                              ciphertext) == KCMVP_SUCCESS &&
             KCMVP_ARIA_Crypt(ARIA_DECRYPT, ARIA_ECB_MODE, NULL,
                              ciphertext, sizeof(ciphertext), key, 128,
                              recovered) == KCMVP_SUCCESS &&
             memcmp(ciphertext, expected, sizeof(expected)) == 0 &&
             memcmp(recovered, plaintext, sizeof(plaintext)) == 0;
    if (passed) {
        print_hex("ciphertext:", ciphertext, sizeof(ciphertext));
        print_hex("recovered:", recovered, sizeof(recovered));
    }
    return report("ARIA encrypt/decrypt known-answer test", passed);
}

static int demo_sha3(void)
{
    static const uint8_t message[3] = { 0x61, 0x62, 0x63 };
    static const uint8_t expected[32] = {
        0x3a,0x98,0x5d,0xa7,0x4f,0xe2,0x25,0xb2,
        0x04,0x5c,0x17,0x2d,0x6b,0xd3,0x90,0xbd,
        0x85,0x5f,0x08,0x6e,0x3e,0x9d,0x52,0x5b,
        0x46,0xbf,0xe2,0x45,0x11,0x43,0x15,0x32
    };
    uint8_t digest[32];
    int passed;

    puts("\n4. SHA3-256 hash");
    passed = ensure_initialized() &&
             KCMVP_SHA3_Hash(digest, sizeof(digest), message,
                             sizeof(message), 256) == KCMVP_SUCCESS &&
             memcmp(digest, expected, sizeof(expected)) == 0;
    if (passed)
        print_hex("SHA3-256(abc):", digest, sizeof(digest));
    return report("SHA3-256 known-answer test", passed);
}

static int demo_hmac(void)
{
    static const uint8_t key[20] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b
    };
    static const uint8_t message[8] = {
        0x48,0x69,0x20,0x54,0x68,0x65,0x72,0x65
    };
    static const uint8_t expected[28] = {
        0x3b,0x16,0x54,0x6b,0xbc,0x7b,0xe2,0x70,
        0x6a,0x03,0x1d,0xca,0xfd,0x56,0x37,0x3d,
        0x98,0x84,0x36,0x76,0x41,0xd8,0xc5,0x9a,
        0xf3,0xc8,0x60,0xf7
    };
    uint8_t mac[28];
    int passed;

    puts("\n5. HMAC-SHA3-224");
    passed = ensure_initialized() &&
             KCMVP_HMAC_SHA3(message, sizeof(message), key, sizeof(key),
                             mac, 224) == KCMVP_SUCCESS &&
             memcmp(mac, expected, sizeof(expected)) == 0;
    if (passed)
        print_hex("HMAC:", mac, sizeof(mac));
    return report("HMAC-SHA3 known-answer test", passed);
}

static int demo_rng(void)
{
    uint8_t before[32];
    uint8_t after[32];
    int passed;

    puts("\n6. Hash_DRBG generation and reseed");
    passed = ensure_initialized() &&
             KCMVP_RNG_Generate(before, sizeof(before)) == KCMVP_SUCCESS &&
             KCMVP_RNG_Reseed() == KCMVP_SUCCESS &&
             KCMVP_RNG_Generate(after, sizeof(after)) == KCMVP_SUCCESS &&
             memcmp(before, after, sizeof(before)) != 0;
    if (passed) {
        print_hex("before reseed:", before, sizeof(before));
        print_hex("after reseed:", after, sizeof(after));
    }
    return report("Hash_DRBG generate/reseed/generate", passed);
}

static int demo_ecdh(void)
{
    uint8_t private_a[KCMVP_ECC_P256_PRIVATE_KEY_BYTES];
    uint8_t private_b[KCMVP_ECC_P256_PRIVATE_KEY_BYTES];
    uint8_t public_a[KCMVP_ECC_P256_PUBLIC_KEY_BYTES];
    uint8_t public_b[KCMVP_ECC_P256_PUBLIC_KEY_BYTES];
    uint8_t secret_a[KCMVP_ECC_P256_SHARED_SECRET_BYTES];
    uint8_t secret_b[KCMVP_ECC_P256_SHARED_SECRET_BYTES];
    int passed;

    puts("\n7. P-256 ECDH key agreement");
    passed = ensure_initialized() &&
             KCMVP_ECC_GenerateKeyPair(public_a, sizeof(public_a),
                                       private_a, sizeof(private_a)) ==
                 KCMVP_SUCCESS &&
             KCMVP_ECC_GenerateKeyPair(public_b, sizeof(public_b),
                                       private_b, sizeof(private_b)) ==
                 KCMVP_SUCCESS &&
             KCMVP_ECC_ComputeSharedSecret(private_a, sizeof(private_a),
                                           public_b, sizeof(public_b),
                                           secret_a, sizeof(secret_a)) ==
                 KCMVP_SUCCESS &&
             KCMVP_ECC_ComputeSharedSecret(private_b, sizeof(private_b),
                                           public_a, sizeof(public_a),
                                           secret_b, sizeof(secret_b)) ==
                 KCMVP_SUCCESS &&
             memcmp(secret_a, secret_b, sizeof(secret_a)) == 0;
    if (passed)
        print_hex("shared secret:", secret_a, sizeof(secret_a));
    return report("P-256 reciprocal shared secrets match", passed);
}

static int demo_mlkem(void)
{
    uint8_t public_key[KCMVP_MLKEM768_PUBLIC_KEY_BYTES];
    uint8_t secret_key[KCMVP_MLKEM768_SECRET_KEY_BYTES];
    uint8_t ciphertext[KCMVP_MLKEM768_CIPHERTEXT_BYTES];
    uint8_t secret_a[KCMVP_MLKEM768_SHARED_SECRET_BYTES];
    uint8_t secret_b[KCMVP_MLKEM768_SHARED_SECRET_BYTES];
    int passed;

    puts("\n8. ML-KEM-768 encapsulation and decapsulation");
    passed = ensure_initialized() &&
             KCMVP_MLKEM_Keypair(public_key, sizeof(public_key),
                                 secret_key, sizeof(secret_key)) ==
                 KCMVP_SUCCESS &&
             KCMVP_MLKEM_Encaps(ciphertext, sizeof(ciphertext),
                                secret_a, sizeof(secret_a), public_key,
                                sizeof(public_key)) == KCMVP_SUCCESS &&
             KCMVP_MLKEM_Decaps(secret_b, sizeof(secret_b), ciphertext,
                                sizeof(ciphertext), secret_key,
                                sizeof(secret_key)) == KCMVP_SUCCESS &&
             memcmp(secret_a, secret_b, sizeof(secret_a)) == 0;
    if (passed)
        print_hex("shared secret:", secret_a, sizeof(secret_a));
    return report("ML-KEM-768 shared secrets match", passed);
}

static int demo_failure_tests(void)
{
    FILE *test_binary;
    int passed;

    puts("\n9. Integrity and startup self-test failure behavior");
    test_binary = fopen("build/module_state_test", "rb");
    passed = test_binary != NULL;
    if (test_binary != NULL)
        fclose(test_binary);
    puts("    Production APIs intentionally expose no fault-injection hooks.");
    puts("    Run: ./build/module_state_test");
    puts("    It covers forced integrity, entropy, KAT, and service-lockout failures.");
    return report("fault-injection coverage is available in the test binary",
                  passed);
}

static int demo_conditional_tests(void)
{
    uint8_t ecc_private[KCMVP_ECC_P256_PRIVATE_KEY_BYTES];
    uint8_t ecc_public[KCMVP_ECC_P256_PUBLIC_KEY_BYTES];
    uint8_t mlkem_public[KCMVP_MLKEM768_PUBLIC_KEY_BYTES];
    uint8_t mlkem_secret[KCMVP_MLKEM768_SECRET_KEY_BYTES];
    KCMVP_MODULE_STATUS status;
    int passed;

    puts("\n10. Pairwise conditional self-tests");
    passed = ensure_initialized() &&
             KCMVP_ECC_GenerateKeyPair(ecc_public, sizeof(ecc_public),
                                       ecc_private, sizeof(ecc_private)) ==
                 KCMVP_SUCCESS &&
             KCMVP_MLKEM_Keypair(mlkem_public, sizeof(mlkem_public),
                                 mlkem_secret, sizeof(mlkem_secret)) ==
                 KCMVP_SUCCESS &&
             KCMVP_GetStatus(&status) == KCMVP_SUCCESS &&
             status.state == KCMVP_CM_NORMAL && status.operational;
    puts("    Both keypair APIs run their internal pairwise test before release.");
    puts("    Forced-failure lockout is covered by ./build/module_state_test.");
    return report("conditional self-tests passed and returned to NORMAL",
                  passed);
}

static int demo_shutdown(void)
{
    uint8_t output[16];
    int zeroize_result;
    int blocked_result;
    int shutdown_result;
    int passed;

    puts("\n11. Zeroize and shutdown");
    if (!ensure_initialized())
        return report("zeroize, service lockout, and shutdown", 0);

    zeroize_result = KCMVP_Zeroize();
    blocked_result = KCMVP_RNG_Generate(output, sizeof(output));
    shutdown_result = KCMVP_Shutdown();
    passed = zeroize_result == KCMVP_SUCCESS &&
             blocked_result == KCMVP_ERROR_INVALID_STATE &&
             shutdown_result == KCMVP_SUCCESS &&
             KCMVP_GetState() == KCMVP_CM_EXIT;
    printf("    zeroize=%d blocked RNG=%d shutdown=%d final state=%d\n",
           zeroize_result, blocked_result, shutdown_result, KCMVP_GetState());
    module_finished = 1;
    module_initialized = 0;
    return report("zeroize, service lockout, and shutdown", passed);
}

static int demo_aria_vectors(void)
{
    static const struct {
        const char *path;
        int mode;
        int key_bits;
    } tests[] = {
        { "vectors/aria/ARIA-128_(ECB)_KAT.txt", ARIA_ECB_MODE, 128 },
        { "vectors/aria/ARIA-192_(ECB)_KAT.txt", ARIA_ECB_MODE, 192 },
        { "vectors/aria/ARIA-256_(ECB)_KAT.txt", ARIA_ECB_MODE, 256 },
        { "vectors/aria/ARIA-128_(CBC)_KAT.txt", ARIA_CBC_MODE, 128 },
        { "vectors/aria/ARIA-192_(CBC)_KAT.txt", ARIA_CBC_MODE, 192 },
        { "vectors/aria/ARIA-256_(CBC)_KAT.txt", ARIA_CBC_MODE, 256 },
        { "vectors/aria/ARIA-128_(CTR)_KAT.txt", ARIA_CTR_MODE, 128 },
        { "vectors/aria/ARIA-192_(CTR)_KAT.txt", ARIA_CTR_MODE, 192 },
        { "vectors/aria/ARIA-256_(CTR)_KAT.txt", ARIA_CTR_MODE, 256 }
    };
    size_t i;
    int failures = 0;

    puts("\n12. Complete supplied ARIA vector suite");
    if (!ensure_initialized())
        return report("3,342 ARIA encryption/decryption vectors", 0);
    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
        failures += kat_run_file(tests[i].path, tests[i].mode,
                                 tests[i].key_bits);
    return report("3,342 ARIA encryption/decryption vectors", failures == 0);
}

static int run_item(int item)
{
    switch (item) {
    case 1: return demo_initialize();
    case 2: return demo_status();
    case 3: return demo_aria();
    case 4: return demo_sha3();
    case 5: return demo_hmac();
    case 6: return demo_rng();
    case 7: return demo_ecdh();
    case 8: return demo_mlkem();
    case 9: return demo_failure_tests();
    case 10: return demo_conditional_tests();
    case 11: return demo_shutdown();
    case 12: return demo_aria_vectors();
    default:
        puts("Unknown menu item.");
        return 1;
    }
}

static int run_all(void)
{
    int item;
    int failures = 0;

    for (item = 1; item <= 10; item++)
        failures += run_item(item);
    failures += run_item(12);
    failures += run_item(11);
    printf("\nFINAL DEMO RESULT: %s (%d failure%s)\n",
           failures == 0 ? "PASS" : "FAIL", failures,
           failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}

static void print_menu(void)
{
    puts("\nSoftware Crypto Module Final Demo");
    puts("  1. Module init and startup self-tests");
    puts("  2. FSM/status query");
    puts("  3. ARIA encrypt/decrypt");
    puts("  4. SHA3 hash");
    puts("  5. HMAC-SHA3");
    puts("  6. RNG/DRBG generate and reseed");
    puts("  7. P-256 ECDH key agreement");
    puts("  8. ML-KEM-768 key establishment");
    puts("  9. Integrity/self-test failure coverage");
    puts(" 10. Conditional self-test behavior");
    puts(" 11. Zeroize and shutdown (ends this process)");
    puts(" 12. Complete ARIA vector suite");
    puts("  0. Run all demos");
    puts("  q. Quit");
}

int main(int argc, char **argv)
{
    char line[32];
    char *end;
    long item;

    if (argc == 2 && strcmp(argv[1], "--all") == 0)
        return run_all();
    if (argc == 2 && strcmp(argv[1], "--vectors") == 0) {
        int result = demo_aria_vectors();

        if (!module_finished && module_initialized)
            result += demo_shutdown();
        return result == 0 ? 0 : 1;
    }
    if (argc != 1) {
        fprintf(stderr, "usage: %s [--all|--vectors]\n", argv[0]);
        return 1;
    }

    for (;;) {
        print_menu();
        printf("Select: ");
        if (fgets(line, sizeof(line), stdin) == NULL)
            break;
        if (line[0] == 'q' || line[0] == 'Q')
            break;
        item = strtol(line, &end, 10);
        if (end == line || (item < 0 || item > 12)) {
            puts("Enter a number from 0 to 12, or q.");
            continue;
        }
        if (item == 0)
            return run_all();
        run_item((int)item);
        if (module_finished)
            break;
    }

    if (!module_finished && module_initialized)
        demo_shutdown();
    return 0;
}
