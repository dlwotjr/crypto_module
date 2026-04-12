#include <stdio.h>
#include <string.h>
#include "../include/kcmvp.h"
#include "kat.h"

static void print_hex(const char *label, const Byte *data, int len)
{
    printf("%s: ", label);
    for (int i = 0; i < len; i++)
        printf("%02X", data[i]);
    printf("\n");
}

/* ------------------------------------------------------------------ */
/* KAT self-test suite                                                  */
/* ------------------------------------------------------------------ */

static int run_kat_suite(void)
{
    printf("=== ARIA KAT Self-Test ===\n");

    /* { filepath, mode, keyBits } */
    struct { const char *path; int mode; int keyBits; } tests[] = {
        /* ECB */
        { "vectors/aria/ARIA-128_(ECB)_KAT.txt", ARIA_ECB_MODE, 128 },
        { "vectors/aria/ARIA-192_(ECB)_KAT.txt", ARIA_ECB_MODE, 192 },
        { "vectors/aria/ARIA-256_(ECB)_KAT.txt", ARIA_ECB_MODE, 256 },
        /* CBC */
        { "vectors/aria/ARIA-128_(CBC)_KAT.txt", ARIA_CBC_MODE, 128 },
        { "vectors/aria/ARIA-192_(CBC)_KAT.txt", ARIA_CBC_MODE, 192 },
        { "vectors/aria/ARIA-256_(CBC)_KAT.txt", ARIA_CBC_MODE, 256 },
        /* CTR */
        { "vectors/aria/ARIA-128_(CTR)_KAT.txt", ARIA_CTR_MODE, 128 },
        { "vectors/aria/ARIA-192_(CTR)_KAT.txt", ARIA_CTR_MODE, 192 },
        { "vectors/aria/ARIA-256_(CTR)_KAT.txt", ARIA_CTR_MODE, 256 },
    };
    int n = (int)(sizeof(tests) / sizeof(tests[0]));

    int total_failed = 0;
    for (int i = 0; i < n; i++)
        total_failed += kat_run_file(tests[i].path, tests[i].mode, tests[i].keyBits);

    printf("\n[KAT] Overall: %s\n\n", total_failed == 0 ? "ALL PASSED" : "SOME FAILED");
    return total_failed;
}

/* ------------------------------------------------------------------ */
/* Quick functional smoke-test                                          */
/* ------------------------------------------------------------------ */

static void run_smoke_test(void)
{
    printf("=== ARIA-128 ECB smoke test ===\n");
    Byte key128[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };
    Byte plaintext[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
    };
    Byte ciphertext[16] = {0};
    Byte decrypted[16]  = {0};

    print_hex("PT     ", plaintext,  16);
    print_hex("KEY    ", key128,     16);

    KCMVP_ARIA_Crypt(ARIA_ENCRYPT, ARIA_ECB_MODE, NULL,
                     plaintext, 16, key128, 128, ciphertext);
    print_hex("CT     ", ciphertext, 16);

    KCMVP_ARIA_Crypt(ARIA_DECRYPT, ARIA_ECB_MODE, NULL,
                     ciphertext, 16, key128, 128, decrypted);
    print_hex("DEC    ", decrypted,  16);
    printf("Verify : %s\n\n",
           memcmp(plaintext, decrypted, 16) == 0 ? "OK" : "FAIL");

    printf("=== ARIA-128 CBC smoke test ===\n");
    Byte iv[16] = {
        0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,
        0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF
    };
    Byte cbc_cipher[16] = {0};
    print_hex("IV     ", iv, 16);
    KCMVP_ARIA_Crypt(ARIA_ENCRYPT, ARIA_CBC_MODE, iv,
                     plaintext, 16, key128, 128, cbc_cipher);
    print_hex("CBC CT ", cbc_cipher, 16);
    printf("\n");
}

/* ------------------------------------------------------------------ */
/* SHA-3 / HMAC-SHA3 demo                                               */
/* ------------------------------------------------------------------ */

static void run_sha3_demo(void)
{
    int i;

    printf("=== SHA-3 / HMAC-SHA3 Demo ===\n");

    /* SHA3-256 of empty string */
    uint8_t digest[64];
    int ret = KCMVP_SHA3_Hash(digest, 32, NULL, 0, 256);
    printf("SHA3-256(\"\") : ");
    if (ret == 0) {
        for (i = 0; i < 32; i++) printf("%02x", digest[i]);
        printf("\n");
        /* expected: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a */
    } else {
        printf("FAILED (ret=%d)\n", ret);
    }

    /* SHA3-256 of "abc" */
    const uint8_t abc[3] = { 0x61, 0x62, 0x63 };
    ret = KCMVP_SHA3_Hash(digest, 32, abc, 3, 256);
    printf("SHA3-256(abc): ");
    if (ret == 0) {
        for (i = 0; i < 32; i++) printf("%02x", digest[i]);
        printf("\n");
        /* expected: 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532 */
    } else {
        printf("FAILED (ret=%d)\n", ret);
    }

    /* HMAC-SHA3-224 Count=1 vector */
    const uint8_t hmac_key[20] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b
    };
    const uint8_t hmac_msg[8] = {
        0x48,0x69,0x20,0x54,0x68,0x65,0x72,0x65  /* "Hi There" */
    };
    uint8_t hmac_out[64];
    ret = KCMVP_HMAC_SHA3(hmac_msg, 8, hmac_key, 20, hmac_out, 224);
    printf("HMAC-SHA3-224: ");
    if (ret == 0) {
        for (i = 0; i < 28; i++) printf("%02x", hmac_out[i]);
        printf("\n");
        /* expected: 3b16546bbc7be2706a031dcafd56373d9884367641d8c59af3c860f7 */
    } else {
        printf("FAILED (ret=%d)\n", ret);
    }

    printf("\n");
}

/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== KCMVP Initialize ===\n");
    int ret = KCMVP_Initialize();
    printf("Result: %s (state=%d)\n\n",
           ret == SUCCESS ? "SUCCESS" : "FAIL", KCMVP_GetState());

    run_smoke_test();
    run_kat_suite();
    run_sha3_demo();

    return 0;
}
