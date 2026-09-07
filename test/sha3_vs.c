/*
 * sha3_vs.c  —  SHA-3 Validation System
 *
 * Runs three test types against the NIST CAVS byte-oriented test vectors
 * in vectors/sha3/sha-3bytetestvectors/:
 *
 *   1. Short Message Test  (SHA3_XXXShortMsg.rsp)
 *   2. Long  Message Test  (SHA3_XXXLongMsg.rsp)
 *   3. Monte Carlo Test    (SHA3_XXXMonte.rsp)
 *   4. HMAC-SHA3 Test      (vectors/sha3/sha-3bytetestvectors/HMAC/HMAC_SHA3.rsp)
 *
 * Compile (via Makefile target 'sha3_vs'):
 *   make sha3_vs
 *
 * Run from project root:
 *   ./build/sha3_vs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "../include/kcmvp.h"

/* ------------------------------------------------------------------ */
/* Utilities                                                            */
/* ------------------------------------------------------------------ */

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Convert hex string → bytes.  Returns number of bytes written. */
static int hex2bin(uint8_t *dst, const char *src)
{
    int n = 0;
    while (src[0] && src[1]) {
        int hi = hex_nibble(src[0]);
        int lo = hex_nibble(src[1]);
        if (hi < 0 || lo < 0) break;
        dst[n++] = (uint8_t)((hi << 4) | lo);
        src += 2;
    }
    return n;
}

/* Trim trailing whitespace (including \r\n) in place */
static void rtrim(char *s)
{
    int n = (int)strlen(s);
    while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r' ||
                     s[n-1] == ' '  || s[n-1] == '\t'))
        s[--n] = '\0';
}

/* Skip leading whitespace */
static const char *ltrim(const char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

static int total_pass = 0;
static int total_fail = 0;


/* ------------------------------------------------------------------ */
/* Short / Long Message Tests                                           */
/*                                                                      */
/* File format (per entry):                                             */
/*   Len = <bits>                                                        */
/*   Msg = <hex>                                                         */
/*   MD  = <hex>                                                         */
/* ------------------------------------------------------------------ */

/* Maximum message size across all LongMsg test vectors (117152 bits = 14644 bytes).
 * Use a fixed large buffer to avoid malloc complexity. */
#define MAX_MSG_BYTES 20000

static int run_msg_test(const char *filepath, int bitSize,
                        const char *test_name)
{
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        printf("  [SKIP] Cannot open %s\n", filepath);
        return 0;
    }

    /* Line buffer must fit one hex-encoded long message (up to 29288 hex chars) */
    char *line = malloc(65536);
    if (!line) { fclose(fp); return -1; }

    static uint8_t msg[MAX_MSG_BYTES];
    uint8_t md_expected[64];
    uint8_t md_computed[64];
    int  len_bits  = -1;
    int  digestLen = bitSize / 8;
    int  case_num  = 0;
    int  pass = 0, fail = 0;
    char label[128];

    while (fgets(line, 65536, fp)) {
        rtrim(line);
        const char *p = ltrim(line);

        if (*p == '#' || *p == '[' || *p == '\0') continue;

        if (strncmp(p, "Len = ", 6) == 0) {
            len_bits = atoi(p + 6);
        } else if (strncmp(p, "Msg = ", 6) == 0) {
            if (len_bits < 0) continue;
            if (len_bits > 0)
                hex2bin(msg, p + 6);
        } else if (strncmp(p, "MD = ", 5) == 0) {
            if (len_bits < 0) continue;
            hex2bin(md_expected, p + 5);

            int msgBytes = len_bits / 8;
            int ret = KCMVP_SHA3_Hash(md_computed, digestLen,
                                      (len_bits > 0 ? msg : NULL), msgBytes,
                                      bitSize);

            case_num++;
            int ok = (ret == 0) &&
                     (memcmp(md_computed, md_expected, digestLen) == 0);
            snprintf(label, sizeof(label), "%s case %d (Len=%d bits)",
                     test_name, case_num, len_bits);
            if (ok) pass++;
            else    { fail++; printf("  FAIL: %s\n", label); }

            len_bits = -1;
        }
    }

    free(line);
    fclose(fp);
    total_pass += pass;
    total_fail += fail;
    printf("  %s: %d passed, %d failed\n", test_name, pass, fail);
    return fail;
}


/* ------------------------------------------------------------------ */
/* Monte Carlo Test                                                     */
/*                                                                      */
/* Algorithm (NIST CAVS SHA-3 byte-oriented):                          */
/*   md = SHA3(Seed)              ← COUNT = 0                          */
/*   for i = 1 to 99:                                                  */
/*       md = SHA3(md)            ← COUNT = i                          */
/*                                                                      */
/* File format:                                                         */
/*   Seed = <hex>                                                        */
/*   COUNT = N                                                           */
/*   MD = <hex>                                                          */
/* ------------------------------------------------------------------ */

/*
 * SHA-3 Monte Carlo algorithm — byte-oriented NIST CAVS variant:
 *
 *   seed = Seed
 *   for j = 0 to 99:          ← outer loop, one result per COUNT
 *       for i = 0 to 999:     ← 1000 inner iterations
 *           seed = SHA3(seed)
 *       COUNT[j] = seed        ← output; becomes Seed for next j
 *
 * Note: the bit-oriented CAVS variant uses a three-message concatenation
 * formula instead; the byte-oriented test vectors used here require the
 * simpler single-hash iteration above.
 */
static int run_monte_test(const char *filepath, int bitSize,
                          const char *test_name)
{
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        printf("  [SKIP] Cannot open %s\n", filepath);
        return 0;
    }

    char    line[1024];
    int     digestLen = bitSize / 8;
    int     pass = 0, fail = 0;
    int     count = -1;
    int     have_results = 0;
    char    label[128];

    uint8_t cur[64];           /* running seed / current digest  */
    uint8_t tmp[64];           /* temporary output buffer        */
    uint8_t md_expected[64];
    uint8_t results[100][64];  /* precomputed outputs for all 100 COUNTs */

    while (fgets(line, sizeof(line), fp)) {
        rtrim(line);
        const char *p = ltrim(line);

        if (*p == '#' || *p == '[' || *p == '\0') continue;

        if (strncmp(p, "Seed = ", 7) == 0) {
            int i, j;
            hex2bin(cur, p + 7);

            for (j = 0; j < 100; j++) {
                /* 1000 inner SHA3 applications */
                for (i = 0; i < 1000; i++) {
                    KCMVP_SHA3_Hash(tmp, digestLen, cur, digestLen, bitSize);
                    memcpy(cur, tmp, digestLen);
                }
                memcpy(results[j], cur, digestLen);
                /* cur already holds the new Seed for next j */
            }
            have_results = 1;

        } else if (strncmp(p, "COUNT = ", 8) == 0) {
            count = atoi(p + 8);
        } else if (strncmp(p, "MD = ", 5) == 0) {
            if (!have_results || count < 0) continue;
            hex2bin(md_expected, p + 5);

            int ok = (memcmp(results[count], md_expected, digestLen) == 0);
            snprintf(label, sizeof(label), "%s COUNT=%d", test_name, count);
            if (ok) pass++;
            else    { fail++; printf("  FAIL: %s\n", label); }
            count = -1;
        }
    }

    fclose(fp);
    total_pass += pass;
    total_fail += fail;
    printf("  %s: %d passed, %d failed\n", test_name, pass, fail);
    return fail;
}


/* ------------------------------------------------------------------ */
/* HMAC-SHA3 Test                                                       */
/*                                                                      */
/* File format:                                                         */
/*   [L = <digestBytes>]  ← determines SHA-3 variant                   */
/*   Count = N                                                           */
/*   KLen  = <keyLen bytes>                                              */
/*   MLen  = <msgLen bytes>                                              */
/*   TLen  = <tagLen bytes>   (truncation, <= digestLen)                 */
/*   Key   = <hex>                                                        */
/*   Msg   = <hex>                                                        */
/*   Mac   = <hex>                                                        */
/* ------------------------------------------------------------------ */

static int run_hmac_test(const char *filepath)
{
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        printf("  [SKIP] Cannot open %s\n", filepath);
        return 0;
    }

    char    line[4096];
    int     L       = -1;   /* digest length in bytes → bitSize = L*8 */
    int     bitSize = -1;
    int     tlen    = -1;
    uint8_t key[512], msg[512], mac_expected[64], mac_computed[64];
    int     klen = 0, mlen = 0;
    int     count = -1;
    int     have_key = 0, have_msg = 0;
    int     pass = 0, fail = 0;
    int     case_num = 0;
    char    label[128];

    while (fgets(line, sizeof(line), fp)) {
        rtrim(line);
        const char *p = ltrim(line);

        if (*p == '#' || *p == '\0') continue;

        if (*p == '[') {
            /* [L = N] */
            int l_val;
            if (sscanf(p, "[L = %d]", &l_val) == 1) {
                L       = l_val;
                bitSize = L * 8;
            }
            continue;
        }

        if (strncmp(p, "Count = ", 8) == 0) {
            count = atoi(p + 8);
            have_key = have_msg = 0;
            tlen = -1;
        } else if (strncmp(p, "KLen = ", 7) == 0) {
            klen = atoi(p + 7);
        } else if (strncmp(p, "MLen = ", 7) == 0) {
            mlen = atoi(p + 7);
        } else if (strncmp(p, "TLen = ", 7) == 0) {
            tlen = atoi(p + 7);
        } else if (strncmp(p, "Key = ", 6) == 0) {
            hex2bin(key, p + 6);
            have_key = 1;
        } else if (strncmp(p, "Msg = ", 6) == 0) {
            hex2bin(msg, p + 6);
            have_msg = 1;
        } else if (strncmp(p, "Mac = ", 6) == 0) {
            if (bitSize < 0 || !have_key || !have_msg || tlen < 0) continue;

            hex2bin(mac_expected, p + 6);

            int ret = KCMVP_HMAC_SHA3(msg, (uint32_t)mlen,
                                      key, (uint32_t)klen,
                                      mac_computed, bitSize);

            case_num++;
            int ok = (ret == KCMVP_SUCCESS) &&
                     (memcmp(mac_computed, mac_expected, tlen) == 0);
            snprintf(label, sizeof(label),
                     "HMAC-SHA3-%d Count=%d (TLen=%d)",
                     bitSize, count, tlen);
            if (ok) pass++;
            else    { fail++; printf("  FAIL: %s\n", label); }
        }
    }

    fclose(fp);
    total_pass += pass;
    total_fail += fail;
    printf("  HMAC-SHA3 test: %d passed, %d failed\n", pass, fail);
    return fail;
}


/* ------------------------------------------------------------------ */
/* Driver                                                               */
/* ------------------------------------------------------------------ */

static void run_variant(int bitSize)
{
    char short_path[256], long_path[256], monte_path[256];

    snprintf(short_path, sizeof(short_path),
             "vectors/sha3/sha-3bytetestvectors/SHA3_%dShortMsg.rsp", bitSize);
    snprintf(long_path,  sizeof(long_path),
             "vectors/sha3/sha-3bytetestvectors/SHA3_%dLongMsg.rsp",  bitSize);
    snprintf(monte_path, sizeof(monte_path),
             "vectors/sha3/sha-3bytetestvectors/SHA3_%dMonte.rsp",    bitSize);

    char name[64];

    snprintf(name, sizeof(name), "SHA3-%d Short Message", bitSize);
    run_msg_test(short_path, bitSize, name);

    snprintf(name, sizeof(name), "SHA3-%d Long  Message", bitSize);
    run_msg_test(long_path, bitSize, name);

    snprintf(name, sizeof(name), "SHA3-%d Monte Carlo", bitSize);
    run_monte_test(monte_path, bitSize, name);
}


int main(void)
{
    printf("============================================================\n");
    printf("  SHA-3 Validation System (SHA3VS)\n");
    printf("============================================================\n\n");

    if (KCMVP_Initialize() != KCMVP_SUCCESS) {
        fprintf(stderr, "KCMVP initialization failed\n");
        return 1;
    }

    /* ---- SHA-3 Hash Tests ---- */
    printf("[ SHA3-224 ]\n");
    run_variant(224);
    printf("\n");

    printf("[ SHA3-256 ]\n");
    run_variant(256);
    printf("\n");

    printf("[ SHA3-384 ]\n");
    run_variant(384);
    printf("\n");

    printf("[ SHA3-512 ]\n");
    run_variant(512);
    printf("\n");

    /* ---- HMAC-SHA3 Tests ---- */
    printf("[ HMAC-SHA3 ]\n");
    run_hmac_test("vectors/sha3/sha-3bytetestvectors/HMAC/HMAC_SHA3.rsp");
    printf("\n");

    /* ---- Summary ---- */
    printf("============================================================\n");
    printf("  TOTAL: %d passed, %d failed\n", total_pass, total_fail);
    printf("============================================================\n");

    if (KCMVP_Shutdown() != KCMVP_SUCCESS)
        return 1;

    return (total_fail == 0) ? 0 : 1;
}
