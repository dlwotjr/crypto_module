#include "kat.h"
#include "../include/kcmvp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Maximum plaintext/ciphertext length seen in KAT files */
#define KAT_MAX_BLOCK 256

/* ------------------------------------------------------------------ */
/* Hex helpers                                                          */
/* ------------------------------------------------------------------ */

static int hex_char(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* Returns number of bytes parsed, -1 on error. */
static int hex_to_bytes(const char *hex, Byte *out, int max_bytes)
{
    int len = (int)strlen(hex);
    if (len % 2 != 0) return -1;
    int nbytes = len / 2;
    if (nbytes > max_bytes) return -1;
    for (int i = 0; i < nbytes; i++) {
        int hi = hex_char(hex[i * 2]);
        int lo = hex_char(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (Byte)((hi << 4) | lo);
    }
    return nbytes;
}

/* ------------------------------------------------------------------ */
/* Line parser                                                          */
/* ------------------------------------------------------------------ */

/* Parse "TAG = HEXVALUE" from line. Returns 1 if tag matched. */
static int parse_field(const char *line, const char *tag, char *hex_out, int hex_max)
{
    size_t tlen = strlen(tag);
    if (strncmp(line, tag, tlen) != 0) return 0;
    const char *p = line + tlen;
    while (*p == ' ' || *p == '=') p++;
    /* copy up to first whitespace / newline */
    int i = 0;
    while (*p && !isspace((unsigned char)*p) && i < hex_max - 1)
        hex_out[i++] = *p++;
    hex_out[i] = '\0';
    return 1;
}

/* ------------------------------------------------------------------ */
/* KAT runner                                                          */
/* ------------------------------------------------------------------ */

int kat_run_file(const char *filepath, int mode, int keyBits)
{
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        fprintf(stderr, "[KAT] Cannot open: %s\n", filepath);
        return -1;
    }

    char line[1024];
    char hex_key[128] = {0};
    char hex_iv[128]  = {0};
    char hex_pt[512]  = {0};
    char hex_ct[512]  = {0};

    Byte key[32], iv[16], pt[KAT_MAX_BLOCK], ct_expected[KAT_MAX_BLOCK];
    Byte ct_computed[KAT_MAX_BLOCK], pt_computed[KAT_MAX_BLOCK];

    int total = 0, passed = 0, failed = 0;
    int has_key = 0, has_iv = 0, has_pt = 0, has_ct = 0;

    /* Helper: run one test vector */
    #define RUN_VECTOR() do { \
        if (!has_key || !has_pt || !has_ct) break; \
        int pt_len = hex_to_bytes(hex_pt, pt, KAT_MAX_BLOCK); \
        int ct_len = hex_to_bytes(hex_ct, ct_expected, KAT_MAX_BLOCK); \
        if (pt_len < 0 || ct_len < 0 || pt_len != ct_len) { \
            fprintf(stderr, "[KAT] Bad hex in vector %d\n", total + 1); \
            failed++; total++; \
        } else { \
            hex_to_bytes(hex_key, key, 32); \
            if (has_iv) hex_to_bytes(hex_iv, iv, 16); \
            memset(ct_computed, 0, sizeof(ct_computed)); \
            memset(pt_computed, 0, sizeof(pt_computed)); \
            int encrypt_result = KCMVP_ARIA_Crypt( \
                ARIA_ENCRYPT, mode, has_iv ? iv : NULL, \
                pt, pt_len, key, keyBits, ct_computed); \
            int decrypt_result = KCMVP_ARIA_Crypt( \
                ARIA_DECRYPT, mode, has_iv ? iv : NULL, \
                ct_expected, ct_len, key, keyBits, pt_computed); \
            total++; \
            if (encrypt_result == KCMVP_SUCCESS && \
                decrypt_result == KCMVP_SUCCESS && \
                memcmp(ct_computed, ct_expected, ct_len) == 0 && \
                memcmp(pt_computed, pt, pt_len) == 0) { \
                passed++; \
            } else { \
                failed++; \
                fprintf(stderr, "[KAT] FAIL vector %d\n", total); \
            } \
        } \
        has_key = has_iv = has_pt = has_ct = 0; \
        hex_key[0] = hex_iv[0] = hex_pt[0] = hex_ct[0] = '\0'; \
    } while (0)

    while (fgets(line, sizeof(line), fp)) {
        /* Strip trailing newline */
        line[strcspn(line, "\r\n")] = '\0';

        if (parse_field(line, "KEY", hex_key, sizeof(hex_key)))  { has_key = 1; continue; }
        if (parse_field(line, "IV",  hex_iv,  sizeof(hex_iv)))   { has_iv  = 1; continue; }
        if (parse_field(line, "PT",  hex_pt,  sizeof(hex_pt)))   { has_pt  = 1; continue; }
        if (parse_field(line, "CT",  hex_ct,  sizeof(hex_ct)))   { has_ct  = 1; RUN_VECTOR(); continue; }
    }
    /* Flush last vector if file doesn't end with blank line */
    RUN_VECTOR();

    #undef RUN_VECTOR

    fclose(fp);

    /* Extract just the filename for the report */
    const char *fname = strrchr(filepath, '/');
    fname = fname ? fname + 1 : filepath;

    printf("[KAT] %-45s  total=%d  passed=%d  failed=%d  %s\n",
           fname, total, passed, failed, failed == 0 ? "OK" : "FAIL");

    return failed;
}
