#ifndef KCMVP_SELFTEST_H
#define KCMVP_SELFTEST_H

typedef struct {
    unsigned char aria_passed;
    unsigned char sha3_passed;
    unsigned char hmac_sha3_passed;
    unsigned char hash_drbg_passed;
    unsigned char ecc_p256_passed;
    unsigned char mlkem768_passed;
} KCMVP_SELFTEST_STATUS;

int selftest_run_startup(KCMVP_SELFTEST_STATUS *status);

typedef enum {
    KCMVP_SELFTEST_FORCE_NONE = 0,
    KCMVP_SELFTEST_FORCE_ARIA,
    KCMVP_SELFTEST_FORCE_SHA3,
    KCMVP_SELFTEST_FORCE_HMAC_SHA3,
    KCMVP_SELFTEST_FORCE_HASH_DRBG,
    KCMVP_SELFTEST_FORCE_ECC_P256,
    KCMVP_SELFTEST_FORCE_MLKEM768
} KCMVP_SELFTEST_FORCE;

#ifdef KCMVP_SELFTEST_TESTING
void selftest_force_failure(KCMVP_SELFTEST_FORCE test);
#endif

#endif
