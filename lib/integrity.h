#ifndef KCMVP_INTEGRITY_H
#define KCMVP_INTEGRITY_H

#include <stdint.h>

#define KCMVP_INTEGRITY_DIGEST_SIZE 32

typedef struct {
    const char *path;
    uint8_t digest[KCMVP_INTEGRITY_DIGEST_SIZE];
} KCMVP_INTEGRITY_ENTRY;

int integrity_verify(void);

#ifdef KCMVP_INTEGRITY_TESTING
void integrity_force_manifest_failure(int enabled);
#endif

#endif
