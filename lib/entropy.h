#ifndef KCMVP_ENTROPY_H
#define KCMVP_ENTROPY_H

#include <stddef.h>
#include <stdint.h>

#define KCMVP_ENTROPY_STARTUP_BYTES 512
#define KCMVP_ENTROPY_RCT_CUTOFF 5
#define KCMVP_ENTROPY_APT_WINDOW 64
#define KCMVP_ENTROPY_APT_CUTOFF 16

int entropy_get(uint8_t *out, size_t len);
int entropy_startup_health_test(void);

#ifdef KCMVP_ENTROPY_TESTING
typedef int (*KCMVP_ENTROPY_PROVIDER)(uint8_t *out, size_t len, void *context);

void entropy_set_test_provider(KCMVP_ENTROPY_PROVIDER provider, void *context);
void entropy_clear_test_provider(void);
#endif

#endif
