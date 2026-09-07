#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/random.h>

#include "entropy.h"
#include "../include/kcmvp.h"

#ifdef KCMVP_ENTROPY_TESTING
static KCMVP_ENTROPY_PROVIDER test_provider;
static void *test_provider_context;

void entropy_set_test_provider(KCMVP_ENTROPY_PROVIDER provider, void *context)
{
    test_provider = provider;
    test_provider_context = context;
}

void entropy_clear_test_provider(void)
{
    test_provider = NULL;
    test_provider_context = NULL;
}
#endif

static void secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;

    while (len-- > 0)
        *p++ = 0;
}

int entropy_get(uint8_t *out, size_t len)
{
    size_t offset = 0;

    if (out == NULL && len != 0)
        return KCMVP_ERROR_INVALID_PARAM;

#ifdef KCMVP_ENTROPY_TESTING
    if (test_provider != NULL)
        return test_provider(out, len, test_provider_context);
#endif

    while (offset < len) {
        ssize_t received = getrandom(out + offset, len - offset, 0);

        if (received < 0) {
            if (errno == EINTR)
                continue;
            return KCMVP_ERROR_SELF_TEST;
        }
        if (received == 0)
            return KCMVP_ERROR_SELF_TEST;
        offset += (size_t)received;
    }

    return KCMVP_SUCCESS;
}

static int repetition_count_test(const uint8_t *samples, size_t len)
{
    size_t run_length = 1;
    size_t i;

    if (len == 0)
        return KCMVP_ERROR_SELF_TEST;

    for (i = 1; i < len; i++) {
        if (samples[i] == samples[i - 1]) {
            run_length++;
            if (run_length >= KCMVP_ENTROPY_RCT_CUTOFF)
                return KCMVP_ERROR_SELF_TEST;
        } else {
            run_length = 1;
        }
    }

    return KCMVP_SUCCESS;
}

static int adaptive_proportion_test(const uint8_t *samples, size_t len)
{
    size_t window_start;

    if (len < KCMVP_ENTROPY_APT_WINDOW)
        return KCMVP_ERROR_SELF_TEST;

    for (window_start = 0;
         window_start + KCMVP_ENTROPY_APT_WINDOW <= len;
         window_start += KCMVP_ENTROPY_APT_WINDOW) {
        uint8_t reference = samples[window_start];
        size_t occurrences = 1;
        size_t i;

        for (i = window_start + 1;
             i < window_start + KCMVP_ENTROPY_APT_WINDOW;
             i++) {
            if (samples[i] == reference) {
                occurrences++;
                if (occurrences >= KCMVP_ENTROPY_APT_CUTOFF)
                    return KCMVP_ERROR_SELF_TEST;
            }
        }
    }

    return KCMVP_SUCCESS;
}

int entropy_startup_health_test(void)
{
    uint8_t samples[KCMVP_ENTROPY_STARTUP_BYTES];
    int result;

    result = entropy_get(samples, sizeof(samples));
    if (result == KCMVP_SUCCESS)
        result = repetition_count_test(samples, sizeof(samples));
    if (result == KCMVP_SUCCESS)
        result = adaptive_proportion_test(samples, sizeof(samples));

    secure_zero(samples, sizeof(samples));
    return result;
}
