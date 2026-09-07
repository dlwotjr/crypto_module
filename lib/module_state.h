#ifndef KCMVP_MODULE_STATE_H
#define KCMVP_MODULE_STATE_H

#include "../include/kcmvp.h"

typedef enum {
    KCMVP_EVENT_BEGIN_SELFTEST = 0,
    KCMVP_EVENT_SELFTEST_PASSED,
    KCMVP_EVENT_BEGIN_SERVICE,
    KCMVP_EVENT_SERVICE_COMPLETE,
    KCMVP_EVENT_BEGIN_COND_SELFTEST,
    KCMVP_EVENT_COND_SELFTEST_PASSED,
    KCMVP_EVENT_FATAL_ERROR,
    KCMVP_EVENT_SHUTDOWN
} KCMVP_MODULE_EVENT;

int module_state_get(void);
int module_state_transition(KCMVP_MODULE_EVENT event);
int module_authorize_service(void);
int module_complete_service(void);

#endif
