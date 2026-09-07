#include "module_state.h"

static KCMVP_MODULE_STATE module_state = KCMVP_CM_LOAD;

int module_state_get(void)
{
    return module_state;
}

int module_state_transition(KCMVP_MODULE_EVENT event)
{
    KCMVP_MODULE_STATE next;

    switch (module_state) {
    case KCMVP_CM_LOAD:
        if (event == KCMVP_EVENT_BEGIN_SELFTEST)
            next = KCMVP_CM_PRE_SELFTEST;
        else if (event == KCMVP_EVENT_FATAL_ERROR)
            next = KCMVP_CM_CRITICAL_ERROR;
        else if (event == KCMVP_EVENT_SHUTDOWN)
            next = KCMVP_CM_EXIT;
        else
            return KCMVP_ERROR_INVALID_STATE;
        break;

    case KCMVP_CM_PRE_SELFTEST:
        if (event == KCMVP_EVENT_SELFTEST_PASSED)
            next = KCMVP_CM_NORMAL;
        else if (event == KCMVP_EVENT_FATAL_ERROR)
            next = KCMVP_CM_CRITICAL_ERROR;
        else
            return KCMVP_ERROR_INVALID_STATE;
        break;

    case KCMVP_CM_NORMAL:
        if (event == KCMVP_EVENT_BEGIN_SERVICE)
            next = KCMVP_CM_EXECUTION;
        else if (event == KCMVP_EVENT_BEGIN_COND_SELFTEST)
            next = KCMVP_CM_COND_SELFTEST;
        else if (event == KCMVP_EVENT_FATAL_ERROR)
            next = KCMVP_CM_CRITICAL_ERROR;
        else if (event == KCMVP_EVENT_SHUTDOWN)
            next = KCMVP_CM_EXIT;
        else
            return KCMVP_ERROR_INVALID_STATE;
        break;

    case KCMVP_CM_EXECUTION:
        if (event == KCMVP_EVENT_SERVICE_COMPLETE)
            next = KCMVP_CM_NORMAL;
        else if (event == KCMVP_EVENT_FATAL_ERROR)
            next = KCMVP_CM_CRITICAL_ERROR;
        else
            return KCMVP_ERROR_INVALID_STATE;
        break;

    case KCMVP_CM_COND_SELFTEST:
        if (event == KCMVP_EVENT_COND_SELFTEST_PASSED)
            next = KCMVP_CM_NORMAL;
        else if (event == KCMVP_EVENT_FATAL_ERROR)
            next = KCMVP_CM_CRITICAL_ERROR;
        else
            return KCMVP_ERROR_INVALID_STATE;
        break;

    case KCMVP_CM_DEGRADED:
    case KCMVP_CM_NORMAL_ERROR:
        if (event == KCMVP_EVENT_FATAL_ERROR)
            next = KCMVP_CM_CRITICAL_ERROR;
        else if (event == KCMVP_EVENT_SHUTDOWN)
            next = KCMVP_CM_EXIT;
        else
            return KCMVP_ERROR_INVALID_STATE;
        break;

    case KCMVP_CM_CRITICAL_ERROR:
        if (event == KCMVP_EVENT_SHUTDOWN)
            next = KCMVP_CM_EXIT;
        else
            return KCMVP_ERROR_INVALID_STATE;
        break;

    case KCMVP_CM_EXIT:
    default:
        return KCMVP_ERROR_INVALID_STATE;
    }

    module_state = next;
    return KCMVP_SUCCESS;
}

int module_authorize_service(void)
{
    if (module_state == KCMVP_CM_LOAD)
        return KCMVP_ERROR_NOT_INITIALIZED;
    if (module_state != KCMVP_CM_NORMAL)
        return KCMVP_ERROR_INVALID_STATE;

    return module_state_transition(KCMVP_EVENT_BEGIN_SERVICE);
}

int module_complete_service(void)
{
    return module_state_transition(KCMVP_EVENT_SERVICE_COMPLETE);
}
