#pragma once

#define SUCCESS			1
#define NOT_INIT		0
#define FAIL			-1

#define KCMVP_CM_MODULE_STATE_BASE		1000

enum KCMVP_CRYPTO_MODULE_STATE
{
	KCMVP_CM_LOAD = KCMVP_CM_MODULE_STATE_BASE,
	KCMVP_CM_PRE_SELFTEST,
	KCMVP_CM_NORMAL,
	KCMVP_CM_COND_SELFTEST,
	KCMVP_CM_EXECUTION,
	KCMVP_CM_DEGRADED,
	KCMVP_CM_NORMAL_ERROR,
	KCMVP_CM_CRITICAL_ERROR,
	KCMVP_CM_EXIT
};

// Tracks KAT self-test completion status for each algorithm in the module
typedef struct _IS_ALG_TESTED_ {
	char isBlockCipherTested;
	char isHashTested;
	char isMACTested;
	char isDRBGTested;
}IS_ALG_TESTED;

// KAT self-test function
//int _aria_KAT_SelfTest();

// EOF

#pragma once
