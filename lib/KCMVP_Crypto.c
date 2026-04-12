
#include <stdio.h>
#include <string.h>
#include "KCMVP_Crypto.h"
#include "aria.h"
#include "sha3.h"
#include "KISA_HMAC_SHA3.h"

#define EXPORT __attribute__((visibility("default")))
//#include "integrityTest.h"

IS_ALG_TESTED algTestedFlag;
int gCryptoState = KCMVP_CM_LOAD;
int gVar;

void _Init() {
	algTestedFlag.isBlockCipherTested = NOT_INIT;
	algTestedFlag.isHashTested = NOT_INIT;
	algTestedFlag.isMACTested = NOT_INIT;
	algTestedFlag.isDRBGTested = NOT_INIT;
}

// Internal function: returns the current cryptographic module state
int _getState() {
	return gCryptoState;
}

// Internal function: updates the module state based on the given event
// Only transitions defined in the finite state model are permitted
void _changeState(int newState) {

	switch (gCryptoState) {
	case KCMVP_CM_LOAD:
		// Codes
		break;
	case KCMVP_CM_EXECUTION:
		// Codes;
		break;
	case KCMVP_CM_PRE_SELFTEST:
		// Codes
		break;
	case KCMVP_CM_COND_SELFTEST:
		// Codes
		break;
	default:
		break;
	}
}

// Pre-selftest: software integrity check for the cryptographic module
int _preSelfTest() {
	int ret = SUCCESS;

	// Codes...
	// Software integrity test for the cryptographic module
	//ret = integrityTest();

	return ret;
}

// Runs the KAT self-test for each algorithm loaded in the cryptographic module
int _AlgKATSelfTest() {
	int ret = SUCCESS;

	/* ---- SHA3-256 KAT: hash of empty string ---- */
	/* Expected: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a */
	static const uint8_t sha3_256_empty_exp[32] = {
		0xa7,0xff,0xc6,0xf8,0xbf,0x1e,0xd7,0x66,
		0x51,0xc1,0x47,0x56,0xa0,0x61,0xd6,0x62,
		0xf5,0x80,0xff,0x4d,0xe4,0x3b,0x49,0xfa,
		0x82,0xd8,0x0a,0x4b,0x80,0xf8,0x43,0x4a
	};
	uint8_t sha3_out[64];
	if (sha3_hash(sha3_out, 32, NULL, 0, 256, SHA3_SHAKE_NONE) != 0 ||
	    memcmp(sha3_out, sha3_256_empty_exp, 32) != 0) {
		fprintf(stderr, "SHA3-256 KAT failed!\n");
		return FAIL;
	}

	/* SHA3-256 KAT: "abc" */
	/* Expected: 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532 */
	static const uint8_t sha3_256_abc_exp[32] = {
		0x3a,0x98,0x5d,0xa7,0x4f,0xe2,0x25,0xb2,
		0x04,0x5c,0x17,0x2d,0x6b,0xd3,0x90,0xbd,
		0x85,0x5f,0x08,0x6e,0x3e,0x9d,0x52,0x5b,
		0x46,0xbf,0xe2,0x45,0x11,0x43,0x15,0x32
	};
	static const uint8_t abc[3] = { 0x61, 0x62, 0x63 };
	if (sha3_hash(sha3_out, 32, (uint8_t *)abc, 3, 256, SHA3_SHAKE_NONE) != 0 ||
	    memcmp(sha3_out, sha3_256_abc_exp, 32) != 0) {
		fprintf(stderr, "SHA3-256 KAT (abc) failed!\n");
		return FAIL;
	}
	algTestedFlag.isHashTested = SUCCESS;

	/* ---- HMAC-SHA3-224 KAT: Count=1 from HMAC_SHA3.rsp ---- */
	/* Key  = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)  */
	/* Msg  = "Hi There" (8 bytes)                                    */
	/* Mac  = 3b16546bbc7be2706a031dcafd56373d9884367641d8c59af3c860f7 */
	static const uint8_t hmac_key[20] = {
		0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
		0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
		0x0b,0x0b,0x0b,0x0b
	};
	static const uint8_t hmac_msg[8] = {
		0x48,0x69,0x20,0x54,0x68,0x65,0x72,0x65
	};
	static const uint8_t hmac_exp[28] = {
		0x3b,0x16,0x54,0x6b,0xbc,0x7b,0xe2,0x70,
		0x6a,0x03,0x1d,0xca,0xfd,0x56,0x37,0x3d,
		0x98,0x84,0x36,0x76,0x41,0xd8,0xc5,0x9a,
		0xf3,0xc8,0x60,0xf7
	};
	uint8_t hmac_out[64];
	HMAC_SHA3(hmac_msg, 8, hmac_key, 20, hmac_out, 224);
	if (memcmp(hmac_out, hmac_exp, 28) != 0) {
		fprintf(stderr, "HMAC-SHA3-224 KAT failed!\n");
		return FAIL;
	}
	algTestedFlag.isMACTested = SUCCESS;

	return ret;
}

// External API: returns the current cryptographic module state
EXPORT int KCMVP_GetState() {

	return _getState();
}

// External API: runs the pre-selftest (software integrity check)
EXPORT int KCMVP_PreSelfTest() {
	int ret = SUCCESS;

	ret = _preSelfTest();

	return ret;
}

// External API: runs the algorithm KAT self-test
EXPORT int KCMVP_AlgKATSelfTest() {
	int ret = SUCCESS;

	ret = _AlgKATSelfTest();

	return ret;
}

// Cryptographic module initialization API
EXPORT int KCMVP_Initialize() {

	int ret = 0;

	printf("KCMVP_Initialize()\n");

	_Init();										// Initialize KAT test flags

	gCryptoState = KCMVP_CM_LOAD;					// Module load state initialization
	gCryptoState = KCMVP_CM_PRE_SELFTEST;
	ret = _preSelfTest();                           // Run pre-selftest (integrity check)
	if (ret != SUCCESS) {
		fprintf(stderr, "Preselftest failed!\n");
		gCryptoState = KCMVP_CM_CRITICAL_ERROR;
		goto END;
	}
	fprintf(stderr, "Preselftest succeeded!\n");
	ret = _AlgKATSelfTest();                        // Run core self-test (algorithm KAT)
	if (ret != SUCCESS) {
		gCryptoState = KCMVP_CM_CRITICAL_ERROR;
		goto END;
	}
	gCryptoState = KCMVP_CM_NORMAL;					// Transition to KCMVP normal state

END:

	return ret;
}


// ARIA cipher KCMVP API
EXPORT int KCMVP_ARIA_EncKeySetup(const Byte* w0, Byte* e, int keyBits) {

	int curCryptoState;
	int ret;

	// Check module state; return if not in operational state
	curCryptoState = _getState();

	// Check self-test completion
	if (algTestedFlag.isBlockCipherTested == NOT_INIT) {
		// Call conditional self-test function
		// On error, transition to degraded state
	}

	// Set up encryption key
	ret = EncKeySetup(w0, e, keyBits);

	// On error, zeroize sensitive key material and return error code

	return ret;
}

EXPORT int KCMVP_ARIA_DecKeySetup(const Byte* w0, Byte* d, int keyBits) {
	int curCryptoState;
	int ret;

	// Check module state; return if not in operational state
	curCryptoState = _getState();

	// Set up decryption key
	ret = DecKeySetup(w0, d, keyBits);

	// On error, zeroize sensitive key material and return error code

	return ret;
}

EXPORT void KCMVP_ARIA_Crypt(int dir, int ARIA_MODE, const Byte* iv,
	const Byte* p, int pSize, const Byte* key, int keyBit, Byte* c) {

	int curCryptoState;
	int ret;

	// Check module state
	curCryptoState = _getState();

	// Check self-test completion
	if (algTestedFlag.isBlockCipherTested == NOT_INIT) {
		// Call conditional self-test function
		// On error, transition to degraded state
	}

	// Perform encryption/decryption by mode
	switch (ARIA_MODE) {
	case ARIA_ECB_MODE:
		ARIA_ECB(dir, p, pSize, key, keyBit, c);
		break;
	case ARIA_CBC_MODE:
		ARIA_CBC(dir, iv, p, pSize, key, keyBit, c);
		break;
	case ARIA_CTR_MODE:
		ARIA_CTR(dir, iv, p, pSize, key, keyBit, c);
		break;
	default:
		break;
	}

	// On error, zeroize sensitive key material

}

EXPORT void KCMVP_ARIA_Crypt_Basic(const Byte* p, int R, const Byte* e, Byte* c) {
	int curCryptoState;

	// Check module state
	curCryptoState = _getState();

	// Check self-test completion
	if (algTestedFlag.isBlockCipherTested == NOT_INIT) {
		// Call conditional self-test function
		// On error, transition to degraded state
	}

	// Perform encryption/decryption
	Crypt(p, R, e, c);

	// On error, zeroize sensitive key material
}

EXPORT void KCMVP_ARIA_printBlock(Byte* b, int size) {

	printBlock(b, size);

}
EXPORT void KCMVP_ARIA_printBlockOfLength(Byte* b, int len) {
	printBlockOfLength(b, len);
}

// Test APIs
EXPORT int plus(int a, int b) {
	return (a + b);
}

EXPORT int minus(int a, int b) {
	return (a - b);
}

EXPORT int times(int a, int b) {
	return (a * b);
}

EXPORT int divide(int a, int b) {
	return (a / b);
}

EXPORT void updateGVar(int a) {
	gVar = a;
}

EXPORT int getGVar() {
	return gVar;
}

EXPORT void incGVar() {

	printf("incGVar() called\n");
	gVar += 1;
}

EXPORT void decGVar() {

	printf("decGVar called\n");
	gVar -= 1;
}

/* ------------------------------------------------------------------ */
/* SHA-3 KCMVP wrapper API                                              */
/* ------------------------------------------------------------------ */

/* One-shot SHA-3 hash.
 * Returns 0 on success, FAIL if the module is not in a valid state
 * or the hash KAT has not been verified yet.
 */
EXPORT int KCMVP_SHA3_Hash(uint8_t *output, int outLen,
                            const uint8_t *input, int inLen,
                            int bitSize)
{
	if (_getState() != KCMVP_CM_NORMAL)
		return FAIL;

	if (algTestedFlag.isHashTested != SUCCESS)
		return FAIL;

	return sha3_hash(output, outLen, (uint8_t *)input, inLen,
	                 bitSize, SHA3_SHAKE_NONE);
}

/* HMAC-SHA3.
 * Output buffer (hmac) must be at least (bitSize/8) bytes.
 * Returns 0 on success, FAIL on state or KAT error.
 */
EXPORT int KCMVP_HMAC_SHA3(const uint8_t *message, uint32_t mlen,
                             const uint8_t *key,     uint32_t klen,
                             uint8_t *hmac, int bitSize)
{
	if (_getState() != KCMVP_CM_NORMAL)
		return FAIL;

	if (algTestedFlag.isMACTested != SUCCESS)
		return FAIL;

	HMAC_SHA3(message, mlen, key, klen, hmac, bitSize);
	return 0;
}

// EOF
