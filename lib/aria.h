#pragma once

typedef unsigned char Byte;

enum ARIA_MODE {
	ARIA_ECB_MODE,
	ARIA_CBC_MODE,
	ARIA_CTR_MODE
};

enum ARIA_DIRECTION {
	ARIA_ENCRYPT,
	ARIA_DECRYPT
};

// Basic functions
int EncKeySetup(const Byte* w0, Byte* e, int keyBits);
int DecKeySetup(const Byte* w0, Byte* d, int keyBits);
void RotXOR(const Byte* s, int n, Byte* t);
void DL(const Byte* i, Byte* o);
void Crypt(const Byte* p, int R, const Byte* e, Byte* c);

void printBlock(Byte* b, int size);
void printBlockOfLength(Byte* b, int len);

// Modes of operation
void ARIA_ECB(int dir, const Byte* p, int pSize, const Byte* key, int keyBit, Byte* c);
void ARIA_CBC(int dir, const Byte* iv, const Byte* p, int pSize, const Byte* key, int keyBit, Byte* c);
void ARIA_CTR(int dir, const Byte* iv, const Byte* p, int pSize, const Byte* key, int keyBit, Byte* c);
void ARIA_CFB64(int dir, const Byte* iv, const Byte* p, int pSize, const Byte* key, int keyBit, Byte* c);
void ARIA_OFB(int dir, const Byte* iv, const Byte* p, int pSize, const Byte* key, int keyBit, Byte* c);

// EOF