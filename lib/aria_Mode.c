
#include "aria.h"
#include <memory.h>


void
ARIA_ECB(int dir, const Byte* p,
	int pSize,
	const Byte* key,
	int keyBit,
	Byte* c)
{
	int cnt_i;
	unsigned char rk[16 * 17] = { 0x00, };
	int numRounds = 0;
	int numofBlocks = pSize >> 4;			// number of 16-byte blocks in pSize
	unsigned char* ptrP = p;
	unsigned char* ptrC = c;

	if (dir == ARIA_ENCRYPT) {
		numRounds = EncKeySetup(key, rk, keyBit);
	}
	else if (dir == ARIA_DECRYPT) {
		numRounds = DecKeySetup(key, rk, keyBit);
	}

	for (cnt_i = 0; cnt_i < numofBlocks; cnt_i++)
	{
		Crypt(ptrP, numRounds, rk, ptrC);
		ptrP += 16;
		ptrC += 16;
	}
}

/*
* @brief ARIA_CBC mode implementation
* @param const Byte *iv initial vector
* @param const Byte *p plaintext
* @param int pSize length of plaintext
* @param const Byte* key master key
* @param int keyBit bit of master key
* @param Byte* c ciphertext
* @return void
*/
void
ARIA_CBC(int dir, const Byte* iv,
	const Byte* p,
	int pSize,
	const Byte* key,
	int keyBit,
	Byte* c)
{
	int cnt_i = 0, cnt_j = 0;
	int numofBlocks = pSize >> 4;			// number of 16-byte blocks in pSize
	int numRounds = 0;
	unsigned char rk[16 * 17] = { 0x00, };
	unsigned char input[16] = { 0x00, };
	unsigned char CT[16] = { 0x00, };
	unsigned char* ptrP = p;
	unsigned char* ptrC = c;

	if (dir == ARIA_ENCRYPT) {
		numRounds = EncKeySetup(key, rk, keyBit);

		memcpy(CT, iv, 16);

		for (cnt_i = 0; cnt_i < numofBlocks; cnt_i++)
		{
			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				input[cnt_j] = (ptrP[cnt_j] ^ CT[cnt_j]);
			}
			memset(CT, 0, sizeof(CT));
			Crypt(input, numRounds, rk, CT);
			memcpy(ptrC, CT, sizeof(CT));

			ptrP += 16;
			ptrC += 16;
		}
	}
	else if (dir == ARIA_DECRYPT) {
		numRounds = DecKeySetup(key, rk, keyBit);

		// Codes...
	}
}

void incCtr(unsigned char* ctr)
{
	int cnt_i = 0;
	unsigned char carry = 1;		// set initial carry to 1
	unsigned char temp = 0;

	for (cnt_i = 15; cnt_i >= 0; cnt_i--)
	{
		temp = ctr[cnt_i] + carry;
		if (temp < ctr[cnt_i])
		{
			carry = 1;
		}
		else
		{
			carry = 0;
		}
		ctr[cnt_i] = temp;
	}
}

void ARIA_CTR(int dir, const Byte* iv,
	const Byte* p,
	int pSize,
	const Byte* key,
	int keyBit,
	Byte* c)
{
	int cnt_i = 0, cnt_j = 0;
	int numofBlocks = pSize >> 4;			// number of 16-byte blocks in pSize
	int numRounds = 0;
	unsigned char rk[16 * 17] = { 0x00, };
	unsigned char ctr[16] = { 0x00, };
	unsigned char CT[16] = { 0x00, };
	unsigned char* ptrP = p;
	unsigned char* ptrC = c;

	memcpy(ctr, iv, 16);		// initialize counter

	if (dir == ARIA_ENCRYPT) {
		numRounds = EncKeySetup(key, rk, keyBit);

		for (cnt_i = 0; cnt_i < numofBlocks; cnt_i++)
		{
			memset(CT, 0, sizeof(CT));
			Crypt(ctr, numRounds, rk, CT);

			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				CT[cnt_j] ^= ptrP[cnt_j];
			}

			memcpy(ptrC, CT, sizeof(CT));

			ptrP += 16;
			ptrC += 16;

			// update counter
			incCtr(ctr);
		}
	}
	else if (dir == ARIA_DECRYPT) {
		numRounds = DecKeySetup(key, rk, keyBit);

		// Codes...
	}
}

void ARIA_CFB64(int dir, const Byte* iv,
	const Byte* p,
	int pSize,
	const Byte* key,
	int keyBit,
	Byte* c)
{
	int cnt_i = 0, cnt_j = 0;
	int numofBlocks = pSize >> 3;			// number of 8-byte blocks in pSize
	int numRounds = 0;
	unsigned char rk[16 * 17] = { 0x00, };
	unsigned char input[16] = { 0x00, };
	unsigned char CF[16] = { 0x00, };
	unsigned char CT[8] = { 0x00, };
	unsigned char* ptrP = p;
	unsigned char* ptrC = c;

	memcpy(input, iv, 16);

	if (dir == ARIA_ENCRYPT) {
		numRounds = EncKeySetup(key, rk, keyBit);

		for (cnt_i = 0; cnt_i < numofBlocks; cnt_i++)
		{
			memset(CF, 0, sizeof(CF));
			memset(CT, 0, sizeof(CT));

			Crypt(input, numRounds, rk, CF);

			for (cnt_j = 0; cnt_j < 8; cnt_j++)
			{
				CT[cnt_j] = (ptrP[cnt_j] ^ CF[cnt_j]);
			}

			memcpy(ptrC, CT, sizeof(CT));

			ptrP += 8;
			ptrC += 8;

			// CF update
			for (cnt_j = 0; cnt_j < 8; cnt_j++)
			{
				input[cnt_j] = input[cnt_j + 8];
			}
			for (cnt_j = 8; cnt_j < 16; cnt_j++)
			{
				input[cnt_j] = CT[cnt_j - 8];
			}
		}

	}
	else if (dir == ARIA_DECRYPT) {
		numRounds = DecKeySetup(key, rk, keyBit);

		// Codes...
	}
}

void ARIA_OFB(int dir, const Byte* iv,
	const Byte* p,
	int pSize,
	const Byte* key,
	int keyBit,
	Byte* c)
{
	int cnt_i = 0, cnt_j = 0;
	int numofBlocks = pSize >> 4;			// number of 16-byte blocks in pSize
	int numRounds = 0;
	unsigned char rk[16 * 17] = { 0x00, };
	unsigned char input[16] = { 0x00, };
	unsigned char OF[16] = { 0x00, };
	unsigned char CT[16] = { 0x00, };
	unsigned char* ptrP = p;
	unsigned char* ptrC = c;

	memcpy(input, iv, 16);

	if (dir == ARIA_ENCRYPT) {
		numRounds = EncKeySetup(key, rk, keyBit);

		for (cnt_i = 0; cnt_i < numofBlocks; cnt_i++)
		{
			memset(OF, 0, sizeof(OF));
			memset(CT, 0, sizeof(CT));

			Crypt(input, numRounds, rk, OF);

			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				CT[cnt_j] = (ptrP[cnt_j] ^ OF[cnt_j]);
			}

			memcpy(ptrC, CT, sizeof(CT));

			ptrP += 16;
			ptrC += 16;

			memcpy(input, OF, sizeof(OF));
		}

	}
	else if (dir == ARIA_DECRYPT) {
		numRounds = DecKeySetup(key, rk, keyBit);

		// Codes...
	}
}

// EOF
