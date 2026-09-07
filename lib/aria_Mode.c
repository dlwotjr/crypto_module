#include <stddef.h>
#include <string.h>

#include "aria.h"

#define ARIA_BLOCK_SIZE 16
#define ARIA_ROUND_KEY_SIZE (16 * 17)

static void secure_zero(void *ptr, size_t len)
{
    volatile Byte *p = (volatile Byte *)ptr;

    while (len-- > 0)
        *p++ = 0;
}

static int valid_key_bits(int key_bits)
{
    return key_bits == 128 || key_bits == 192 || key_bits == 256;
}

static int valid_direction(int direction)
{
    return direction == ARIA_ENCRYPT || direction == ARIA_DECRYPT;
}

int ARIA_ECB(int direction, const Byte *input, int input_size,
             const Byte *key, int key_bits, Byte *output)
{
    Byte round_keys[ARIA_ROUND_KEY_SIZE];
    int rounds;
    int offset;

    if (!valid_direction(direction) || input == NULL || key == NULL ||
        output == NULL || input_size <= 0 ||
        (input_size % ARIA_BLOCK_SIZE) != 0 || !valid_key_bits(key_bits))
        return ARIA_MODE_ERROR;

    rounds = direction == ARIA_ENCRYPT ?
        EncKeySetup(key, round_keys, key_bits) :
        DecKeySetup(key, round_keys, key_bits);
    if (rounds <= 0) {
        secure_zero(round_keys, sizeof(round_keys));
        return ARIA_MODE_ERROR;
    }

    for (offset = 0; offset < input_size; offset += ARIA_BLOCK_SIZE)
        Crypt(input + offset, rounds, round_keys, output + offset);

    secure_zero(round_keys, sizeof(round_keys));
    return ARIA_MODE_SUCCESS;
}

int ARIA_CBC(int direction, const Byte *iv, const Byte *input, int input_size,
             const Byte *key, int key_bits, Byte *output)
{
    Byte round_keys[ARIA_ROUND_KEY_SIZE];
    Byte chain[ARIA_BLOCK_SIZE];
    Byte block[ARIA_BLOCK_SIZE];
    Byte ciphertext[ARIA_BLOCK_SIZE];
    int rounds;
    int offset;
    int i;

    if (!valid_direction(direction) || iv == NULL || input == NULL ||
        key == NULL || output == NULL || input_size <= 0 ||
        (input_size % ARIA_BLOCK_SIZE) != 0 || !valid_key_bits(key_bits))
        return ARIA_MODE_ERROR;

    rounds = direction == ARIA_ENCRYPT ?
        EncKeySetup(key, round_keys, key_bits) :
        DecKeySetup(key, round_keys, key_bits);
    if (rounds <= 0) {
        secure_zero(round_keys, sizeof(round_keys));
        return ARIA_MODE_ERROR;
    }

    memcpy(chain, iv, sizeof(chain));
    for (offset = 0; offset < input_size; offset += ARIA_BLOCK_SIZE) {
        if (direction == ARIA_ENCRYPT) {
            for (i = 0; i < ARIA_BLOCK_SIZE; i++)
                block[i] = input[offset + i] ^ chain[i];
            Crypt(block, rounds, round_keys, output + offset);
            memcpy(chain, output + offset, sizeof(chain));
        } else {
            memcpy(ciphertext, input + offset, sizeof(ciphertext));
            Crypt(ciphertext, rounds, round_keys, block);
            for (i = 0; i < ARIA_BLOCK_SIZE; i++)
                output[offset + i] = block[i] ^ chain[i];
            memcpy(chain, ciphertext, sizeof(chain));
        }
    }

    secure_zero(round_keys, sizeof(round_keys));
    secure_zero(chain, sizeof(chain));
    secure_zero(block, sizeof(block));
    secure_zero(ciphertext, sizeof(ciphertext));
    return ARIA_MODE_SUCCESS;
}

static void increment_counter(Byte counter[ARIA_BLOCK_SIZE])
{
    int i;

    for (i = ARIA_BLOCK_SIZE - 1; i >= 0; i--) {
        counter[i]++;
        if (counter[i] != 0)
            break;
    }
}

int ARIA_CTR(int direction, const Byte *iv, const Byte *input, int input_size,
             const Byte *key, int key_bits, Byte *output)
{
    Byte round_keys[ARIA_ROUND_KEY_SIZE];
    Byte counter[ARIA_BLOCK_SIZE];
    Byte stream[ARIA_BLOCK_SIZE];
    int rounds;
    int offset;

    if (!valid_direction(direction) || iv == NULL || input == NULL ||
        key == NULL || output == NULL || input_size <= 0 ||
        !valid_key_bits(key_bits))
        return ARIA_MODE_ERROR;

    /* CTR encryption and decryption both use the block-cipher encryption key. */
    rounds = EncKeySetup(key, round_keys, key_bits);
    if (rounds <= 0) {
        secure_zero(round_keys, sizeof(round_keys));
        return ARIA_MODE_ERROR;
    }

    memcpy(counter, iv, sizeof(counter));
    for (offset = 0; offset < input_size; offset += ARIA_BLOCK_SIZE) {
        int remaining = input_size - offset;
        int block_size = remaining < ARIA_BLOCK_SIZE ? remaining : ARIA_BLOCK_SIZE;
        int i;

        Crypt(counter, rounds, round_keys, stream);
        for (i = 0; i < block_size; i++)
            output[offset + i] = input[offset + i] ^ stream[i];
        increment_counter(counter);
    }

    secure_zero(round_keys, sizeof(round_keys));
    secure_zero(counter, sizeof(counter));
    secure_zero(stream, sizeof(stream));
    return ARIA_MODE_SUCCESS;
}

/* Legacy non-public modes retained from the course code. */
void ARIA_CFB64(int direction, const Byte *iv, const Byte *input,
                int input_size, const Byte *key, int key_bits, Byte *output)
{
    Byte round_keys[ARIA_ROUND_KEY_SIZE];
    Byte feedback[ARIA_BLOCK_SIZE];
    Byte stream[ARIA_BLOCK_SIZE];
    Byte ciphertext[8];
    int rounds;
    int offset;
    int i;

    if (direction != ARIA_ENCRYPT || iv == NULL || input == NULL ||
        key == NULL || output == NULL || input_size <= 0 ||
        (input_size % 8) != 0 || !valid_key_bits(key_bits))
        return;

    rounds = EncKeySetup(key, round_keys, key_bits);
    if (rounds <= 0)
        return;

    memcpy(feedback, iv, sizeof(feedback));
    for (offset = 0; offset < input_size; offset += 8) {
        Crypt(feedback, rounds, round_keys, stream);
        for (i = 0; i < 8; i++)
            ciphertext[i] = input[offset + i] ^ stream[i];
        memcpy(output + offset, ciphertext, sizeof(ciphertext));
        memmove(feedback, feedback + 8, 8);
        memcpy(feedback + 8, ciphertext, sizeof(ciphertext));
    }

    secure_zero(round_keys, sizeof(round_keys));
    secure_zero(feedback, sizeof(feedback));
    secure_zero(stream, sizeof(stream));
    secure_zero(ciphertext, sizeof(ciphertext));
}

void ARIA_OFB(int direction, const Byte *iv, const Byte *input,
              int input_size, const Byte *key, int key_bits, Byte *output)
{
    Byte round_keys[ARIA_ROUND_KEY_SIZE];
    Byte feedback[ARIA_BLOCK_SIZE];
    Byte stream[ARIA_BLOCK_SIZE];
    int rounds;
    int offset;
    int i;

    if (direction != ARIA_ENCRYPT || iv == NULL || input == NULL ||
        key == NULL || output == NULL || input_size <= 0 ||
        (input_size % ARIA_BLOCK_SIZE) != 0 || !valid_key_bits(key_bits))
        return;

    rounds = EncKeySetup(key, round_keys, key_bits);
    if (rounds <= 0)
        return;

    memcpy(feedback, iv, sizeof(feedback));
    for (offset = 0; offset < input_size; offset += ARIA_BLOCK_SIZE) {
        Crypt(feedback, rounds, round_keys, stream);
        for (i = 0; i < ARIA_BLOCK_SIZE; i++)
            output[offset + i] = input[offset + i] ^ stream[i];
        memcpy(feedback, stream, sizeof(feedback));
    }

    secure_zero(round_keys, sizeof(round_keys));
    secure_zero(feedback, sizeof(feedback));
    secure_zero(stream, sizeof(stream));
}
