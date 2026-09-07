#include <stddef.h>
#include <stdint.h>

int kcmvp_internal_randombytes(uint8_t *output, size_t output_len);

int PQCLEAN_randombytes(uint8_t *output, size_t output_len)
{
    return kcmvp_internal_randombytes(output, output_len);
}
