#include "../include/math.h"

void xor_16_bytes_arrays(Uint8_t* output, Uint8_t* input, Uint8_t* xor)
{
    CLEAR_BLOCK_0x10(output);
    for (size_t i = 0; i < BLOCK_SIZE_0x10; i++)
        output[i] = input[i] ^ xor[i];
}

