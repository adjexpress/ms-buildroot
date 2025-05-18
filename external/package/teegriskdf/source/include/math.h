#ifndef _MATH__H__
#define _MATH__H__

#include "core.h"

typedef struct _XOR_STRING {
    Uint8_t xor_key_1  [BLOCK_SIZE_0x10];
    Uint8_t xor_key_2  [BLOCK_SIZE_0x10];
    Uint8_t xor_key_i  [6 * BLOCK_SIZE_0x10];
    Uint8_t final_xor_1[BLOCK_SIZE_0x10];
    Uint8_t final_xor_2[BLOCK_SIZE_0x10];
} __attribute__((packed)) XOR_STRING; //  160 bytes

typedef struct _HDK {
    Uint8_t encryption_key_value_1[BLOCK_SIZE_0x10];
    Uint8_t encryption_key_value_2[BLOCK_SIZE_0x10];
    Uint8_t hdk                   [BLOCK_SIZE_0x20];
} __attribute__((packed)) HDK; //  64 bytes

// perform xor operation on 16 bytes of 'input' bytes with 'xor' bytes and save them in 'output' bytes
void xor_16_bytes_arrays(Uint8_t* output, Uint8_t* input, Uint8_t* xor);

#endif //! _MATH__H__
