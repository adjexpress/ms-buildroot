#ifndef _CORE__H__
#define _CORE__H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRUE  1
#define FALSE 0

#define HDK_LOG(PRIORITY, FORMATTED_MSG, ...) do { \
    if (PRIORITY == FALSE)                         \
        ;                                          \
    else if (PRIORITY == TRUE)                     \
        printf((FORMATTED_MSG), ##__VA_ARGS__);    \
    else                                           \
        ;                                          \
} while(FALSE);

#define __DEPRECATED_FUNCTION__

#define BLOCK_SIZE_0x10 0x10
#define BLOCK_SIZE_0x20 0x20
#define BLOCK_SIZE_0x40 0x40
#define CLEAR_BLOCK_0x10(BUFF)  memset(BUFF, 0, BLOCK_SIZE_0x10)
#define COPY_BLOCK_0x10(p1, p2) memcpy(p1, p2, BLOCK_SIZE_0x10)
#define CLEAR_BLOCK_0x20(BUFF)  memset(BUFF, 0, BLOCK_SIZE_0x20)
#define COPY_BLOCK_0x20(p1, p2) memcpy(p1, p2, BLOCK_SIZE_0x20)
#define CLEAR_BLOCK_0x40(BUFF)  memset(BUFF, 0, BLOCK_SIZE_0x40)
#define COPY_BLOCK_0x40(p1, p2) memcpy(p1, p2, BLOCK_SIZE_0x40)

typedef unsigned int       Boolean;
typedef char               Int8_t;
typedef short              Int16_t;
typedef int                Int32_t;
typedef long long          Int64_t;
typedef unsigned char      Uint8_t;
typedef unsigned short     Uint16_t;
typedef unsigned int       Uint32_t;
typedef unsigned long long Uint64_t;

typedef struct _vector_0x10 {
    Uint8_t data[BLOCK_SIZE_0x10];
    size_t  size;
} vector_0x10;

typedef struct _ROT {
    Uint8_t asn1_sequence;      // 0x30
    Uint8_t asn1_length;        // 0x4A
    Uint8_t t1;                 // 0x04
    Uint8_t l1;                 // 0x20
    Uint8_t vbmeta_pub_key[32]; // must be calculated from parsing VBMETA
    Uint8_t t2;                 // 0x01
    Uint8_t l2;                 // 0x01
    Uint8_t boolean_type;       // 0xFF = true | 0x00 = false
    Uint8_t t3;                 // 0x0A
    Uint8_t l3;                 // 0x01
    Uint8_t enumerated_type;    // 0x00 or 0x02
    Uint8_t t4;                 // 0x04
    Uint8_t l4;                 // 0x20
    Uint8_t reserved[32];       // all 0x00
} __attribute__ ((packed)) ROT; // 76 bytes

// dump in HEX, buffer 'buffer' with size 'size' with priority to log in stdout. FALSE (do not log), TRUE (log it)
void dump_buffer(Boolean priority, Uint8_t* buffer, size_t size);

// dump in HEX, buffer 'buffer' with size 'size'
void raw_dump_buffer(Uint8_t* buffer, size_t size);

// allocationg a buffer with length 'size' bytes and putting 'value' in all bytes
void* Alloc(size_t size, Uint8_t value);

// safely free out an allocated pointer
void safe_free(void* p);

// changing endianness of a uint8_t
Uint16_t change_endianness_16(Uint16_t n);

// changing endianness of a uint32_t
Uint32_t change_endianness_32(Uint32_t n);

// changing endianness of a uint64_t
Uint64_t change_endianness_64(Uint64_t n);

// easily compare byte by byte two hex buffers
Int32_t slugish_compare(void* _b1, void* _b2, size_t size);

// copy data from src to trg starting from 'start_offset' until 'end_offset'
void CopyData(void* trg, size_t start_offset, size_t end_offset, void* src);

#endif //! _CORE__H__
