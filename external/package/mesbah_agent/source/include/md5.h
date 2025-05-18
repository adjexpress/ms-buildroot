#ifndef _MD5__H__
#define _MD5__H__

#		include <stdio.h>
#		include <stdint.h>
#		include <string.h>
#		include <stdlib.h>

/// data structure for MD5 context to hold size, result of algorithm, input, etc.
///
typedef struct _MD5Context {
    unsigned long long size;       // Size of input in bytes
    unsigned int       buffer[4];  // Current accumulation of hash
    unsigned char      input [64]; // Input to be used in the next step
    unsigned char      digest[16]; // Result of algorithm
} MD5Context;

/// data structure for MD5 context to hold size, result of algorithm, input, etc.
/// @param ctx -> a pointer to an already initialized MD5Context
/// @return nothing
///
void md5Init     (MD5Context* ctx);

/// Adds some amount of input to the context. If the input fills out a block of 512 bits, apply the algorithm (md5Step)
/// and save the result in the buffer. Also updates the overall size.
/// @param ctx -> a pointer to an already initialized MD5Context
/// @param input_len -> the amount of input to be added to the context
/// @return nothing
///
void md5Update   (MD5Context* ctx, unsigned char* input, size_t input_len);

/// Pads the current input to get to 448 bytes, append the size in bits to the very end,
/// and save the result of the final iteration into digest.
/// @param ctx -> a pointer to an already initialized MD5Context
/// @return nothing
///
void md5Finalize (MD5Context* ctx);

/// Step on 512 bits of input with the main MD5 algorithm
/// @param buffer -> 
/// @param input -> 
/// @return nothing
///
void md5Step     (unsigned int* buffer, unsigned int* input);

/// Functions that run the algorithm on the provided input and put the digest into result. result should be able to store 16 bytes
/// @param input -> input buffer
/// @param result -> buffer to store data in
/// @return nothing
///
void md5String   (char* input, unsigned char* result);

/// data structure for MD5 context to hold size, result of algorithm, input, etc.
/// @param file -> file containing input buffer
/// @see md5String
/// @param result -> buffer to store data in
/// @return nothing
///
void md5File     (FILE* file, unsigned char* result);

#endif //!_MD5__H__
