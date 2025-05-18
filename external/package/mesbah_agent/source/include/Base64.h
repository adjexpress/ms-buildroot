#ifndef _BASE64__H__
#define _BASE64__H__

#include <stdint.h>
#include <stdlib.h>

/// encodes a buffer to the corresponding base-64
/// @param data
/// @param input_length
/// @param output_length
/// @return char* -> buffer containing the data of base 64
///
char* base64_encode        (char* data, size_t input_length, size_t* output_length);

/// decodes a base-64 buffer to the corresponding plain bytes
/// @param data
/// @param input_length
/// @param output_length
/// @return char* -> buffer containing the plain data
///
char* base64_decode        (char* data, size_t input_length, size_t* output_length);

/// construct the base 64 table
/// @param nothing
/// @return nothing
///
void  build_decoding_table ();

/// destruct the base 64 table
/// @param nothing
/// @return nothing
///
void  base64_cleanup       ();

#endif //!_BASE64__H__