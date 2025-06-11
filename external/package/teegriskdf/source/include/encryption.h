#ifndef _ENCRYPTION__H__
#define _ENCRYPTION__H__

#include "core.h"
#include "../openssl/aes.h"
#include "../openssl/evp.h"
#include "../openssl/aes.h"
#include "../openssl/sha.h"
#include "../openssl/kdf.h"

// performing AES-128-ECB on buffer inside data with buffer inside key and returning the result as a vector_0x10
vector_0x10 aes_128_ecb(const vector_0x10* key, const vector_0x10* data);

// performing SHA256 on data into output buffer
int sha256_encrypt(Uint8_t* output, const Uint8_t* data, Uint64_t size);

// performing SHA512 on data into output buffer
int sha512_encrypt(Uint8_t* output, const Uint8_t* data, Uint64_t size);

// performing AES-GCM-256
Int32_t gcm_decrypt(Uint8_t* source, 
                    Uint8_t* target, 
                    Uint8_t* aad, 
                    Uint8_t* iv, 
                    Uint8_t* tag, 
                    Uint8_t* key, 
                    Uint32_t source_size,
                    Uint32_t aad_size,
                    Uint32_t iv_size,
                    Uint32_t tag_size,
                    Uint32_t key_size);

// decrypte file 'encrypted_key' file contents
Int32_t decrypt_encrypted_key(const char* encrypted_key_address, Uint8_t* key, Uint8_t* out);


#endif //! _ENCRYPTION__H__
