#ifndef _CUSTOM_ASN1__H__
#define _CUSTOM_ASN1__H__

#include "core.h"
#include "../openssl/asn1.h"

typedef enum _KM_ASN1_TAGS {
    KM_IV_TAG             = 0x88130090,
    KM_AUTH_TAG_TAG       = 0x89130090,
    KM_HEK_RANDOMNESS_TAG = 0x92130090,
} KM_ASN1_TAGS;


__DEPRECATED_FUNCTION__ Int32_t parse_keymaster_key_blob_encrypted_data_asn1_v1(Uint8_t* data, 
                                                                                Uint32_t data_length,
                                                                                Uint8_t* encrypted_key_file_key);

__DEPRECATED_FUNCTION__ Int32_t parse_keymaster_key_blob_asn1_iv_tag_aad(Uint8_t* buffer, 
                                                                         Uint32_t buffer_length,
                                                                         Uint8_t* iv,
                                                                         Uint8_t* tag,
                                                                         Uint8_t* aad);

__DEPRECATED_FUNCTION__ Int32_t parse_keymaster_key_blob_asn1_v1(Uint8_t*  keymaster_key_blob_asn1_buffer, 
                                                                 Uint32_t  keymaster_key_blob_asn1_buffer_length,
                                                                 Uint8_t*  encrypted_data,
                                                                 Uint32_t* encrypted_data_length,
                                                                 Uint8_t*  iv,
                                                                 Uint8_t*  tag,
                                                                 Uint8_t*  aad);

// deserialize ASN1 content of 'keymaster_key_blob' file, recurseively

Int32_t parse_keymaster_key_blob_asn1_v2(Uint8_t*  keymaster_key_blob_asn1_buffer, 
                                         Uint32_t  keymaster_key_blob_asn1_buffer_length,
                                         Uint8_t*  encrypted_data,
                                         Uint32_t* encrypted_data_length,
                                         Uint8_t*  iv_data,
                                         Uint8_t*  tag_data,
                                         Uint8_t*  aad_data);

// deserialize ASN1 content of 'encrypted_key' file, recurseively
Int32_t parse_keymaster_key_blob_encrypted_data_asn1_v2(Uint8_t* data, 
                                                        Uint32_t data_length,
                                                        Uint8_t* encrypted_key_file_key);

#endif //! _CUSTOM_ASN1__H__
