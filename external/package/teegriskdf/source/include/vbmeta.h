#ifndef _VBMETA__H__
#define _VBMETA__H__

#include "core.h"

typedef struct _VBMETA_HEADER {
    Uint8_t  magic[4];
    Uint32_t libavb_version_major;
    Uint32_t libavb_version_minor;
    Uint64_t sizeof_auth_data;
    Uint64_t sizeof_aux_data;
    Uint32_t algorithm;
    Uint64_t hash_offset;
    Uint64_t hash_size;
    Uint64_t signature_offset;
    Uint64_t signature_size;
    Uint64_t public_key_offset;
    Uint64_t public_key_size;
    Uint64_t public_key_metadata_offset;
    Uint64_t public_key_metadata_size;
    Uint64_t descriptors_offset;
    Uint64_t descriptors_size;
    Uint64_t rollback_index;
    Uint32_t flags;
    Uint32_t rollback_index_location;
    Uint8_t  release_string[48];
    Uint8_t  reserved[80];
} __attribute__((packed)) VBMETA_HEADER; // 256 bytes

typedef struct _VBMETA_PUBLIC_KEY {
    Uint32_t key_num_bits; // it must be devided by 8 to give number of bytes for 'n' and 'rr' quantities
    Uint32_t n0inv;        // it is a computed value and we forget it
} __attribute__((packed)) VBMETA_PUBLIC_KEY; // 8 bytes
/* right after this header comes 'key_num_bits / 8' bytes for n and 
   then comes 'key_num_bits / 8' bytes for rr */

// parse VBMETA header
void           parse_vbmeta_header   (VBMETA_HEADER* vh);
Uint8_t* vbmeta_read_file_content    (const char* vbmeta_address);
Uint8_t* assign_vbmeta_public_key    (Uint8_t* vbmeta_data);
Uint8_t* calculate_vbmeta_public_key (Uint8_t* vbmeta_public_key_data, Uint32_t* n_bytes);

#endif //! _VBMETA__H__