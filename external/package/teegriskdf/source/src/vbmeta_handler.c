#include "../include/vbmeta.h"

void parse_vbmeta_header(VBMETA_HEADER* vh)
{
    printf("libavb_version_major: 0x%llx\n"       , change_endianness_64(vh->libavb_version_major)         );
    printf("libavb_version_minor: 0x%llx\n"       , change_endianness_64(vh->libavb_version_minor)         );
    printf("sizeof_auth_data: 0x%llx\n"           , change_endianness_64(vh->sizeof_auth_data)             );
    printf("sizeof_aux_data: 0x%llx\n"            , change_endianness_64(vh->sizeof_aux_data)              );
    printf("algorithm: 0x%llx\n"                  , change_endianness_64(vh->algorithm)                    );
    printf("hash_offset: 0x%llx\n"                , change_endianness_64(vh->hash_offset)                  );
    printf("hash_size: 0x%llx\n"                  , change_endianness_64(vh->hash_size)                    );
    printf("signature_offset: 0x%llx\n"           , change_endianness_64(vh->signature_offset)             );
    printf("signature_size: 0x%llx\n"             , change_endianness_64(vh->signature_size)               );
    printf("public_key_offset: 0x%llx\n"          , change_endianness_64(vh->public_key_offset)            );
    printf("public_key_size: 0x%llx\n"            , change_endianness_64(vh->public_key_size)              );
    printf("public_key_metadata_offset: 0x%llx\n" , change_endianness_64(vh->public_key_metadata_offset)   );
    printf("public_key_metadata_size: 0x%llx\n"   , change_endianness_64(vh->public_key_metadata_size)     );
    printf("descriptors_offset: 0x%llx\n"         , change_endianness_64(vh->descriptors_offset)           );
    printf("descriptors_size: 0x%llx\n"           , change_endianness_64(vh->descriptors_size)             );
    printf("rollback_index: 0x%llx\n"             , change_endianness_64(vh->rollback_index)               );
    printf("flags: 0x%llx\n"                      , change_endianness_64(vh->flags)                        );
    printf("rollback_index_location: 0x%llx\n"    , change_endianness_64(vh->rollback_index_location)      );
}

Uint8_t* vbmeta_read_file_content(const char* vbmeta_address)
{
    FILE* vbmeta = fopen(vbmeta_address, "rb");
    if(!vbmeta)
    {
        printf("ERROR -> opening %s failed\n", vbmeta_address);
        return NULL;
    }
    Uint64_t vbmeta_size = 0;

    fseek(vbmeta, 0L, SEEK_END);
    vbmeta_size = (Uint64_t)ftell(vbmeta);
    fseek(vbmeta, 0L, SEEK_SET);

    if (vbmeta_size == 0)
    {
        printf("ERROR -> size %s is zero\n", vbmeta_address);
        return NULL;
    }

    Uint8_t* vbmeta_data = Alloc(vbmeta_size, 0);
    fread(vbmeta_data, vbmeta_size, 1, vbmeta);
    fclose(vbmeta);

    return vbmeta_data;
}

Uint8_t* assign_vbmeta_public_key(Uint8_t* vbmeta_data)
{
    VBMETA_HEADER* v = (VBMETA_HEADER*)vbmeta_data;
    Uint64_t vbmeta_public_key_size = change_endianness_64(v->public_key_size);
    Uint64_t vbmeta_public_key_offset = change_endianness_64(v->public_key_offset);
    Uint8_t* vbmeta_public_key_data = malloc(vbmeta_public_key_size);
    memcpy(vbmeta_public_key_data, &vbmeta_data[sizeof(VBMETA_HEADER) + change_endianness_64(v->sizeof_auth_data) + vbmeta_public_key_offset], vbmeta_public_key_size);
    return vbmeta_public_key_data;
}

Uint8_t* calculate_vbmeta_public_key(Uint8_t* vbmeta_public_key_data, Uint32_t* n_bytes)
{
    VBMETA_PUBLIC_KEY* pk = (VBMETA_PUBLIC_KEY*)vbmeta_public_key_data;
    *n_bytes  = change_endianness_32(pk->key_num_bits >> 3); 
    Uint32_t rr_bytes = *n_bytes;
    Uint8_t* n = malloc(*n_bytes);
    memset(n, 0, *n_bytes);
    memcpy(n, vbmeta_public_key_data + sizeof(VBMETA_PUBLIC_KEY), *n_bytes);
    return n;
}