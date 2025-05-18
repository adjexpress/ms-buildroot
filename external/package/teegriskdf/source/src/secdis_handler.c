#include "../include/secdis.h"

Uint8_t* handle_secdiscardable_file(const char* secdiscardable_address)
{
    Uint8_t sha512[32] = "Android secdiscardable SHA512";

    FILE* secdis = fopen(secdiscardable_address, "rb");
    if(!secdis)
    {
        printf("ERROR -> opening %s failed\n", secdiscardable_address);
        return NULL;
    }
    Uint64_t secdiscardable_size = 0;

    fseek(secdis, 0L, SEEK_END);
    secdiscardable_size = (Uint64_t)ftell(secdis);
    fseek(secdis, 0L, SEEK_SET);

    if (secdiscardable_size == 0)
    {
        printf("ERROR -> size %s is zero\n", secdiscardable_address);
        return NULL;
    }
    if (secdiscardable_size > (16512 - 32))
    {
        printf("ERROR -> size %s is exceeded the max possible\n", secdiscardable_address);
        return NULL;
    }

    Uint8_t* secdis_buffer = Alloc(16512, 0);
    Uint32_t offset        = 16512 - secdiscardable_size;
    fread(&secdis_buffer[offset], secdiscardable_size, 1, secdis);
    fclose(secdis);    

    memcpy(secdis_buffer, sha512, BLOCK_SIZE_0x20);
    return secdis_buffer;
}


