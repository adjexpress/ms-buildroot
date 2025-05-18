#include "../include/keymaster_key_blob.h"

Uint8_t* read_keymaster_key_blob_file(const char* keymaster_key_blob_address, Uint64_t* kkb_size)
{
    FILE* kkb = fopen(keymaster_key_blob_address, "rb");
    if(!kkb)
    {
        printf("ERROR -> opening %s failed\n", keymaster_key_blob_address);
        return NULL;
    }

    fseek(kkb, 0L, SEEK_END);
    *kkb_size = (Uint64_t)ftell(kkb);
    fseek(kkb, 0L, SEEK_SET);

    if (*kkb_size == 0)
    {
        printf("ERROR -> size %s is zero\n", keymaster_key_blob_address);
        return NULL;
    }
    Uint8_t* kkb_buffer = Alloc(*kkb_size, 0);
    fread(kkb_buffer, *kkb_size, 1, kkb);
    fclose(kkb);
    return kkb_buffer;
}

Uint8_t* get_ukdm(Uint8_t* kkb_buffer, Uint64_t kkb_size)
{
    Uint8_t* ptr = kkb_buffer;
    Uint8_t  find_ukdm_tag[12] = { 0x30, 0x1a, 0x02, 0x04, 0x90, 0x00, 0x13, 0x92, 0xa1, 0x12, 0x04, 0x10 };
    Uint32_t index = 0;
    Uint8_t* ukdm = Alloc(BLOCK_SIZE_0x10, 0);
    Boolean found = FALSE;
    while(index < kkb_size - BLOCK_SIZE_0x10)
    {
        Int32_t cmp = slugish_compare(ptr, find_ukdm_tag, 12);
        if (cmp == 1)
        {
            memcpy(ukdm, (void*)(ptr + 12), BLOCK_SIZE_0x10);
            safe_free(kkb_buffer);
            found = TRUE;
            break;
        }
        ptr++;
        index++;
    }
    if (found == FALSE)
        return NULL;
    return ukdm;
}