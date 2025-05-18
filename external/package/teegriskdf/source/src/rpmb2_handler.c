#include "../include/rpmb2.h"

Int32_t read_rpmb2_file(const char* rpmb_address, Uint8_t* rpmb2)
{
    FILE* rpmb_f = fopen(rpmb_address, "rb");
    if (NULL == rpmb_f)
    { 
        printf("RPBM2 File Not Found!\n"); 
        return -1; 
    }
    fseek(rpmb_f, 0L, SEEK_END);
    Uint64_t rpmb_file_size = ftell(rpmb_f);
    fseek(rpmb_f, 0L, SEEK_SET);    
    size_t data_read = fread(rpmb2, 1, rpmb_file_size, rpmb_f);
    if (data_read != rpmb_file_size)
    { 
        printf("RPMB2 data read was incorrect!\n"); 
        return -2; 
    }
    fclose(rpmb_f);
    return 0;
}