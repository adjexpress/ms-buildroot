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

const char* lut_1 = "0123456789abcdef";
const char* lut_2 = "0123456789ABCDEF";

static unsigned int position_in_lut(char ch)
{
	for(int i = 0; i < 16; i++)
		if (ch == lut_1[i])
			return i;
	for(int i = 0; i < 16; i++)
		if (ch == lut_2[i])
			return i;
	return ~0;
}

Int32_t read_rpmb2(const char* rpmb_as_arg, Uint8_t* rpmb2)
{
    if (strlen(rpmb_as_arg) != 32)
    {
        printf("RPBM2 length must be 32 characters!\n"); 
        return -1;
    }

    for(int i = 0; i < 32; i += 2)
	{
		char high = rpmb_as_arg[i + 0];
		char low  = rpmb_as_arg[i + 1];
		unsigned char num = (position_in_lut(high) << 4) | position_in_lut(low);
        rpmb2[i/2] = num;
	}
    return 0;
}