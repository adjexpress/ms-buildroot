#ifndef _RPMB2__H__
#define _RPMB2__H__

#include "core.h"

// reads data from rpmb2.bin file
Int32_t read_rpmb2_file(const char* rpmb_address, Uint8_t* rpmb2);
Int32_t read_rpmb2(const char* rpmb_as_arg, Uint8_t* rpmb2);

#endif //! _RPMB2__H__