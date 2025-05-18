#ifndef _KKB__H__
#define _KKB__H__

#include "core.h"

Uint8_t* read_keymaster_key_blob_file (const char* keymaster_key_blob_address, Uint64_t* kkb_size);
Uint8_t* get_ukdm                     (Uint8_t* kkb_buffer, Uint64_t kkb_size);

#endif //! _KKB__H__