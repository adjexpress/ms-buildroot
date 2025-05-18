/*  ****************************************************************************************************
    This work was done in Reverse Engineering group of Fapna Co. 
    For more info regarding reverse engineering procedure and coding, please contact the group.
    Reverse engineering of keymaster, TEEGIRS, and KDF functionality for Samsung Mediatek phones 
    to obtain the HDK key to decrypt keymaster_key_blob and later on, to decrypt 'encrypte_key' blob 
    which is used to decrypt the metadata of 'userbin' file.

    // >>>>>>>>>>>>>>>>>> RPMB2 FOR DIFFERENT PHONES <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< //

    //A22: 0x85,0x00,0x08,0xf9,0xe6,0x16,0x0e,0x5f,0xcc,0x0b,0x9f,0x0a,0x3d,0x97,0x47,0xff
    //A05: 0xec,0x6d,0x06,0x19,0xb0,0x56,0x67,0x56,0xf0,0x60,0x68,0x9b,0x51,0xa4,0x72,0x61
    //A04: 0xe2,0x6e,0x2c,0x4b,0xcd,0xec,0x05,0xe7,0x74,0xb5,0xbc,0xf5,0xc0,0xaf,0x33,0x57
    //M04: 0xb7,0x41,0x9a,0xf4,0xf8,0x71,0x54,0xd1,0x97,0xde,0x43,0xe4,0xd4,0xd6,0xc6,0x99

    // >>>>>>>>>>>>>>>>>> RPMB2 FOR DIFFERENT PHONES <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< //

******************************************************************************************************** */
#include "../include/core.h"
#include "../include/vbmeta.h"
#include "../include/secdis.h"
#include "../include/keymaster_key_blob.h"
#include "../include/custom_asn1.h"
#include "../include/math.h"
#include "../include/encryption.h"
#include "../include/rpmb2.h"

/* salt maker */
Int32_t salt_maker(const char* secdiscardable_address, 
                   const char* keymaster_key_blob_address, 
                   const char* vbmeta_address,
                   Uint32_t    integrity_status,
                   Uint8_t*    iv,
                   Uint8_t*    tag,
                   Uint8_t*    aad,
                   Uint8_t*    encrypted_data,
                   Uint32_t*   encrypted_data_length,
                   Uint8_t(*salts)[BLOCK_SIZE_0x20])
{
    Uint32_t integrity_status_size = 0;
    if(integrity_status != 0) 
        integrity_status_size = sizeof(Uint32_t);

    Uint8_t* main_buffer = Alloc(189 + integrity_status_size + 512, 0); // what if we have 'DATA'
    ROT rot;
    memset(&rot, 0, sizeof(ROT));

    rot.asn1_sequence = 0x30;
    rot.asn1_length   = 0x4A;
    rot.t1            = 0x04;
    rot.l1            = 0x20;
    rot.t2            = 0x01;
    rot.l2            = 0x01;
    rot.t3            = 0x0A;
    rot.l3            = 0x01;
    rot.t4            = 0x04;
    rot.l4            = 0x20;

    Uint32_t sha_256_length    = BLOCK_SIZE_0x20;
    Uint32_t sha_512_length    = BLOCK_SIZE_0x40;
    Uint8_t  mdfpp        [27] = "MDFPP HW Keymaster HEK v20";
    Uint8_t  id           [2]  = {'I','D'};
    Uint8_t  data         [4]  = {'D','A','T','A'};
    Uint8_t  final_sha_256[sha_256_length];
    Uint8_t  final_sha_512[sha_512_length];

    Uint8_t* secdis_buffer = handle_secdiscardable_file(secdiscardable_address);
    sha512_encrypt(final_sha_512, secdis_buffer, 16512);
    safe_free(secdis_buffer);
    
    Uint64_t kkb_size = 0;
    Uint8_t* kkb_buffer = read_keymaster_key_blob_file(keymaster_key_blob_address, &kkb_size);
   
    parse_keymaster_key_blob_asn1_v2(kkb_buffer, kkb_size - 32, encrypted_data, encrypted_data_length, iv, tag, aad);
 
    Uint8_t* ukdm = get_ukdm(kkb_buffer, kkb_size);

    Uint32_t n_bytes;
    Uint8_t* vbmeta_data = vbmeta_read_file_content(vbmeta_address);
    Uint8_t* vpk = assign_vbmeta_public_key(vbmeta_data);
    Uint8_t* n = calculate_vbmeta_public_key(vpk, &n_bytes);
    sha256_encrypt(final_sha_256, n, n_bytes);
    safe_free(vpk);
    safe_free(vbmeta_data);
    safe_free(n);

    memcpy(rot.vbmeta_pub_key, final_sha_256, BLOCK_SIZE_0x20);

    Uint8_t* ref_ptr = main_buffer;
    memcpy(ref_ptr, mdfpp, 27); ref_ptr += 27;

    // look for all possible 4 rot values
    for (size_t j = 0; j < 4; j++)
    {
        rot.boolean_type    = (j == 0) ? 0xFF : (j == 1) ? 0xFF : (j == 2) ? 0x00 : 0x00;
        rot.enumerated_type = (j == 0) ? 0x00 : (j == 1) ? 0x02 : (j == 2) ? 0x00 : 0x02;

        memcpy(ref_ptr, &rot, sizeof(ROT));             ref_ptr += sizeof(ROT);
        memcpy(ref_ptr, id, 2);                         ref_ptr += 2;
        memcpy(ref_ptr, &sha_512_length, 4);            ref_ptr += sizeof(sha_512_length);
        memcpy(ref_ptr, final_sha_512, sha_512_length); ref_ptr += sha_512_length;

        if (integrity_status != 0)
        {
            memcpy(ref_ptr, &integrity_status, integrity_status_size);
            ref_ptr += integrity_status_size;
        }
        
        // what if there is DATA
        memcpy(ref_ptr, ukdm, 16);

        ref_ptr -= (sizeof(ROT) + 2 + sizeof(sha_512_length) + integrity_status_size + sha_512_length);
        
        memset(final_sha_256, 0, BLOCK_SIZE_0x20);
        sha256_encrypt(final_sha_256, main_buffer, 189 + integrity_status_size);

        memcpy((j == 0) ? salts[0] : 
               (j == 1) ? salts[1] : 
               (j == 2) ? salts[2] : 
                          salts[3], final_sha_256, BLOCK_SIZE_0x20);
        memset(final_sha_256, 0, BLOCK_SIZE_0x20);
    }

    safe_free(ukdm);
    safe_free(main_buffer);
    return 0;
}

/* some extra checks for function input_output_handler */
static Int64_t __check_byte_flag(char c) 
{
    Int64_t ret;    
    if (c < 0)
        ret = c + 0x100000000;
    else if ((c & 0x80000000) == 0)
        ret = c;
    else
        ret = (Int64_t)c + -0x100000000;
    return ret;
}

/* get the 'input' buffer and perform some checks on bytes and save them in 'output' */
static void weired_math_operation_on_buffer(Uint8_t* output, Uint8_t* input) 
{
    CLEAR_BLOCK_0x10(output);
    for (size_t i = 0; i < BLOCK_SIZE_0x10; i++)
    {
        output[i] = input[i] * 2;
        if (i < 15) 
        {
            Int64_t sts = __check_byte_flag(input[i + 1]);
            if ((sts & 0x80000000) != 0) 
                output[i] = (input[i] * 2) | 1;
        }
    }
    if (((Int32_t)input[0] & 0x80) != 0)
        output[15] ^= 0x87;
}

// populate a buffer from salt and other strings
// in the end we need something like this:
/*  ***********************************************************************************************************************************
    Uint8_t xor_key_1_1[16] = { 0x01, 0x00, 0x00, 0x00, 0x4B, 0x4D, 0x20, 0x51, 0x53, 0x45, 0x45, 0x20, 0x48, 0x57, 0x20, 0x43 };
    Uint8_t xor_key_1_2[16] = { 0x02, 0x00, 0x00, 0x00, 0x4B, 0x4D, 0x20, 0x51, 0x53, 0x45, 0x45, 0x20, 0x48, 0x57, 0x20, 0x43 };
    Uint8_t xor_key_2[16]   = { 0x72, 0x79, 0x70, 0x74, 0x6F, 0x20, 0x44, 0x65, 0x72, 0x69, 0x76, 0x65, 0x64, 0x20, 0x6B, 0x65 };
    Uint8_t xor_key_3[16]   = { 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4B, 0x45, 0x59, 0x4D };
    Uint8_t xor_key_4[16]   = { 0x53, 0x54, 0x73, 0x61, 0x6D, 0x73, 0x75, 0x6E, 0x67, 0x5F, 0x74, 0x61, 0x00, 0x00, 0x00, 0x00 };
    Uint8_t xor_key_5[16]   = { 0x00, 0x00, 0xB4, 0x27, 0x5E, 0xB9, 0x76, 0x47, 0x63, 0x45, 0xAA, 0x39, 0x62, 0x61, 0xA0, 0x2C };
    Uint8_t xor_key_6[16]   = { 0x22, 0x6D, 0xE0, 0xDD, 0xA4, 0x87, 0xAB, 0xC4, 0x15, 0x65, 0x9F, 0x4F, 0x3D, 0xBD, 0xF9, 0x87 };
    Uint8_t xor_key_7[16]   = { 0xA6, 0xC4, 0x00, 0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
***********************************************************************************************************************************  */
void hdk_impl(XOR_STRING* xor_string, void* salt)
{
    // define these three values to be used later
    Uint32_t t0 = 256;
    Uint32_t t1 = 1; 
    Uint32_t t2 = 2;

    // define these strings
    const char* KM_QSEE_HW_Crypto_Derived_key = "KM QSEE HW Crypto Derived key";
    char KEYMST[16]     = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'K', 'E', 'Y', 'M', 'S', 'T'  };
    char samsung_ta[16] = {'s', 'a', 'm', 's', 'u', 'n', 'g', '_', 't', 'a', 0, 0, 0, 0, 0, 0};

    // get the length of 'KM_QSEE_HW_Crypto_Derived_key' and plus one to have a '00' byte at the end
    Int32_t QSEE_len = strlen(KM_QSEE_HW_Crypto_Derived_key) + 1;

    // allocate and zero a buffer with length 112 bytes
    void* buf_2 = Alloc(112, 0);

    // leave first 4 bytes alone and copy 'KM_QSEE_HW_Crypto_Derived_key' starting from byte 5 on
    CopyData(buf_2, 4, QSEE_len + 4, KM_QSEE_HW_Crypto_Derived_key);

    // allocate and zero a buffer with length 64 bytes
    void* buf_1 = Alloc(0x40, 0);

    // copy the following buffers in it respectively
    CopyData(buf_1, 0x00, 0x10, (void*)KEYMST);
    CopyData(buf_1, 0x10, 0x20, (void*)samsung_ta);
    CopyData(buf_1, 0x20, 0x40, salt);

    Int32_t buf_1_len = 0x40;

    // copy 'buf_1' buffer right after 'KM_QSEE_HW_Crypto_Derived_key + 1 byte 00' in 'buf_2'
    CopyData(buf_2, QSEE_len + 4, QSEE_len + buf_1_len + 4, buf_1);

    // we don't need buf_1 anymore, as such safe_free it
    safe_free(buf_1);

    // copy t0 value (aka. 256) in 'buf_2' 
    CopyData(buf_2, QSEE_len + buf_1_len + 4, QSEE_len + buf_1_len + 4 + 4, &t0);

    // copy t1 value (aka. 1) in first 4 bytes of 'buf_2' 
    CopyData(buf_2, 0, 4, &t1);

    // store first BLOCK of what we have as 'buf_2' inside xor_string->xor_key_1
    COPY_BLOCK_0x10(xor_string->xor_key_1, buf_2);

    // copy t2 value (aka. 2) in first 4 bytes of 'buf_2' 
    CopyData(buf_2, 0, 4, &t2);

    // store first BLOCK of what we have as 'buf_2' inside xor_string->xor_key_2
    COPY_BLOCK_0x10(xor_string->xor_key_2, buf_2);

    // define two reference pointers for copying
    Uint8_t* b = (Uint8_t*)buf_2;
    Uint8_t* src = &b[BLOCK_SIZE_0x10];

    // in a loop copy from second BLOCK of 'buf_2' inside xor_string buffers
    for (size_t i = 0; i < 6; i++)
    {
        Uint8_t* trg = &xor_string->xor_key_i[i * BLOCK_SIZE_0x10];
        COPY_BLOCK_0x10(trg, src);
        src += BLOCK_SIZE_0x10;
    }

    // finally, put value 0x80 inside offset 0x56 of xor_string->xor_key_i
    xor_string->xor_key_i[0x56] = 0x80;

    // safe_free out buf_2
    safe_free(buf_2);
}

/* entry point of the application */
int main(int argc, char* argv[])
{
    // sanity
    if(argc < 5)
    {
        printf("usage:\n\t./kdf [rpmb2_file_address] [secdiscardable_file_address] [vbmeta_file_address] [keymaster_key_blob_file_address]\n");
        return -100;
    }

    // rpmb2 holder
    Uint8_t rpmb2[BLOCK_SIZE_0x10];

    // make rpmb2 from user's input
    read_rpmb2_file(argv[1], rpmb2);

    // salt array must be calculated
    Uint8_t salt[4][BLOCK_SIZE_0x20];

    // define a holder for integrity_status
    Uint32_t integ_sts = 0;

    // define AES-GCM-256 parameters
    Uint8_t  iv [12];
    Uint8_t  tag[16];
    Uint8_t  aad[20];
    Uint8_t  enc_data[4096];
    Uint32_t enc_data_len = 0;

    while(integ_sts < 8)
    {
        if(salt_maker(argv[2], argv[4], argv[3], integ_sts, iv, tag, aad, enc_data, &enc_data_len, salt) < 0) 
            return -10;

        for (size_t i = 0; i < 4; i++)
        {  
            // needed variables 
            XOR_STRING    xor_string;
            HDK           hdk;
            Uint8_t zero  [BLOCK_SIZE_0x10]; 
            Uint8_t temp_0[BLOCK_SIZE_0x10];
            Uint8_t temp_1[BLOCK_SIZE_0x10];

            // construct xor_values and put them in xor_string
            hdk_impl(&xor_string, salt[i]);   

            // clear out 'zero' buffer 
            CLEAR_BLOCK_0x10(zero);

            // define two 'vector' variables for AES-128-ECB operation
            vector_0x10 key_vec  = {.size = BLOCK_SIZE_0x10}; COPY_BLOCK_0x10(key_vec.data, rpmb2);
            vector_0x10 data_vec = {.size = BLOCK_SIZE_0x10}; COPY_BLOCK_0x10(data_vec.data, zero);

            // get the result of AES-128-ECB as a 'vector'
            vector_0x10 output   = aes_128_ecb(&key_vec, &data_vec);

            // handle output of AES-128-ECB operation
            weired_math_operation_on_buffer(temp_0, output.data);

            // handle again output of last handle operation
            weired_math_operation_on_buffer(temp_1, temp_0);

            // xor the result of last handle operation with last block of xor_string
            xor_16_bytes_arrays (temp_0, temp_1, &xor_string.xor_key_i[5 * BLOCK_SIZE_0x10]);

            // xor the 'zero' buffer with first block of xor_string
            xor_16_bytes_arrays (temp_1, zero, xor_string.xor_key_1);

            // copy the result in 'vector' for another AES-128-ECB
            COPY_BLOCK_0x10(data_vec.data, temp_1);
            data_vec.size = BLOCK_SIZE_0x10;

            // do the AES-128-ECB and get the result as a 'vector'
            output = aes_128_ecb(&key_vec, &data_vec);

            // now in a loop do the following:
            for (size_t j = 0; j < 5; j++)
            {
                // xor the last AES-128-ECB result with next xor_string block
                xor_16_bytes_arrays(temp_1, output.data, &xor_string.xor_key_i[j * BLOCK_SIZE_0x10]);

                // copy the result as the data for next round
                COPY_BLOCK_0x10(data_vec.data, temp_1);
                data_vec.size = BLOCK_SIZE_0x10;

                // do the next AES-128-ECB operation
                output = aes_128_ecb(&key_vec, &data_vec);
            } 

            // copy the result in 'xor_string.final_xor_1'
            COPY_BLOCK_0x10(xor_string.final_xor_1, output.data);

            // xor the 'zero' buffer with second block of xor_string
            xor_16_bytes_arrays(temp_1, zero, xor_string.xor_key_2);

            // copy the result in 'vector' for another AES-128-ECB
            COPY_BLOCK_0x10(data_vec.data, temp_1);
            data_vec.size = BLOCK_SIZE_0x10;

            // do the AES-128-ECB and get the result as a 'vector'
            output = aes_128_ecb(&key_vec, &data_vec);

            // now in a loop do the following:
            for (size_t j = 0; j < 5; j++)
            {
                // xor the last AES-128-ECB result with next xor_string block
                xor_16_bytes_arrays(temp_1, output.data, &xor_string.xor_key_i[j * BLOCK_SIZE_0x10]);

                // copy the result as the data for next round
                COPY_BLOCK_0x10(data_vec.data, temp_1);
                data_vec.size = BLOCK_SIZE_0x10;

                // do the next AES-128-ECB operation
                output = aes_128_ecb(&key_vec, &data_vec);
            } 

            // copy the result in 'xor_string.final_xor_2'
            COPY_BLOCK_0x10(xor_string.final_xor_2, output.data);

            // xor what was kept in 'temp0' buffer with final_xor_1 and final_xor_2, respectively and save the 
            // results in hdk.encryption_key_value_1 and hdk.encryption_key_value_2, respectively.
            xor_16_bytes_arrays(hdk.encryption_key_value_1, temp_0, xor_string.final_xor_1);
            xor_16_bytes_arrays(hdk.encryption_key_value_2, temp_0, xor_string.final_xor_2);

            // copy 'hdk.encryption_key_value_1' in a 'vector' for AES-128-ECB operation
            COPY_BLOCK_0x10(data_vec.data, hdk.encryption_key_value_1);
            data_vec.size = BLOCK_SIZE_0x10;

            // do the next AES-128-ECB operation
            output = aes_128_ecb(&key_vec, &data_vec);

            // finaly copy the result as the FIRST BLOCK of hdk
            COPY_BLOCK_0x10(hdk.hdk, output.data);

            // copy 'hdk.encryption_key_value_2' in a 'vector' for AES-128-ECB operation
            COPY_BLOCK_0x10(data_vec.data, hdk.encryption_key_value_2);
            data_vec.size = BLOCK_SIZE_0x10;

            // do the next AES-128-ECB operation
            output = aes_128_ecb(&key_vec, &data_vec);

            // finaly copy the result as the SECOND BLOCK of hdk
            COPY_BLOCK_0x10(&hdk.hdk[BLOCK_SIZE_0x10], output.data);

            // define a buffer for decrypted data
            Uint8_t decrypted_data[4096];

            // do the decryption
            Int32_t decrypted_len = gcm_decrypt(enc_data, decrypted_data, aad, iv, tag, hdk.hdk, enc_data_len, 20, 12, 16, 32);
            
            // did we succeed?
            if (decrypted_len > 0)
            {
                // dump all decrypted fields to the STDOUT
                printf("decryption was successful with integrity_status ' %i '\n\nSALT:\n", integ_sts);
                dump_buffer(salt[i], 32);
                printf("--------------------------\nHDK:\n");
                dump_buffer(hdk.hdk, 32);
                printf("--------------------------\n'keymaster_key_blob' decrypted as:\nIV:\n");
                dump_buffer(iv,  12);
                printf("\nAUTH TAG:\n");
                dump_buffer(tag, 16);
                printf("\nAAD:\n");
                dump_buffer(aad, 20);
                printf("\nASN1 encrypted data:\n");
                dump_buffer(decrypted_data, decrypted_len);
                printf("--------------------------\n");

                // define a 64 byte holder to keep decrypted data of 'encrypetd_key' file
                Uint8_t metadata_decrypted_data[64];

                // define a 32 byte holder for 'metadata_decryption_key' to be populated by ASN1 parsing 
                Uint8_t metadata_decryption_key[32];

                Int32_t sts = parse_keymaster_key_blob_encrypted_data_asn1_v2(decrypted_data, decrypted_len, metadata_decryption_key);
                decrypted_len = decrypt_encrypted_key("encrypted_key", metadata_decryption_key, metadata_decrypted_data);
                if (decrypted_len > 0)
                {
                    printf("'encrypted_key' decrypted as:\n");
                    dump_buffer(metadata_decrypted_data, 64);
                    printf("--------------------------\n");
                }

                return 0;
            }
        }

        // increment integrity status value for the next round of extraction
        integ_sts++;
    }
}