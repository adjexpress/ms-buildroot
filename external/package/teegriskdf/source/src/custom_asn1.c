#include "../include/custom_asn1.h"

__DEPRECATED_FUNCTION__ static Int32_t parse_keymaster_key_blob_asn1_iv_tag_aad_count = 0;
__DEPRECATED_FUNCTION__ Int32_t parse_keymaster_key_blob_asn1_iv_tag_aad(Uint8_t* buffer, 
                                                                         Uint32_t buffer_length,
                                                                         Uint8_t* iv,
                                                                         Uint8_t* tag,
                                                                         Uint8_t* aad)
{
    if(parse_keymaster_key_blob_asn1_iv_tag_aad_count == 3)
        return 0;
    Uint8_t* org = buffer;
    Uint32_t remained_bytes = buffer_length;
    long plength = 0;
    Int32_t ptag;
    Int32_t pclass;    
    ASN1_get_object((const Uint8_t**)&buffer, &plength, &ptag, &pclass, remained_bytes);
    Uint8_t* trg = buffer;
    Uint32_t current_tag = *(Uint32_t*)(buffer + 2);
    if (current_tag == 0x88130090)
    {
        Uint8_t* iv_data = buffer + 10;
        memcpy(iv, iv_data, 12);
    }
    if (current_tag == 0x89130090)
    {
        Uint8_t* tag_data = buffer + 10;
        memcpy(tag, tag_data, 16);
    }
    if (current_tag == 0x92130090)
    {
        Uint8_t* aad_data = buffer + 10;
        memcpy(&aad[4], aad_data, 16);
    }
    parse_keymaster_key_blob_asn1_iv_tag_aad_count++;
    unsigned long step = (long)trg - (long)org;
    parse_keymaster_key_blob_asn1_iv_tag_aad(buffer + plength, buffer_length - plength - step, iv, tag, aad);
    return 0;
}

__DEPRECATED_FUNCTION__ Int32_t parse_keymaster_key_blob_asn1_v1(Uint8_t*  keymaster_key_blob_asn1_buffer, 
                                                                 Uint32_t  keymaster_key_blob_asn1_buffer_length,
                                                                 Uint8_t*  encrypted_data,
                                                                 Uint32_t* encrypted_data_length,
                                                                 Uint8_t*  iv,
                                                                 Uint8_t*  tag,
                                                                 Uint8_t*  aad)
{
    Uint32_t remained_bytes = keymaster_key_blob_asn1_buffer_length - 32;
    long plength = 0;
    Int32_t ptag;
    Int32_t pclass;
    Int32_t ret = ASN1_get_object((const Uint8_t**)&keymaster_key_blob_asn1_buffer, &plength, &ptag, &pclass, remained_bytes);
    if ((ret & (1 << 8)) == 1)
    {
        printf("ASN1 -> error occured\n");
        return -1;
    }    
    Uint8_t* buf = malloc(plength);
    Uint8_t* p = keymaster_key_blob_asn1_buffer;
    memcpy(buf, p, plength);
    long remaind = plength;
    while(remaind > 0)
    {
        Uint8_t* org = p;
        ret = ASN1_get_object((const Uint8_t**)&p, &plength, &ptag, &pclass, remaind);
        if (pclass == V_ASN1_UNIVERSAL && ptag == V_ASN1_INTEGER)
        {
            Uint32_t enc_ver = (Uint32_t)*p;
            memcpy(aad, &enc_ver, 4);
        }
        if (pclass == V_ASN1_UNIVERSAL && ptag == V_ASN1_OCTET_STRING)
        {
            memcpy(encrypted_data, p, plength);
            *encrypted_data_length = plength;
        }
        if (pclass == V_ASN1_UNIVERSAL && ptag == V_ASN1_SET)
        {
            Uint8_t* set_data = malloc(plength);
            memcpy(set_data, p, plength);
            parse_keymaster_key_blob_asn1_iv_tag_aad(set_data, plength, iv, tag, aad);
            safe_free(set_data);
        }
        p += plength;
        long sz = ((long)p - (long)org);
        remaind -= sz;
    }
    return 0;
}

/* deserialize ASN1 content of 'keymaster_key_blob' file, recurseively */
static Int32_t parse_keymaster_key_blob_asn1_v2_depth = 0;
static Int32_t iv_tag_found                           = FALSE;
static Int32_t tag_tag_found                          = FALSE;
static Int32_t aad_tag_found                          = FALSE;

Int32_t parse_keymaster_key_blob_asn1_v2(Uint8_t*  keymaster_key_blob_asn1_buffer, 
                                         Uint32_t  keymaster_key_blob_asn1_buffer_length,
                                         Uint8_t*  encrypted_data,
                                         Uint32_t* encrypted_data_length,
                                         Uint8_t*  iv_data,
                                         Uint8_t*  tag_data,
                                         Uint8_t*  aad_data)
{
    const Uint8_t* src    = (const Uint8_t*)keymaster_key_blob_asn1_buffer;
    long           length = 0;
    Int32_t        tag    = -1;
    Int32_t        class  = -1;

    ASN1_get_object(&src, &length, &tag, &class, keymaster_key_blob_asn1_buffer_length);

    if(length == 0) 
        return 0;

    // printf("*** tag:%i, class: %i, len: %li, depth = %i\n", tag, class, length, depth);    
    // dump_buffer(src, length);
    // printf("*****************************************\n");

    if ((iv_tag_found == TRUE) && (12 == length))
    {
        memcpy(iv_data, src, 12);
        iv_tag_found = 0;
    }
    if ((tag_tag_found == TRUE) && (16 == length))
    {
        memcpy(tag_data, src, 16);
        tag_tag_found = 0;
    }
    if ((aad_tag_found == TRUE) && (16 == length))
    {
        memcpy(&aad_data[4], src, 16);
        aad_tag_found = 0;
    }   

    if ((1 == parse_keymaster_key_blob_asn1_v2_depth) && (tag == V_ASN1_INTEGER) && (1 == length))
    {
        Uint32_t enc_ver = (Uint32_t)*src;
        memcpy(aad_data, &enc_ver, 4);
    }
    if ((1 == parse_keymaster_key_blob_asn1_v2_depth) && (tag == V_ASN1_OCTET_STRING))
    {
        memcpy(encrypted_data, src, length);
        *encrypted_data_length = length;
    }
    if ((4 == length) && (*(Uint32_t*)src == KM_IV_TAG))
        iv_tag_found = TRUE;
    if ((4 == length) && (*(Uint32_t*)src == KM_AUTH_TAG_TAG))
        tag_tag_found = TRUE;
    if ((4 == length) && (*(Uint32_t*)src == KM_HEK_RANDOMNESS_TAG))
        aad_tag_found = TRUE;

    long step = ((long)src - (long)keymaster_key_blob_asn1_buffer);

    if (tag   != V_ASN1_SEQUENCE         && 
        tag   != V_ASN1_SET              && 
        class != V_ASN1_APPLICATION      && 
        class != V_ASN1_CONTEXT_SPECIFIC && 
        class != V_ASN1_PRIVATE)
    {
        src += length;
    } 
    else 
    {
        parse_keymaster_key_blob_asn1_v2_depth++;
    }

    parse_keymaster_key_blob_asn1_v2(src, 
                                     keymaster_key_blob_asn1_buffer_length - step, 
                                     encrypted_data, 
                                     encrypted_data_length, 
                                     iv_data, 
                                     tag_data, 
                                     aad_data);
}

__DEPRECATED_FUNCTION__ Int32_t parse_keymaster_key_blob_encrypted_data_asn1_v1(Uint8_t* data, 
                                                                                Uint32_t data_length,
                                                                                Uint8_t* encrypted_key_file_key)
{
    Uint32_t remained_bytes = data_length;
    long plength = 0;
    Int32_t ptag;
    Int32_t pclass;
    Int32_t ret = ASN1_get_object((const Uint8_t**)&data, &plength, &ptag, &pclass, remained_bytes);
    if ((ret & (1 << 8)) == 1)
    {
        printf("ASN1 -> error occured\n");
        return -1;
    }    
    Uint8_t* buf = malloc(plength);
    Uint8_t* p = data;
    memcpy(buf, p, plength);
    long remaind = plength;
    while(remaind > 0)
    {
        Uint8_t* org = p;
        ret = ASN1_get_object((const Uint8_t**)&p, &plength, &ptag, &pclass, remaind);
        if (pclass == V_ASN1_UNIVERSAL && ptag == V_ASN1_INTEGER)
        {}
        if (pclass == V_ASN1_UNIVERSAL && ptag == V_ASN1_OCTET_STRING)
        {
            memcpy(encrypted_key_file_key, p, 32);
            return 0;
        }
        p += plength;
        long sz = ((long)p - (long)org);
        remaind -= sz;
    }
    return -1;
}

/* deserialize ASN1 content of 'encrypted_key' file, recurseively */
static Int32_t parse_keymaster_key_blob_encrypted_data_asn1_v2_depth = 0;
Int32_t parse_keymaster_key_blob_encrypted_data_asn1_v2(Uint8_t* data, 
                                                        Uint32_t data_length,
                                                        Uint8_t* encrypted_key_file_key)
{
    const Uint8_t* src    = (const Uint8_t*)data;
    long           length = 0;
    Int32_t        tag    = -1;
    Int32_t        class  = -1;

    ASN1_get_object(&src, &length, &tag, &class, data_length);

    if(length == 0) 
        return 0;

    // printf("*** tag:%i, class: %i, len: %li, depth = %i\n", tag, class, length, parse_keymaster_key_blob_encrypted_data_asn1_v2_depth);    
    // dump_buffer(src, length);
    // printf("*****************************************\n");

    if ((1 == parse_keymaster_key_blob_encrypted_data_asn1_v2_depth) && (tag == V_ASN1_OCTET_STRING))
    {
        memcpy(encrypted_key_file_key, src, 32);
        return 0;
    }
    
    long step = ((long)src - (long)data);

    if (tag   != V_ASN1_SEQUENCE         && 
        tag   != V_ASN1_SET              && 
        class != V_ASN1_APPLICATION      && 
        class != V_ASN1_CONTEXT_SPECIFIC && 
        class != V_ASN1_PRIVATE)
    {
        src += length;
    } 
    else
    {
        parse_keymaster_key_blob_encrypted_data_asn1_v2_depth++;
    }

    parse_keymaster_key_blob_encrypted_data_asn1_v2(src, data_length - step, encrypted_key_file_key);
}


