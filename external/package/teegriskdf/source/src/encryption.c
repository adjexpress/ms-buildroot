#include "../include/encryption.h"

vector_0x10 aes_128_ecb(vector_0x10* key, vector_0x10* data)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_EncryptInit_ex (ctx, EVP_aes_128_ecb(), NULL, key->data, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    Uint8_t buffer[BLOCK_SIZE_0x20];
    int outlen;
    EVP_EncryptUpdate(ctx, buffer, &outlen, data->data, data->size);

    vector_0x10 ret;
    memcpy(ret.data, buffer, outlen);
    ret.size = outlen;

    EVP_EncryptFinal_ex(ctx, buffer, &outlen);
    return ret;
}

void sha256_encrypt(Uint8_t* output, Uint8_t* data, Uint64_t size)
{
    memset(output, 0, BLOCK_SIZE_0x20);
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (ctx)
	{
		EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
		EVP_DigestUpdate(ctx, data, size);
		Uint8_t hash[BLOCK_SIZE_0x20];
		Uint32_t  len_of_hash = 0;
        EVP_DigestFinal_ex(ctx, hash, &len_of_hash);
		memcpy(output, hash, len_of_hash);
        return;
	}
}

void sha512_encrypt(Uint8_t* output, Uint8_t* data, Uint64_t size)
{
    memset(output, 0, BLOCK_SIZE_0x40);
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (ctx)
	{
		EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
		EVP_DigestUpdate(ctx, data, size);
		Uint8_t hash[BLOCK_SIZE_0x40];
		Uint32_t len_of_hash = 0;
		EVP_DigestFinal_ex(ctx, hash, &len_of_hash);        
		memcpy(output, hash, len_of_hash);
        return;
	}
}

Int32_t gcm_decrypt(Uint8_t* source, 
                    Uint8_t* target, 
                    Uint8_t* aad, 
                    Uint8_t* iv, 
                    Uint8_t* tag, 
                    Uint8_t* key, 
                    Uint32_t source_size,
                    Uint32_t aad_size,
                    Uint32_t iv_size,
                    Uint32_t tag_size,
                    Uint32_t key_size)
{
	Int32_t output_len = 0;
	Int32_t temp_len   = 0;

	EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();

	if (!context)
	{
		// printf("EVP_CIPHER_CTX_new failed\n");
		return -1;
	}

	// Initialize context with decryption mode
	Int32_t decrypt_init = EVP_DecryptInit(context, EVP_aes_256_gcm(), NULL, NULL);
	if (!decrypt_init)
	{
		// printf("EVP_DecryptInit failed\n");
		EVP_CIPHER_CTX_free(context);
		context = NULL;
		return -2;
	}

	// set IV length
	Int32_t cipher_ctrl = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL);
	if (!cipher_ctrl)
	{
		// printf("EVP_CIPHER_CTX_ctrl failed\n");
		EVP_CIPHER_CTX_free(context);
		context = NULL;
		return -3;
	}

	// set secret key length
	Int32_t key_length = EVP_CIPHER_CTX_set_key_length(context, (Int32_t)key_size);
	if (key_length < 0)
	{
		// printf("EVP_CIPHER_CTX_set_key_length failed\n");
		EVP_CIPHER_CTX_free(context);
		context = NULL;
		return -4;
	}

	// initialize secret key and IV
	decrypt_init = EVP_DecryptInit(context, NULL, &key[0], &iv[0]);
	if (!decrypt_init)
	{
		// printf("EVP_DecryptInit failed\n");
		EVP_CIPHER_CTX_free(context);
		context = NULL;
		return -5;
	}

	// Provide AAD if supplied
	if (aad_size != 0)
	{
		Int32_t decrypt_update = EVP_DecryptUpdate(context, NULL, &temp_len, &aad[0], aad_size);
		if (!decrypt_update)
		{
			// printf("EVP_DecryptUpdate failed\n");
			EVP_CIPHER_CTX_free(context);
			context = NULL;
			return -6;
		}
	}

	// Create a temp buffer for decryption output
	Uint8_t* tmp_out = Alloc(source_size + 1024, 0);

	// get the output size
	if (!EVP_DecryptUpdate(context, tmp_out, &temp_len, &source[0], source_size))
	{
		// printf("EVP_DecryptUpdate failed\n");
		EVP_CIPHER_CTX_free(context);
		context = NULL;
		return -7;
	}

	//
	output_len = temp_len;

	//
	temp_len = 0;

	// Set expected tag value
	if (!EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, 16, &tag[0]))
	{
		// printf("EVP_CIPHER_CTX_ctrl failed\n");
		EVP_CIPHER_CTX_free(context);
		context = NULL;
		return -8;
	}

	// set no padding
	Int32_t set_padding = EVP_CIPHER_CTX_set_padding(context, 0);
	if (!set_padding)
	{
		// printf("EVP_CIPHER_CTX_set_padding failed\n");
		EVP_CIPHER_CTX_free(context);
		context = NULL;
		return -9;
	}

	// Finalise the decryption
	if (EVP_DecryptFinal_ex(context, &tmp_out[output_len], &temp_len) <= 0)
	{
		// printf("EVP_DecryptFinal_ex failed\n");
		EVP_CIPHER_CTX_free(context);
		context = NULL;
		return -10;
	}

	output_len += temp_len;

	EVP_CIPHER_CTX_free(context);
	context = NULL;

	memcpy(target, tmp_out, output_len);
    safe_free(tmp_out);
	return output_len;
}

Int32_t decrypt_encrypted_key(const char* encrypted_key_address, Uint8_t* key, Uint8_t* out)
{
    FILE* ek = fopen(encrypted_key_address, "rb");
    if(!ek)
    {
        printf("ERROR -> opening %s failed\n", encrypted_key_address);
        return -1;
    }
    Uint64_t ek_size = 0;

    fseek(ek, 0L, SEEK_END);
    ek_size = (Uint64_t)ftell(ek);
    fseek(ek, 0L, SEEK_SET);

    if (ek_size == 0)
    {
        printf("ERROR -> size %s is zero\n", encrypted_key_address);
        fclose(ek);
        return -1;
    }

    Uint8_t* buffer = Alloc(ek_size, 0);
    fread(buffer, ek_size, 1, ek);
    fclose(ek);

    Uint8_t iv [12];
    Uint8_t tag[16];
    memcpy(iv, buffer, 12);
    memcpy(tag, &buffer[ek_size - 16], 16);
    Uint8_t* source = Alloc(ek_size - 16 - 12, 0);
    memcpy(source, &buffer[12], ek_size - 16 - 12);
    Int32_t dec = gcm_decrypt(source, out, NULL, iv, tag, key, ek_size - 16 - 12, 0, 12, 16, 32);
    if(dec > 0)
    {
        safe_free(source);
        safe_free(buffer);
        return dec;
    }
}


