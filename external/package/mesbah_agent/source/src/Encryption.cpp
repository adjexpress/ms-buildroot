#ifdef __linux__ 
#		include "../include/Packet.h"
#elif defined _WIN32
#		include "Packet.h"
#endif

Encryption::Encryption(unsigned char* _key, unsigned char* _iv) noexcept
    : key{ _key }, iv{ _iv }
{}

int Encryption::encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
 {    
    EVP_CIPHER_CTX* ctx;

    int len, ciphertext_len;

    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        handleErrors();
        return -1;
    }

    /*
     * Initialize the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        handleErrors();
        return -1;
    }

    // Provide the message to be encrypted, and obtain the encrypted output. EVP_EncryptUpdate can be called multiple times if necessary
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        handleErrors();
        return -1;
    }

    // update length of 'ciphertext_len'
    ciphertext_len = len;

    // Finalise the encryption. Further ciphertext bytes may be written at this stage.
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        handleErrors();
        return -1;
    }

    // update length of 'ciphertext_len'
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // return to the caller
    return ciphertext_len;
}

int Encryption::decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* plaintext) 
{
    EVP_CIPHER_CTX* ctx;

    int len, plaintext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        handleErrors();
        return -1;
    }

    /*
     * Initialize the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        handleErrors();
        return -1;
    }

    // Provide the message to be decrypted, and obtain the plaintext output. EVP_DecryptUpdate can be called multiple times if necessary.
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();

    // update length of 'ciphertext_len'
    plaintext_len = len;

    // Finalise the decryption. Further plaintext bytes may be written at this stage.
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        handleErrors();
        return -1;
    }

    // update length of 'ciphertext_len'
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // return to the caller
    return plaintext_len;
}

void Encryption::handleErrors(void)
{
    ERR_print_errors_fp(stderr);
		LOG("Encryption::handleErrors :: reported an error to stderr");
    //abort();
}
