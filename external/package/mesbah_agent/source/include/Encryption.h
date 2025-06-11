#ifndef _ENCRYPTION__H__
#define _ENCRYPTION__H__

#ifdef __linux__ 
#       include "../include/openssl/conf.h"
#       include "../include/openssl/evp.h"
#       include "../include/openssl/err.h"
#elif defined _WIN32
#		include "openssl/conf.h"
#		include "openssl/evp.h"
#		include "openssl/err.h"
#endif

#include <memory>

/// class Encryption: starts an Encryption object
/// 
/// It should be only called with constructor Encryption(unsigned char* _key, unsigned char* _iv) noexcept.
/// 
class Encryption {
private:
    void handleErrors(void);
    unsigned char* key;
    unsigned char* iv;

public:
    /// gets called to set iv and key for an encryption and/or decryption event
    /// @param _key -> a 32 bytes array
    /// @param _iv -> a 16 bytes array
    ///
    Encryption  (unsigned char* _key, unsigned char* _iv) noexcept;
    
    /// both client and server objects can call this method to start encryption
    /// @param plaintext
    /// @param plaintext_len
    /// @param ciphertext
    /// @returns int: returns the size of ciphertext
    /// 
    int encrypt (unsigned char* plaintext, int plaintext_len, unsigned char* ciphertext);
    
    /// both client and server objects can call this method to start decryption
    /// @param ciphertext
    /// @param ciphertext_len
    /// @param plaintext
    /// @returns int: returns the size of plaintext
    ///
    int decrypt (unsigned char* ciphertext, int ciphertext_len, unsigned char* plaintext);

protected:
    /// forbidden CTORs { should not be called by user at all! }
    ///
    Encryption            (const Encryption&) = delete;
    Encryption            (Encryption&&)      = delete;
    Encryption& operator= (const Encryption&) = delete;
    Encryption& operator= (Encryption&&)      = delete;
};

#endif //!_ENCRYPTION__H__