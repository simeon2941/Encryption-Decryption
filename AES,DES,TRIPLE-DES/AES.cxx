
#include <iostream>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl/aes.h"
#include <iostream>
#include <openssl/aes.h>

using namespace std;

int main()
{
    // prepare AES key
    AES_KEY key;
    unsigned char keyBytes[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
        0x67, 0x89, 0xab, 0xcd, 0xef };
    // example input block: 16 bytes of data
    unsigned char* plaintext = (unsigned char*)"a secret message";
    // buffer to hold encrypted data
    unsigned char ciphertext[16];
    // run encryption
	AES_set_encrypt_key(keyBytes, 128, &key);
	AES_ecb_encrypt(plaintext, ciphertext, &key, AES_ENCRYPT);
    // buffer to hold decrypted data
    unsigned char deciphertext[17];
    // run descryption
    AES_set_decrypt_key(keyBytes, 128, &key);
    AES_ecb_encrypt(ciphertext, deciphertext, &key, AES_DECRYPT);
    // check for correctness
	deciphertext[16] = '\0';
    cout << "Clear Text: " << deciphertext << endl;
}
