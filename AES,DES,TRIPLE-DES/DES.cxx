
#include <iostream>
#include <openssl/des.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace std;

int main()
{
    int all = 0, all1 = 0, count = 1000;
    struct timespec start, stop;
    srand(time(NULL));
    // prepare DES key:
    DES_cblock cbc_key = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    DES_key_schedule key;
    // example input block: 8 bytes of data
    DES_cblock plaintext = { 'm', 'y', 's', 'e', 'c', 'r', 'e', 't' };
    // block to hold encrypted data
    DES_cblock cyphertext;
    // set DES key
    DES_set_key(&cbc_key, &key);
    // run encryption
    DES_ecb_encrypt(&plaintext, &cyphertext, &key, DES_ENCRYPT);
    // block to hold decrypted data
    DES_cblock decyphertext; 
    // run decryption
    DES_ecb_encrypt(&cyphertext, &decyphertext, &key, DES_DECRYPT); 
    // check for correctness
    cout << "Clear Text: " << decyphertext << endl;
}
