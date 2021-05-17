
#include <iostream>
#include <openssl/des.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace std;
/* Triple DES key for Encryption and Decryption */
DES_cblock Key1 = { 0x12, 0x34, 0x56, 0x78, 0x12, 0x13, 0x14, 0x15 };
DES_cblock Key2 = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
DES_cblock Key3 = { 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33 };
DES_key_schedule SchKey1, SchKey2, SchKey3;
int main()
{
    /* Input data to encrypt */
    DES_cblock input_data = { 'm', 'y', 's', 'E', 'c', 'r', 'e', 'T' };
    /* Buffers for Encryption and Decryption */
    DES_cblock cipher;
    DES_cblock text;
	/* set DES key */
	DES_set_key(&Key1,&SchKey1);
	DES_set_key(&Key2,&SchKey2);
	DES_set_key(&Key3,&SchKey3);
    /* Triple-DES ECB Encryption */
    DES_ecb3_encrypt(&input_data, &cipher, &SchKey1, &SchKey2, &SchKey3, DES_ENCRYPT);
    // end of payload  
    /* Triple-DES ECB Decryption */
    DES_ecb3_encrypt(&cipher, &text, &SchKey1, &SchKey2, &SchKey3, DES_DECRYPT);     
    // check for correctness
    cout << "Clear Text: " << text << endl;
}
