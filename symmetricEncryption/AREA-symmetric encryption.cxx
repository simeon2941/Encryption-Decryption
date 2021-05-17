/*
  symmetric encryption in block mode  (Algorithm Aria, Block mode : EVP_aria_128_ctr())
  Erind Hysa  z1879691
  Simeon Lico  z1885981

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <iostream>
#include <ctime>
#include <fstream>
#include <sstream>
using namespace std;
#define ERR_EVP_CIPHER_INIT -1
#define ERR_EVP_CIPHER_UPDATE -2
#define ERR_EVP_CIPHER_FINAL -3
#define ERR_EVP_CTX_NEW -4

#define AES_128_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define BUFSIZE 1024

typedef struct _cipher_params_t
{
    unsigned char* key;
    unsigned char* iv;
    unsigned int encrypt;
    const EVP_CIPHER* cipher_type;
} cipher_params_t;

void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

void file_encrypt(cipher_params_t* params, FILE* ifp, FILE* ofp)
{
    int all = 0, count = 1000;
    struct timespec start, stop;
    srand(time(NULL));
    /* Allow enough space in output buffer for additional block */
    int cipher_block_size = EVP_CIPHER_block_size(params->cipher_type);
    unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];
    int bytes_Read, out_len;
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    /* Don't set key or IV right away; we want to check lengths */
    if (!EVP_CipherInit_ex(ctx, params->cipher_type, NULL, NULL, NULL, params->encrypt))
        handleErrors();
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_128_KEY_SIZE);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_BLOCK_SIZE);
    /* Now we can set key and IV */
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, params->key, params->iv, params->encrypt))
        handleErrors();
    // Run 1000 times encryption to get average time
    for (int i = 0; i < count; i++)
    {
        clock_gettime(CLOCK_REALTIME, &start);

        while (true)
        {
            // Read in data in blocks until EOF. Update the ciphering with each read.
            bytes_Read = fread(in_buf, sizeof(unsigned char), BUFSIZE, ifp);

            if (!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, bytes_Read))
                handleErrors();
            fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
            if (bytes_Read < BUFSIZE) break;
        }
        /* Now cipher the final block and write it out to file */
        if (!EVP_CipherFinal_ex(ctx, out_buf, &out_len))
            handleErrors();
        clock_gettime(CLOCK_REALTIME, &stop);

        long start_time = start.tv_sec * 1000000000 + start.tv_nsec;
        long stop_time = stop.tv_sec * 1000000000 + stop.tv_nsec;
        all += stop_time - start_time;
    }
    cout << "Average time used for encryption: " << dec << (all / count)/1000 << " microseconds\n";

    fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
    EVP_CIPHER_CTX_cleanup(ctx);
}

int main(int argc, char* argv[])
{
    FILE *inputFile, *encryptedFile;
    /* Make sure user provides the input file */
    if (argc != 4)
    {
        printf("Usage: %s /path/to/file\n", argv[0]);
        return -1;
    }
    // allocate memory for params
    cipher_params_t* params = (cipher_params_t*)malloc(sizeof(cipher_params_t));
    if (!params)
    {
        /* couldnt allocate memory */
        fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno));
        return errno;
    }

    // strKey contains argv[1] as stromg
    string strKey = argv[1];
    unsigned char key[16] = { 0 }; // initliaze key[] with 0
    // iterate throug hthe string and convert the string into hex
    for (int i = 0; i < strlen(argv[1]) / 2; i++)
    {
        string splitString = strKey.substr(i * 2, 2);
        istringstream buffer(splitString);
        uint64_t value;
        buffer >> hex >> value;
        key[i] = value;
    }
    // string that contains argv2
    string strIv = argv[2];
    unsigned char iv[16] = { 0 }; // initiliaze iv array to 0

    for (int i = 0; i < strlen(argv[2]) / 2; i++)
    {
        string splitString = strIv.substr(i * 2, 2);
        istringstream buffer(splitString);
        uint64_t value;
        buffer >> hex >> value;
        iv[i] = value;
    }
    params->key = key;
    params->iv = iv;
    /* Indicate that we want to encrypt */
    params->encrypt = 1;
    /* Set the cipher type you want for encryption-decryption */
    params->cipher_type = EVP_aria_128_ctr();

    /* Open the input file for reading in binary ("rb" mode) */
    inputFile = fopen(argv[3], "rb");
    if (!inputFile)
    {
        /* error if it couldnt open the file */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }
    string argument3 = argv[3];
    size_t pos = argument3.find(".");
    string fileName = argument3.substr(0, pos);
    string finalName = fileName.append(".crypt");
    /* Open and truncate file to zero length or create ciphertext file for writing */
    encryptedFile = fopen(finalName.c_str(), "wb");
    if (!encryptedFile)
    {
        /* Unable to open file for writing */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }
    /* Encrypt the given file */
    file_encrypt(params, inputFile, encryptedFile);
    /* Encryption done, close the file descriptors */
    fclose(inputFile);
    fclose(encryptedFile);
    /* Free the memory allocated to our structure */
    free(params);
    return 0;
}
