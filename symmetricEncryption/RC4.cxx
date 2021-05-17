/*
  symmetric encryption in stream mode
*/
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <string.h>
#include <iostream>
#include <ctime>
#include <fstream>
#include <sstream>
#include <openssl/rand.h>
using namespace std;
#define ERR_EVP_CIPHER_INIT -1
#define ERR_EVP_CIPHER_UPDATE -2
#define ERR_EVP_CIPHER_FINAL -3
#define ERR_EVP_CTX_NEW -4

#define BUFSIZE 1024

typedef struct _cipher_params_t
{
    unsigned char* key;
    unsigned char* iv;
    unsigned int encrypt;
    const EVP_CIPHER* cipher_type;
} cipher_params_t;
void file_encrypt(cipher_params_t* params, FILE* ifp, FILE* ofp)
{
    int all = 0, count = 1000;
    struct timespec start, stop;
    srand(time(NULL));
    /* Allow enough space in output buffer for additional block */
    int cipher_block_size = EVP_CIPHER_block_size(params->cipher_type);
    unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];
    int num_bytes_read, out_len;
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    /* Don't set key or IV right away; we want to check lengths */
    EVP_CipherInit_ex(ctx, params->cipher_type, NULL, NULL, NULL, params->encrypt);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
    /* Now we can set key and IV */
    EVP_CipherInit_ex(ctx, NULL, NULL, params->key, params->iv, params->encrypt);
     // Run 1000 times encryption to get average time
    for (int i = 0; i < count; i++)
    {

        clock_gettime(CLOCK_REALTIME, &start);
    while (true)
    {
        // Read in data in blocks until EOF. Update the ciphering with each read.
        num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, ifp);
        EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read);
        fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
        if (num_bytes_read < BUFSIZE)
        {
            /* Reached End of file */
            break;
        }
    }
    /* Now cipher the final block and write it out to file */
    EVP_CipherFinal_ex(ctx, out_buf, &out_len);
    clock_gettime(CLOCK_REALTIME, &stop);

        long start_time = start.tv_sec * 1000000000 + start.tv_nsec;
        long stop_time = stop.tv_sec * 1000000000 + stop.tv_nsec;
        all += stop_time - start_time;
            }


    cout << "\nAverage time used for encryption: " << dec << (all / count)/1000.0 << " microseconds\n";
    fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
    EVP_CIPHER_CTX_cleanup(ctx);
}

int main(int argc, char* argv[])
{
    FILE *f_input, *f_enc, *f_dec;


  /* print error */
    if (argc != 3)
    {
        printf("Usage: %s /path/to/file\n", argv[0]);
        return -1;
    }

    cipher_params_t* params = (cipher_params_t*)malloc(sizeof(cipher_params_t));



    string stringKey = argv[1];
    unsigned char key[16];
    for (int i = 0; i < strlen(argv[1]) / 2; i++)
    {
        string splitString = stringKey.substr(i * 2, 2);
        istringstream buffer(splitString);
        uint64_t value;
        buffer >> hex >> value;
        // cout << hex << value;
        key[i] = value;
    }

    params->key = key;
    /* Indicate that we want to encrypt */
    params->encrypt = 1;

    /* Set the cipher type you want for encryption-decryption */
    params->cipher_type = EVP_rc4();

    /* Open the input file for reading in binary ("rb" mode) */
    f_input = fopen(argv[2], "rb");
    if (!f_input)
    {
        /* Unable to open file for reading */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }

    string argument = argv[2];
    size_t pos = argument.find(".");
    string firstWord = argument.substr(0, pos);
    string finalName = firstWord.append(".crypt");
    /* Open and truncate file to zero length or create ciphertext file for writing */
    f_enc = fopen(finalName.c_str(), "wb");
    if (!f_enc)
    {
        /* Unable to open file for writing */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }
   
        /* Encrypt the given file */
        file_encrypt(params, f_input, f_enc);
    /* Encryption done, close the file descriptors */
    fclose(f_input);
    fclose(f_enc);
    /* Free the memory allocated to our structure */
    free(params);

    return 0;
}
