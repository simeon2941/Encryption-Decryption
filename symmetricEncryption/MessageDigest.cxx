
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>


#include <iostream>
using namespace std;

int main(int argc, char* argv[])
{

    int all = 0, count = 1000;
    struct timespec start, stop;
    srand(time(NULL));
    // hash value
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    // setup and create context
    EVP_MD_CTX* mdctx;
    mdctx = EVP_MD_CTX_create();

    // initialize hash function
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);


    // feed data to hash function

    FILE* fp;
    char str[1024];
    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("Could not open file %s", argv[1]);
        return 1;
    }
    // Run 1000 times encryption to get average time
    for (int i = 0; i < count; i++)
    {
        clock_gettime(CLOCK_REALTIME, &start);


        while (fgets(str, 1024, fp) != NULL)
        {
            EVP_DigestUpdate(mdctx, str, strlen(str));
        }
        clock_gettime(CLOCK_REALTIME, &stop);
        long start_time = start.tv_sec * 1000000000 + start.tv_nsec;
        long stop_time = stop.tv_sec * 1000000000 + stop.tv_nsec;
        all += stop_time - start_time;
    }
    fclose(fp);
    cout << "\nAverage time used for encryption: " << dec << (all / count)/1000.0 << " microseconds\n";
    // get hash value
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);

    cout << "Message digest is: ";
    for (unsigned int i = 0; i < md_len; i++)
        cout << hex << (int)md_value[i];
    cout << endl;

    // cleanup
    EVP_MD_CTX_destroy(mdctx);
    return 0;
}
