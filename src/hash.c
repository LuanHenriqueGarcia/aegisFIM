#include "aegisfim.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#else
#include <unistd.h>
#include <fcntl.h>
#endif

static uint64_t file_mtime_sec(const char *path){
#ifdef _WIN32
    struct _stat64 st;
    if(_stat64(path, &st)==0) return (uint64_t)st.st_mtime;
#else
    struct stat st;
    if(stat(path, &st)==0) return (uint64_t)st.st_mtime;
#endif
    return 0;
}

int sha256_file(const char *path, unsigned char out[32], uint64_t *out_size, uint64_t *out_mtime){
    FILE *f = fopen(path, "rb");
    if(!f) return -1;

    unsigned char buf[1<<15];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(!ctx){ fclose(f); return -2; }
    if(1!=EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)){ EVP_MD_CTX_free(ctx); fclose(f); return -3; }

    uint64_t total=0;
    size_t r;
    while((r=fread(buf,1,sizeof(buf),f))>0){
        total += (uint64_t)r;
        if(total > AEGIS_MAX_FILE_SIZE){
            EVP_MD_CTX_free(ctx); fclose(f); return -4;
        }
        if(1!=EVP_DigestUpdate(ctx, buf, r)){ EVP_MD_CTX_free(ctx); fclose(f); return -5; }
    }
    if(ferror(f)){ EVP_MD_CTX_free(ctx); fclose(f); return -6; }

    unsigned int mdlen=0;
    if(1!=EVP_DigestFinal_ex(ctx, out, &mdlen)){ EVP_MD_CTX_free(ctx); fclose(f); return -7; }
    EVP_MD_CTX_free(ctx);
    fclose(f);

    if(out_size)  *out_size = total;
    if(out_mtime) *out_mtime = file_mtime_sec(path);
    return 0;
}
