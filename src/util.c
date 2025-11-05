#include "aegisfim.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void vec_init(RecVec *v){ v->items=NULL; v->len=0; v->cap=0; }

void vec_push(RecVec *v, FileRec rec){
    if(v->len==v->cap){
        size_t ncap = v->cap? v->cap*2 : 64;
        FileRec *n = (FileRec*)realloc(v->items, ncap*sizeof(FileRec));
        if(!n){ perror("realloc"); exit(2);}
        v->items=n; v->cap=ncap;
    }
    v->items[v->len++] = rec;
}

void vec_free(RecVec *v){
    if(!v) return;
    for(size_t i=0;i<v->len;i++) free(v->items[i].path);
    free(v->items);
    v->items=NULL; v->len=v->cap=0;
}

int rec_cmp_path(const void *a, const void *b){
    const FileRec *ra = (const FileRec*)a;
    const FileRec *rb = (const FileRec*)b;
    return strcmp(ra->path, rb->path);
}

void sha256_hex(const unsigned char in[32], char out_hex[65]){
    static const char *hex="0123456789abcdef";
    for(int i=0;i<32;i++){
        out_hex[i*2]   = hex[(in[i]>>4)&0xF];
        out_hex[i*2+1] = hex[in[i]&0xF];
    }
    out_hex[64]='\0';
}
