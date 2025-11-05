#include "aegisfim.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int baseline_save_tsv(const char *file, const RecVec *v){
    FILE *f = fopen(file, "wb");
    if(!f) return -1;
    for(size_t i=0;i<v->len;i++){
        char hex[65]; sha256_hex(v->items[i].sha256, hex);
        fprintf(f, "%s\t%llu\t%llu\t%s\n",
            v->items[i].path,
            (unsigned long long)v->items[i].size,
            (unsigned long long)v->items[i].mtime,
            hex
        );
    }
    fclose(f);
    return 0;
}

static int parse_hex32(const char *hex, unsigned char out[32]){
    for(int i=0;i<32;i++){
        unsigned int byte;
        if(sscanf(hex + i*2, "%2x", &byte)!=1) return -1;
        out[i]=(unsigned char)byte;
    }
    return 0;
}

int baseline_load_tsv(const char *file, RecVec *v){
    vec_init(v);
    FILE *f = fopen(file, "rb");
    if(!f) return -1;
    char *line=NULL; size_t cap=0;
    while(1){
        ssize_t nread;
#if defined(_WIN32)
        int c; size_t len=0;
        if(!line){ cap=1024; line=(char*)malloc(cap);}
        while((c=fgetc(f))!=EOF){
            if(len+1>=cap){ cap*=2; line=(char*)realloc(line,cap); }
            line[len++]=(char)c;
            if(c=='\n') break;
        }
        if(len==0 && feof(f)) break;
        line[len]='\0'; nread=(ssize_t)len;
#else
        nread = getline(&line, &cap, f);
        if(nread==-1) break;
#endif
        char *p=line; char *tok;

        tok = strsep(&p, "\t"); if(!tok) continue;
        char *path = strdup(tok);

        tok = strsep(&p, "\t"); if(!tok){ free(path); continue; }
        uint64_t size = strtoull(tok,NULL,10);

        tok = strsep(&p, "\t"); if(!tok){ free(path); continue; }
        uint64_t mtime = strtoull(tok,NULL,10);

        tok = strsep(&p, "\t\r\n"); if(!tok){ free(path); continue; }
        unsigned char h[32]; if(parse_hex32(tok,h)!=0){ free(path); continue; }

        FileRec r={0};
        r.path=path; r.size=size; r.mtime=mtime;
        memcpy(r.sha256, h, 32);
        vec_push(v,r);
    }
    free(line);
    fclose(f);
    return 0;
}

DiffSummary diff_and_report(const RecVec *base, const RecVec *curr){
    DiffSummary s={0};
    size_t i=0,j=0;
    while(i<base->len && j<curr->len){
        int c = strcmp(base->items[i].path, curr->items[j].path);
        if(c==0){
            if(memcmp(base->items[i].sha256, curr->items[j].sha256, 32)==0){
                s.unchanged++;
            }else{
                s.modified++;
                char hexb[65], hexc[65];
                sha256_hex(base->items[i].sha256, hexb);
                sha256_hex(curr->items[j].sha256, hexc);
                printf("[MOD] %s\n      old:%s\n      new:%s\n", curr->items[j].path, hexb, hexc);
            }
            i++; j++;
        }else if(c<0){
            s.removed++;
            printf("[DEL] %s\n", base->items[i].path);
            i++;
        }else{
            s.added++;
            printf("[ADD] %s\n", curr->items[j].path);
            j++;
        }
    }
    while(i<base->len){ s.removed++; printf("[DEL] %s\n", base->items[i++].path); }
    while(j<curr->len){ s.added++;  printf("[ADD] %s\n", curr->items[j++].path); }
    return s;
}
