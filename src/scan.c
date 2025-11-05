#include "aegisfim.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifndef _WIN32
  #include <dirent.h>
  #include <unistd.h>
  #include <fnmatch.h>
#else
  #include <windows.h>
  #include <io.h>
#endif


static int is_ignored_dir(const char *name){
    return strcmp(name,".git")==0 || strcmp(name,"node_modules")==0 ||
           strcmp(name,"dist")==0  || strcmp(name,"build")==0 ||
           strcmp(name,"vendor")==0 || strcmp(name,".aegisfim")==0;
}

static int is_ignored_file_name(const char *name){
    return strcmp(name,"aegisfim.baseline.tsv")==0;
}

#ifndef _WIN32
static char **ign_globs = NULL;
static size_t ign_n = 0;
static int ign_loaded = 0;
#endif

static char* join_path(const char *a, const char *b){
    size_t la=strlen(a), lb=strlen(b);
#ifdef _WIN32
    int need_sep = (la>0 && a[la-1]!='\\' && a[la-1]!='/');
#else
    int need_sep = (la>0 && a[la-1]!='/');
#endif
    char *out = (char*)malloc(la + need_sep + lb + 1);
    memcpy(out, a, la);
#ifdef _WIN32
    if(need_sep){ out[la]='\\'; la++; }
#else
    if(need_sep){ out[la]='/'; la++; }
#endif
    memcpy(out+la, b, lb);
    out[la+lb] = '\0';
    return out;
}

#ifndef _WIN32
static void load_ignore_list_once(const char* root){
    if(ign_loaded) return; ign_loaded = 1;
    char *path = join_path(root, ".aegisfimignore");
    FILE *f = fopen(path, "r");
    if(!f){ free(path); return; }
    char line[512];
    while(fgets(line, sizeof line, f)){
        char *p=line;
        while(*p==' '||*p=='\t') p++;
        if(*p=='#' || *p=='\n' || *p=='\0') continue;
        p[strcspn(p,"\r\n")] = 0;
        ign_globs = (char**)realloc(ign_globs, (ign_n+1)*sizeof(char*));
        ign_globs[ign_n++] = strdup(p);
    }
    fclose(f);
    free(path);
}

static int is_glob_ignored(const char *relpath){
    for(size_t i=0;i<ign_n;i++){
        if(fnmatch(ign_globs[i], relpath, FNM_PATHNAME|FNM_PERIOD) == 0) return 1;
    }
    return 0;
}
#else
static void load_ignore_list_once(const char* root){ (void)root; }
static int is_glob_ignored(const char *relpath){ (void)relpath; return 0; }
#endif


static int is_regular_file(const char *path){
#ifdef _WIN32
    struct _stat64 st;
    if(_stat64(path,&st)!=0) return 0;
    return (st.st_mode & _S_IFREG)!=0;
#else
    struct stat st;
    if(lstat(path,&st)!=0) return 0;
    return S_ISREG(st.st_mode);
#endif
}


#ifndef _WIN32
static int scan_dir(const char *root, const char *rel, RecVec *out){
    char *base = rel? join_path(root, rel) : strdup(root);
    DIR *d = opendir(base);
    if(!d){ free(base); return 0; }
    struct dirent *e;
    while((e=readdir(d))){
        if(strcmp(e->d_name,".")==0 || strcmp(e->d_name,"..")==0) continue;
        if(is_ignored_dir(e->d_name)) continue;

        char *subrel = rel? join_path(rel,e->d_name) : strdup(e->d_name);
        char *full   = join_path(root, subrel);

        if(is_glob_ignored(subrel)){ free(subrel); free(full); continue; }

        struct stat st;
        if(lstat(full,&st)==0 && S_ISDIR(st.st_mode)){
            scan_dir(root, subrel, out);
            free(subrel);
            free(full);
            continue;
        }

        if(is_regular_file(full)){

            const char *leaf = strrchr(subrel, '/');
            leaf = leaf ? leaf + 1 : subrel;
            if(is_ignored_file_name(leaf)){ free(subrel); free(full); continue; }

            FileRec r = (FileRec){0};
            r.path = subrel;
            if(sha256_file(full, r.sha256, &r.size, &r.mtime)==0){
                vec_push(out, r);
            }else{
                free(subrel);
            }
            free(full);
        }else{
            free(subrel);
            free(full);
        }
    }
    closedir(d);
    free(base);
    return 0;
}
#else
static int scan_dir(const char *root, const char *rel, RecVec *out){
    char *base = rel? join_path(root, rel) : strdup(root);
    char *pattern = join_path(base, "*");
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(pattern, &ffd);
    if(hFind==INVALID_HANDLE_VALUE){ free(pattern); free(base); return 0; }
    do{
        const char *n = ffd.cFileName;
        if(strcmp(n,".")==0 || strcmp(n,"..")==0) continue;
        if(is_ignored_dir(n)) continue;

        char *subrel = rel? join_path(rel,n) : strdup(n);
        char *full   = join_path(root, subrel);

        if(!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && is_regular_file(full)){
            const char *leaf = strrchr(subrel, '\\');
            leaf = leaf ? leaf + 1 : subrel;
            if(is_ignored_file_name(leaf)){ free(subrel); free(full); continue; }

            FileRec r = (FileRec){0};
            r.path = subrel;
            if(sha256_file(full, r.sha256, &r.size, &r.mtime)==0){
                vec_push(out, r);
            }else{
                free(subrel);
            }
            free(full);
        }else if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY){
            scan_dir(root, subrel, out);
            free(subrel);
            free(full);
        }else{
            free(subrel);
            free(full);
        }
    } while(FindNextFileA(hFind, &ffd)!=0);
    FindClose(hFind);
    free(pattern);
    free(base);
    return 0;
}
#endif

int scan_tree(const char *root, RecVec *out){
    vec_init(out);
    load_ignore_list_once(root);
    return scan_dir(root, NULL, out);
}

int stable_sort(RecVec *v){
    qsort(v->items, v->len, sizeof(FileRec), rec_cmp_path);
    return 0;
}
