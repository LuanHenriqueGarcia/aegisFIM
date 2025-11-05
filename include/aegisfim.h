#ifndef AEGISFIM_H
#define AEGISFIM_H

#include <stddef.h>
#include <stdint.h>

#define AEGIS_MAX_FILE_SIZE (50ULL * 1024ULL * 1024ULL)

typedef struct {
    char   *path;
    uint64_t size;
    uint64_t mtime;
    unsigned char sha256[32];
} FileRec;

typedef struct {
    FileRec *items;
    size_t   len;
    size_t   cap;
} RecVec;

void   vec_init(RecVec *v);
void   vec_push(RecVec *v, FileRec rec);
void   vec_free(RecVec *v);
int    rec_cmp_path(const void *a, const void *b);
void   sha256_hex(const unsigned char in[32], char out_hex[65]);

int sha256_file(const char *path, unsigned char out[32], uint64_t *out_size, uint64_t *out_mtime);

int scan_tree(const char *root, RecVec *out);
int stable_sort(RecVec *v);

int baseline_save_tsv(const char *file, const RecVec *v);
int baseline_load_tsv(const char *file, RecVec *v);

typedef struct {
    size_t added, removed, modified, unchanged;
} DiffSummary;

DiffSummary diff_and_report(const RecVec *base, const RecVec *curr);

int run_tui(const char *root, const char *baseline, int interval);

#endif
