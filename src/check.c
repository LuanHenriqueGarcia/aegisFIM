#include "aegisfim.h"
#include <stdio.h>
#include <time.h>


void write_sarif(const char *filename, const RecVec *base, const RecVec *curr) {
}

int do_check_once(const char *root, const char *basefile, const char *json_out, const char *sarif_out){
    RecVec b;
    if(baseline_load_tsv(basefile,&b)!=0){
        fprintf(stderr,"erro carregando baseline\n");
        return 2;
    }
    stable_sort(&b);

    RecVec c;
    scan_tree(root,&c);
    stable_sort(&c);

    DiffSummary s = diff_and_report(&b,&c);
    printf("[check] +%zu -%zu ~%zu =%zu (total:%zu)\n", s.added, s.removed, s.modified, s.unchanged, c.len);

    if(json_out){
        FILE *jf = fopen(json_out, "wb");
        if(jf){
            time_t t = time(NULL);
            fprintf(jf,
                    "{ \"dir\":\"%s\", \"tested\":%zu, \"added\":%zu, \"removed\":%zu, \"modified\":%zu, \"unchanged\":%zu, \"ts\":%ld }\n",
                    root, c.len, s.added, s.removed, s.modified, s.unchanged, (long)t);
            fclose(jf);
            printf("JSON salvo em %s\n", json_out);
        }else{
            fprintf(stderr,"Falha ao abrir %s\n", json_out);
        }
    }

    if(sarif_out){
        write_sarif(sarif_out, &b, &c);
        printf("SARIF salvo em %s\n", sarif_out);
    }

    vec_free(&b);
    vec_free(&c);
    return (s.modified>0)? 1 : 0;
}
