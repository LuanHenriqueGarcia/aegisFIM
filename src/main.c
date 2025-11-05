#include "aegisfim.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#ifdef _WIN32
  #include <windows.h>
#else
  #include <unistd.h>
  #ifdef __linux__
    #include <sys/inotify.h>
  #endif
#endif

static void usage(const char *prog){
    fprintf(stderr,
        "Uso (português):\n"
        "  %s verificar [-r <dir>] [-b <baseline.tsv>] [--json <arquivo>]\n"
        "      -> cria baseline se faltar, faz 1 verificação e sai\n"
        "  %s vigiar    [-r <dir>] [-b <baseline.tsv>] [-i <seg>] [--realtime]\n"
        "      -> modo contínuo; --realtime usa inotify (Linux)\n"
        "  %s interface [-r <dir>] [-b <baseline.tsv>] [-i <seg>]\n"
        "\nComandos originais (também funcionam):\n"
        "  %s auto  [-r <dir>] [-b <baseline.tsv>] [-i <seg>]\n"
        "  %s init  [-r <dir>] [-b <baseline.tsv>]\n"
        "  %s check [-r <dir>] [-b <baseline.tsv>]\n"
        "  %s watch [-r <dir>] [-b <baseline.tsv>] [-i <seg>]\n"
        "  %s tui   [-r <dir>] [-b <baseline.tsv>] [-i <seg>]\n",
        prog, prog, prog, prog, prog, prog, prog, prog
    );
}

static int parse_int(const char *s, int *out){
    char *end=NULL; long v = strtol(s, &end, 10);
    if(!s || end==s || *end!='\0' || v<=0) return -1;
    *out = (int)v; return 0;
}

static void ensure_baseline(const char *root, const char *basefile){
    RecVec tmp;
    if(baseline_load_tsv(basefile,&tmp)!=0){
        RecVec v; scan_tree(root,&v); stable_sort(&v);
        if(baseline_save_tsv(basefile,&v)!=0){
            fprintf(stderr,"erro salvando baseline\n"); vec_free(&v); exit(2);
        }
        printf("baseline criada com %zu arquivos -> %s\n", v.len, basefile);
        vec_free(&v);
    } else {
        vec_free(&tmp);
    }
}

static int do_check_once(const char *root, const char *basefile, const char *json_out){
    RecVec base; if(baseline_load_tsv(basefile,&base)!=0){ fprintf(stderr,"erro carregando baseline\n"); return 2; }
    stable_sort(&base);
    RecVec curr; scan_tree(root,&curr); stable_sort(&curr);

    DiffSummary s = diff_and_report(&base,&curr);
    printf("\nResumo: +%zu  -%zu  ~%zu  =%zu  (total atual: %zu)\n",
        s.added, s.removed, s.modified, s.unchanged, curr.len);

    if(json_out){
        FILE *jf=fopen(json_out,"wb");
        if(jf){
            time_t t=time(NULL);
            fprintf(jf,"{ \"dir\":\"%s\", \"tested\":%zu, \"added\":%zu, \"removed\":%zu, \"modified\":%zu, \"unchanged\":%zu, \"ts\":%ld }\n",
                    root, curr.len, s.added, s.removed, s.modified, s.unchanged, (long)t);
            fclose(jf);
            printf("JSON salvo em %s\n", json_out);
        }else{
            fprintf(stderr,"Falha ao abrir %s\n", json_out);
        }
    }

    vec_free(&base); vec_free(&curr);
    return (s.modified>0)? 1 : 0;
}

int main(int argc, char **argv){
    if(argc<2){ usage(argv[0]); return 1; }
    const char *cmd = argv[1];

    const char *root=".";
    const char *basefile=NULL;
    const char *json_out=NULL;
    int interval=3;
    int realtime=0;

    for(int i=2;i<argc;i++){
        if(strcmp(argv[i],"-r")==0 && i+1<argc) root=argv[++i];
        else if(strcmp(argv[i],"-b")==0 && i+1<argc) basefile=argv[++i];
        else if(strcmp(argv[i],"-i")==0 && i+1<argc){
            if(parse_int(argv[++i], &interval)!=0){ fprintf(stderr,"Intervalo inválido em -i\n"); return 1; }
        }
        else if(strcmp(argv[i],"--json")==0 && i+1<argc) json_out=argv[++i];
        else if(strcmp(argv[i],"--realtime")==0) realtime=1;
    }

    char default_base[1024];
    if(!basefile){
        snprintf(default_base, sizeof(default_base), "%s/%s", root, "aegisfim.baseline.tsv");
        basefile = default_base;
    }

    if(strcmp(cmd,"verificar")==0){
        ensure_baseline(root, basefile);
        return do_check_once(root, basefile, json_out);
    }

    if(strcmp(cmd,"vigiar")==0){
#ifndef _WIN32
  #ifdef __linux__
        if(realtime){
            int fd = inotify_init1(IN_NONBLOCK);
            if(fd<0){ perror("inotify_init1"); return 2; }
            int wd = inotify_add_watch(fd, root,
                        IN_CREATE|IN_DELETE|IN_MODIFY|IN_MOVED_FROM|IN_MOVED_TO|
                        IN_ATTRIB|IN_DELETE_SELF|IN_MOVE_SELF|IN_CLOSE_WRITE);
            if(wd<0){ perror("inotify_add_watch"); return 2; }

            printf("[realtime] monitorando %s (agrupando eventos a cada %ds)\n", root, interval);
            for(;;){
                char buf[8192];
                (void)read(fd, buf, sizeof buf);
                do_check_once(root, basefile, NULL);
                struct timespec ts={.tv_sec=interval,.tv_nsec=0};
                nanosleep(&ts,NULL);
            }
        }
  #else
        (void)realtime;
  #endif
#endif
        for(;;){
            RecVec base; if(baseline_load_tsv(basefile,&base)!=0){ fprintf(stderr,"erro carregando baseline\n"); return 2; }
            stable_sort(&base);
            RecVec curr; scan_tree(root,&curr); stable_sort(&curr);
            DiffSummary s = diff_and_report(&base,&curr);
            printf("[tick] +%zu -%zu ~%zu =%zu\n", s.added, s.removed, s.modified, s.unchanged);
            vec_free(&base); vec_free(&curr);
#ifdef _WIN32
            Sleep(interval*1000);
#else
            struct timespec ts = { .tv_sec = interval, .tv_nsec = 0 };
            nanosleep(&ts, NULL);
#endif
        }
    }

    if(strcmp(cmd,"interface")==0){
        ensure_baseline(root, basefile);
        return run_tui(root, basefile, interval);
    }


    if(strcmp(cmd,"auto")==0){
        RecVec base;
        if(baseline_load_tsv(basefile,&base)!=0){
            RecVec v; scan_tree(root,&v); stable_sort(&v);
            if(baseline_save_tsv(basefile,&v)!=0){
                fprintf(stderr,"erro salvando baseline\n"); vec_free(&v); return 2;
            }
            printf("baseline criada com %zu arquivos -> %s\n", v.len, basefile);
            vec_free(&v);
        }else{
            vec_free(&base);
        }
        for(;;){
            RecVec b; if(baseline_load_tsv(basefile,&b)!=0){ fprintf(stderr,"erro carregando baseline\n"); return 2; }
            stable_sort(&b);
            RecVec c; scan_tree(root,&c); stable_sort(&c);
            DiffSummary s = diff_and_report(&b,&c);
            printf("[tick] +%zu -%zu ~%zu =%zu\n", s.added, s.removed, s.modified, s.unchanged);
            vec_free(&b); vec_free(&c);
#ifdef _WIN32
            Sleep(interval*1000);
#else
            struct timespec ts = { .tv_sec = interval, .tv_nsec = 0 };
            nanosleep(&ts, NULL);
#endif
        }
    }
    else if(strcmp(cmd,"init")==0){
        RecVec v; scan_tree(root,&v); stable_sort(&v);
        if(baseline_save_tsv(basefile,&v)!=0){ fprintf(stderr,"erro salvando baseline\n"); vec_free(&v); return 2; }
        printf("baseline criada com %zu arquivos -> %s\n", v.len, basefile);
        vec_free(&v);
        return 0;
    }
    else if(strcmp(cmd,"check")==0){
        return do_check_once(root, basefile, json_out);
    }
    else if(strcmp(cmd,"watch")==0){
        for(;;){
            RecVec base; if(baseline_load_tsv(basefile,&base)!=0){ fprintf(stderr,"erro carregando baseline\n"); return 2; }
            stable_sort(&base);
            RecVec curr; scan_tree(root,&curr); stable_sort(&curr);
            DiffSummary s = diff_and_report(&base,&curr);
            printf("[tick] +%zu -%zu ~%zu =%zu\n", s.added, s.removed, s.modified, s.unchanged);
            vec_free(&base); vec_free(&curr);
#ifdef _WIN32
            Sleep(interval*1000);
#else
            struct timespec ts = { .tv_sec = interval, .tv_nsec = 0 };
            nanosleep(&ts, NULL);
#endif
        }
    }
    else if(strcmp(cmd,"tui")==0){
        ensure_baseline(root, basefile);
        return run_tui(root, basefile, interval);
    }
    else{
        usage(argv[0]); return 1;
    }
}