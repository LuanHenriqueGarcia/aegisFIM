#include "aegisfim.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <dirent.h>
#include <limits.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#ifdef __linux__
#include <sys/inotify.h>
#endif
#endif

#ifndef MAX_WATCHES
#define MAX_WATCHES 1024
#endif

static int watch_fds[MAX_WATCHES];
static char *watch_paths[MAX_WATCHES];
static int watch_count = 0;

static void usage(const char *prog)
{
    fprintf(stderr,
            "Uso (português):\n"
            "  %s verificar [-r <dir>] [-b <baseline.tsv>] [--json <arquivo>] [--sarif <arquivo>]\n"
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
            prog, prog, prog, prog, prog, prog, prog, prog);
}

static int parse_int(const char *s, int *out)
{
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (!s || end == s || *end != '\0' || v <= 0)
        return -1;
    *out = (int)v;
    return 0;
}

static void ensure_baseline(const char *root, const char *basefile)
{
    RecVec tmp;
    if (baseline_load_tsv(basefile, &tmp) != 0)
    {
        RecVec v;
        scan_tree(root, &v);
        stable_sort(&v);
        if (baseline_save_tsv(basefile, &v) != 0)
        {
            fprintf(stderr, "erro salvando baseline\n");
            vec_free(&v);
            exit(2);
        }
        printf("baseline criada com %zu arquivos -> %s\n", v.len, basefile);
        vec_free(&v);
    }
    else
    {
        vec_free(&tmp);
    }
}

extern int do_check_once(const char *root, const char *basefile, const char *json_out, const char *sarif_out);

#ifdef __linux__
static void watch_recursive(int fd, const char *path)
{
    if (watch_count >= MAX_WATCHES)
        return;
    int wd = inotify_add_watch(fd, path, IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF | IN_CLOSE_WRITE);
    if (wd < 0)
        return;
    watch_fds[watch_count] = wd;
    watch_paths[watch_count] = strdup(path);
    watch_count++;

    DIR *d = opendir(path);
    if (!d)
        return;
    struct dirent *de;
    while ((de = readdir(d)))
    {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", path, de->d_name);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISDIR(st.st_mode))
        {
            watch_recursive(fd, full);
        }
    }
    closedir(d);
}
#endif

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        usage(argv[0]);
        return 1;
    }
    const char *cmd = argv[1];

    const char *root = ".";
    const char *basefile = NULL;
    const char *json_out = NULL;
    const char *sarif_out = NULL;
    int interval = 3;
    int realtime = 0;

    for (int i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "-r") == 0 && i + 1 < argc)
            root = argv[++i];
        else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc)
            basefile = argv[++i];
        else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc)
        {
            if (parse_int(argv[++i], &interval) != 0)
            {
                fprintf(stderr, "Intervalo inválido em -i\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "--json") == 0 && i + 1 < argc)
            json_out = argv[++i];
        else if (strcmp(argv[i], "--sarif") == 0 && i + 1 < argc)
            sarif_out = argv[++i];
        else if (strcmp(argv[i], "--realtime") == 0)
            realtime = 1;
    }

    char default_base[1024];
    if (!basefile)
    {
        snprintf(default_base, sizeof(default_base), "%s/%s", root, "aegisfim.baseline.tsv");
        basefile = default_base;
    }

    if (strcmp(cmd, "verificar") == 0)
    {
        ensure_baseline(root, basefile);
        return do_check_once(root, basefile, json_out, sarif_out);
    }

    if (strcmp(cmd, "check") == 0)
    {
        return do_check_once(root, basefile, json_out, sarif_out);
    }
   if (strcmp(cmd, "init") == 0) {
    RecVec v;
    scan_tree(root, &v);
    stable_sort(&v);
    if (baseline_save_tsv(basefile, &v) != 0) {
        fprintf(stderr, "erro salvando baseline\n");
        vec_free(&v);
        return 2;
    }
    printf("baseline criada com %zu arquivos -> %s\n", v.len, basefile);
    vec_free(&v);
    return 0;
}


    usage(argv[0]);
    return 1;
}
