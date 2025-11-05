#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

typedef struct { int *v; int n, cap; } VecI;
static void vpush(VecI *a, int x){ if(a->n==a->cap){ a->cap = a->cap? a->cap*2 : 64; a->v = realloc(a->v, a->cap*sizeof(int)); } a->v[a->n++] = x; }

static void parse_ports(const char *spec, VecI *out){

    char *dup = strdup(spec?spec:"2222,8080,9000");
    for(char *tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")){
        int a,b;
        if(sscanf(tok, "%d-%d", &a, &b) == 2){
            if(a<1) a=1; if(b>65535) b=65535; if(a>b){ int t=a; a=b; b=t; }
            for(int p=a; p<=b; ++p) vpush(out, p);
        }else{
            int p = atoi(tok);
            if(p>=1 && p<=65535) vpush(out, p);
        }
    }
    free(dup);

    int w=0;
    for(int i=0;i<out->n;i++){
        int seen=0; for(int j=0;j<w;j++) if(out->v[j]==out->v[i]){ seen=1; break; }
        if(!seen) out->v[w++] = out->v[i];
    }
    out->n = w;
}

static int set_nonblock(int fd){
    int fl = fcntl(fd, F_GETFL, 0);
    if(fl<0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

typedef struct {
    int fd;
    int local_port;
    time_t connected_at;
    int closed;
} Client;

typedef struct {
    int fd;
    int port;
} Listener;

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int s){ (void)s; g_stop = 1; }

static void ensure_parent_dir(const char *path){

    const char *slash = strrchr(path, '/');
    if(!slash) return;
    size_t len = (size_t)(slash - path);
    char *dir = malloc(len+1);
    memcpy(dir, path, len); dir[len]='\0';
    struct stat st;
    if(stat(dir, &st)!=0){

        mkdir(dir, 0755);
    }
    free(dir);
}

static void now_iso8601(char *buf, size_t n){
    time_t t = time(NULL);
    struct tm tm; localtime_r(&t, &tm);
    strftime(buf, n, "%Y-%m-%dT%H:%M:%S%z", &tm);
}

int main(int argc, char **argv){
    const char *portspec = NULL;
    const char *outlog = ".aegisfim/honey.log";
    const char *banner = NULL;
    int max_clients = 1024;

    for(int i=1;i<argc;i++){
        if(strcmp(argv[i],"-p")==0 && i+1<argc) portspec = argv[++i];
        else if(strcmp(argv[i],"-o")==0 && i+1<argc) outlog = argv[++i];
        else if(strcmp(argv[i],"-b")==0 && i+1<argc) banner = argv[++i];
        else if(strcmp(argv[i],"-m")==0 && i+1<argc) max_clients = atoi(argv[++i]);
        else if(!strcmp(argv[i],"-h") || !strcmp(argv[i],"--help")){
            fprintf(stderr,
                "Uso: %s [-p 2222,8080,9000] [-o arquivo.log] [-b \"banner opcional\"] [-m max_clientes]\n"
                "Obs: portas <1024 exigem sudo.\n", argv[0]);
            return 0;
        }
    }
    if(max_clients < 16) max_clients = 16;
    if(max_clients > 16384) max_clients = 16384;


    VecI ports = {0};
    parse_ports(portspec ? portspec : "2222,8080,9000", &ports);
    if(ports.n == 0){ fprintf(stderr,"Sem portas válidas.\n"); return 1; }


    ensure_parent_dir(outlog);
    FILE *logf = fopen(outlog, "a");
    if(!logf){ perror("fopen log"); return 2; }
    setvbuf(logf, NULL, _IOLBF, 0);


    Listener *ls = calloc(ports.n, sizeof(Listener));
    int lcount = 0;
    for(int i=0;i<ports.n;i++){
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if(fd<0){ perror("socket"); continue; }
        int yes=1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        struct sockaddr_in sa; memset(&sa,0,sizeof(sa));
        sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_ANY);
        sa.sin_port = htons(ports.v[i]);
        if(bind(fd, (struct sockaddr*)&sa, sizeof(sa))<0){
            fprintf(stderr,"bind %d: %s\n", ports.v[i], strerror(errno));
            close(fd); continue;
        }
        if(listen(fd, 256)<0){ perror("listen"); close(fd); continue; }
        set_nonblock(fd);
        ls[lcount].fd = fd;
        ls[lcount].port = ports.v[i];
        lcount++;
    }
    if(lcount == 0){ fprintf(stderr,"Nenhuma porta conseguiu escutar.\n"); return 3; }

    printf("Honeypot ativo em %d porta(s): ", lcount);
    for(int i=0;i<lcount;i++){ printf("%s%d", i?", ":"", ls[i].port); }
    printf("\nLog: %s\n", outlog);
    if(banner) printf("Banner ativo: \"%s\"\n", banner);


    int cap = lcount + max_clients;
    struct pollfd *pfds = calloc(cap, sizeof(struct pollfd));
    Client *cl = calloc(max_clients, sizeof(Client));
    for(int i=0;i<cap;i++){ pfds[i].fd=-1; pfds[i].events=0; }
    for(int i=0;i<max_clients;i++){ cl[i].fd=-1; cl[i].closed=1; }


    for(int i=0;i<lcount;i++){
        pfds[i].fd = ls[i].fd;
        pfds[i].events = POLLIN;
    }
    int base = lcount; 
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    char tbuf[64];
    char rbuf[1024];

    while(!g_stop){
        int n = poll(pfds, cap, 2000);
        if(n < 0){
            if(errno == EINTR) continue;
            perror("poll"); break;
        }
        if(n == 0) continue;

        for(int i=0;i<lcount;i++){
            if(pfds[i].revents & POLLIN){
                for(;;){
                    struct sockaddr_in ra; socklen_t ralen = sizeof(ra);
                    int cfd = accept(ls[i].fd, (struct sockaddr*)&ra, &ralen);
                    if(cfd < 0){
                        if(errno==EAGAIN || errno==EWOULDBLOCK) break;
                        perror("accept"); break;
                    }
                    set_nonblock(cfd);

                    int slot=-1;
                    for(int k=0;k<max_clients;k++) if(cl[k].closed){ slot=k; break; }
                    if(slot==-1){ close(cfd); break; }
                    cl[slot].fd = cfd;
                    cl[slot].local_port = ls[i].port;
                    cl[slot].connected_at = time(NULL);
                    cl[slot].closed = 0;
                    pfds[base+slot].fd = cfd;
                    pfds[base+slot].events = POLLIN | POLLHUP | POLLERR;


                    char ip[64]; inet_ntop(AF_INET, &ra.sin_addr, ip, sizeof(ip));
                    now_iso8601(tbuf, sizeof tbuf);
                    fprintf(logf, "%s ACCEPT port=%d from=%s:%d\n",
                            tbuf, ls[i].port, ip, ntohs(ra.sin_port));
                }
            }
        }

        for(int k=0;k<max_clients;k++){
            int idx = base + k;
            if(pfds[idx].fd < 0) continue;
            short ev = pfds[idx].revents;
            if(!ev) continue;

            int cfd = pfds[idx].fd;

            if(ev & POLLIN){
                ssize_t r = read(cfd, rbuf, sizeof(rbuf)-1);
                if(r > 0){
                    rbuf[r] = '\0';
                    struct sockaddr_in ra; socklen_t ralen=sizeof(ra);
                    getpeername(cfd, (struct sockaddr*)&ra, &ralen);
                    char ip[64]; inet_ntop(AF_INET, &ra.sin_addr, ip, sizeof(ip));
                    now_iso8601(tbuf, sizeof tbuf);
                    size_t show = (r>200)?200:(size_t)r;
                    for(size_t i=0;i<show;i++) if(rbuf[i]=='\n' || rbuf[i]=='\r') rbuf[i]=' ';

                    fprintf(logf, "%s DATA port=%d from=%s:%d bytes=%zd payload=\"%.*s\"\n",
                            tbuf, cl[k].local_port, ip, ntohs(ra.sin_port), r, (int)show, rbuf);

                    if(banner){
                        (void)write(cfd, banner, strlen(banner));
                        (void)write(cfd, "\r\n", 2);
                    }

                    close(cfd);
                    pfds[idx].fd = -1;
                    cl[k].closed = 1;
                }else{
                    close(cfd);
                    pfds[idx].fd = -1;
                    cl[k].closed = 1;
                }
            }
            if(ev & (POLLHUP | POLLERR)){
                close(cfd);
                pfds[idx].fd = -1;
                cl[k].closed = 1;
            }
        }
    }

    printf("\nEncerrando.\n");
    for(int i=0;i<lcount;i++) close(ls[i].fd);
    for(int i=0;i<max_clients;i++) if(!cl[i].closed && cl[i].fd>=0) close(cl[i].fd);
    fclose(logf);
    free(ls); free(pfds); free(cl); free(ports.v);
    return 0;
}
