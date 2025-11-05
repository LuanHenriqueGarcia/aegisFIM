#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

typedef struct { int *v; int n, cap; } Vec;
static void vpush(Vec *a, int x){
    if(a->n==a->cap){
        a->cap = a->cap ? a->cap*2 : 256;
        a->v = realloc(a->v, a->cap * sizeof(int));
    }
    a->v[a->n++] = x;
}

static void parse_ports(const char *spec, Vec *out){
    char *dup = strdup(spec ? spec : "1-1024");
    for(char *tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")){
        int a,b;
        if(sscanf(tok, "%d-%d", &a, &b) == 2){
            if(a<1) a=1; if(b>65535) b=65535; if(a>b){ int t=a; a=b; b=t; }
            for(int p=a; p<=b; p++) vpush(out, p);
        } else {
            int p = atoi(tok);
            if(p>=1 && p<=65535) vpush(out, p);
        }
    }
    free(dup);
    int w=0;
    for(int i=0;i<out->n;i++){
        int seen=0;
        for(int j=0;j<w;j++) if(out->v[j]==out->v[i]){ seen=1; break; }
        if(!seen) out->v[w++]=out->v[i];
    }
    out->n = w;
}

static int set_nonblock(int fd){
    int fl = fcntl(fd, F_GETFL, 0);
    if(fl<0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

typedef struct { int fd; int port; } Conn;

static void usage(const char *p){
    fprintf(stderr,
        "Uso:\n"
        "  %s -h <host> [-p <ports>] [-c <concorrencia>] [-t <timeout_ms>] [-v] [--json <arquivo>]\n"
        "ex.: %s -h 127.0.0.1 -p 1-1024,3306,5432 -c 300 -t 250 -v --json out.json\n", p,p);
}

int main(int argc, char **argv){
    const char *host = NULL, *portspec = "1-1024";
    int conc = 200, tmo_ms = 300;
    int verbose = 0;
    const char *json_out = NULL;

    for(int i=1;i<argc;i++){
        if(strcmp(argv[i],"-h")==0 && i+1<argc) host = argv[++i];
        else if(strcmp(argv[i],"-p")==0 && i+1<argc) portspec = argv[++i];
        else if(strcmp(argv[i],"-c")==0 && i+1<argc) conc = atoi(argv[++i]);
        else if(strcmp(argv[i],"-t")==0 && i+1<argc) tmo_ms = atoi(argv[++i]);
        else if(strcmp(argv[i],"-v")==0) verbose = 1;
        else if(strcmp(argv[i],"--json")==0 && i+1<argc) json_out = argv[++i];
    }

    if(!host){ usage(argv[0]); return 1; }
    if(conc<1) conc=1; if(conc>5000) conc=5000;
    if(tmo_ms<50) tmo_ms=50; if(tmo_ms>5000) tmo_ms=5000;

    struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;
    int gai = getaddrinfo(host, NULL, &hints, &res);
    if(gai!=0){ fprintf(stderr,"getaddrinfo: %s\n", gai_strerror(gai)); return 2; }

    char ipstr[INET6_ADDRSTRLEN] = "?";
    void *addrptr = NULL;
    int family = res->ai_family;
    if(family==AF_INET)  addrptr=&((struct sockaddr_in*)res->ai_addr)->sin_addr;
    if(family==AF_INET6) addrptr=&((struct sockaddr_in6*)res->ai_addr)->sin6_addr;
    if(addrptr) inet_ntop(family, addrptr, ipstr, sizeof(ipstr));
    printf("Alvo: %s (%s)\n", host, ipstr);
    if(verbose){
        printf("Params: ports=\"%s\" conc=%d timeout=%dms\n", portspec, conc, tmo_ms);
    }

    Vec ports = {0};
    parse_ports(portspec, &ports);
    if(ports.n==0){ fprintf(stderr,"Sem portas válidas.\n"); freeaddrinfo(res); return 1; }

    Conn *conns = calloc(conc, sizeof(Conn));
    struct pollfd *pfds = calloc(conc, sizeof(struct pollfd));
    for(int i=0;i<conc;i++){ conns[i].fd=-1; pfds[i].fd=-1; }

    int next=0, active=0, open_count=0;
    Vec open_ports = {0};

    while(next < ports.n || active > 0){
        while(active < conc && next < ports.n){
            struct sockaddr_storage ss; socklen_t slen=0;
            if(family==AF_INET){
                struct sockaddr_in sin = *(struct sockaddr_in*)res->ai_addr;
                sin.sin_port = htons(ports.v[next]);
                memcpy(&ss,&sin,sizeof(sin)); slen=sizeof(sin);
            }else{
                struct sockaddr_in6 sin6 = *(struct sockaddr_in6*)res->ai_addr;
                sin6.sin6_port = htons(ports.v[next]);
                memcpy(&ss,&sin6,sizeof(sin6)); slen=sizeof(sin6);
            }
            int fd = socket(family, SOCK_STREAM, 0);
            if(fd<0){ next++; continue; }
            set_nonblock(fd);
            (void)connect(fd, (struct sockaddr*)&ss, slen);

            int slot=-1;
            for(int i=0;i<conc;i++) if(pfds[i].fd==-1){ slot=i; break; }
            if(slot==-1){ close(fd); break; }

            conns[slot].fd   = fd;
            conns[slot].port = ports.v[next];
            pfds[slot].fd    = fd;
            pfds[slot].events= POLLOUT;
            active++;
            next++;
        }

        int n = poll(pfds, conc, tmo_ms);
        if(n <= 0){
            for(int i=0;i<conc;i++){
                if(pfds[i].fd!=-1){
                    int err=0; socklen_t elen=sizeof(err);
                    getsockopt(pfds[i].fd, SOL_SOCKET, SO_ERROR, &err, &elen);
                    if(err==0){
                       printf("OPEN  %5d\n", conns[i].port);
                       open_count++;
                       vpush(&open_ports, conns[i].port);
                    }
                    close(pfds[i].fd);
                    pfds[i].fd=-1; conns[i].fd=-1; active--;
                }
            }
            continue;
        }

        for(int i=0;i<conc && n>0;i++){
            if(pfds[i].fd==-1) continue;
            if(pfds[i].revents & (POLLOUT|POLLERR|POLLHUP)){
                n--;
                int err=0; socklen_t elen=sizeof(err);
                getsockopt(pfds[i].fd, SOL_SOCKET, SO_ERROR, &err, &elen);
                if(err==0){
                    printf("OPEN  %5d\n", conns[i].port);
                    open_count++;
                    vpush(&open_ports, conns[i].port);
                }
                close(pfds[i].fd);
                pfds[i].fd=-1; conns[i].fd=-1; active--;
            }
        }
    }

   clock_gettime(CLOCK_MONOTONIC, &t1);
   double dur_ms = (t1.tv_sec - t0.tv_sec)*1000.0 + (t1.tv_nsec - t0.tv_nsec)/1e6;
   printf("\nTotal abertas: %d de %d portas testadas. (%.2f ms)\n", open_count, ports.n, dur_ms);

    if(json_out){
        FILE *jf = fopen(json_out, "wb");
        if(jf){
            fprintf(jf, "{\n  \"host\": \"%s\",\n  \"ip\": \"%s\",\n  \"tested\": %d,\n  \"open\": [",
                    host, ipstr, ports.n);
            for(int i=0;i<open_ports.n;i++){
                fprintf(jf, "%s%d", (i?", ":""), open_ports.v[i]);
            }
            fprintf(jf, "],\n  \"duration_ms\": %.2f\n}\n", dur_ms);
            fclose(jf);
            if(verbose) printf("JSON salvo em %s\n", json_out);
        } else {
            fprintf(stderr, "Falha ao abrir %s para escrita.\n", json_out);
        }
    }
    freeaddrinfo(res);
    free(conns); free(pfds); free(ports.v); free(open_ports.v);
    return 0;
}
