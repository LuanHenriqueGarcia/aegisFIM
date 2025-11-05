#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>

static void die(const char *m){ fprintf(stderr,"%s\n",m); exit(2); }
static double now_ms(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return ts.tv_sec*1000.0 + ts.tv_nsec/1e6; }

static int tcp_connect_host(const char *host, int port, int timeout_ms, char *ip_out, size_t ip_n){
    struct addrinfo hints={0}, *res=NULL;
    hints.ai_socktype=SOCK_STREAM; hints.ai_family=AF_UNSPEC;
    char pbuf[16]; snprintf(pbuf,sizeof pbuf,"%d",port);
    int rc=getaddrinfo(host,pbuf,&hints,&res); if(rc!=0) return -1;
    int fd=-1; for(struct addrinfo *ai=res; ai; ai=ai->ai_next){
        fd=socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);
        if(fd<0) continue;
        if(timeout_ms>0){
            struct timeval tv={timeout_ms/1000,(timeout_ms%1000)*1000};
            setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof tv);
            setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
        }
        if(connect(fd,ai->ai_addr,ai->ai_addrlen)==0){
            if(ip_out){
                if(ai->ai_family==AF_INET){
                    struct sockaddr_in *sa=(struct sockaddr_in*)ai->ai_addr;
                    inet_ntop(AF_INET,&sa->sin_addr,ip_out,(socklen_t)ip_n);
                }else if(ai->ai_family==AF_INET6){
                    struct sockaddr_in6 *sa=(struct sockaddr_in6*)ai->ai_addr;
                    inet_ntop(AF_INET6,&sa->sin6_addr,ip_out,(socklen_t)ip_n);
                }
            }
            freeaddrinfo(res); return fd;
        }
        close(fd); fd=-1;
    }
    freeaddrinfo(res); return -2;
}


static int fetch_public_ip(char *out, size_t n){
    int fd=tcp_connect_host("api.ipify.org",80,3000,NULL,0);
    if(fd<0) return -1;
    char req[]="GET /?format=text HTTP/1.0\r\nHost: api.ipify.org\r\nUser-Agent: aegisnet/1\r\n\r\n";
    if(write(fd,req,strlen(req))<0){ close(fd); return -1; }
    char buf[4096]; ssize_t r=read(fd,buf,sizeof buf -1);
    close(fd);
    if(r<=0) return -1; buf[r]=0;
    char *body=strstr(buf,"\r\n\r\n"); if(!body) return -1; body+=4;
    size_t len=strcspn(body,"\r\n"); if(len>=n) len=n-1;
    memcpy(out,body,len); out[len]=0;
    return 0;
}

static void list_ifaces(FILE *out){
    struct ifaddrs *ifas=NULL;
    if(getifaddrs(&ifas)!=0){ fprintf(out,"  \"ifaces\": []\n"); return; }
    fprintf(out,"  \"ifaces\": [\n");
    bool first=true;
    for(struct ifaddrs *it=ifas; it; it=it->ifa_next){
        if(!it->ifa_addr) continue;
        if(!(it->ifa_flags & IFF_UP)) continue;
        if(it->ifa_addr->sa_family!=AF_INET) continue;
        if(strcmp(it->ifa_name,"lo")==0) continue;
        char ip[64]; inet_ntop(AF_INET,&((struct sockaddr_in*)it->ifa_addr)->sin_addr,ip,sizeof ip);
        if(!first) fprintf(out,",\n");
        fprintf(out,"    {\"iface\":\"%s\",\"ipv4\":\"%s\"}", it->ifa_name, ip);
        first=false;
    }
    fprintf(out,"\n  ]\n");
    freeifaddrs(ifas);
}

static int read_default_gw(char *out, size_t n){
    FILE *f=fopen("/proc/net/route","r"); if(!f) return -1;
    char line[512]; // skip header
    if(!fgets(line,sizeof line,f)){ fclose(f); return -1; }
    while(fgets(line,sizeof line,f)){
        char iface[64]; unsigned long dest, gw, flags;
        int r=sscanf(line,"%63s %lx %lx %lx", iface, &dest, &gw, &flags);
        if(r>=3 && dest==0){
            struct in_addr ina; ina.s_addr= (uint32_t)gw;
            uint32_t x=(uint32_t)gw;
            uint8_t b0=x & 0xff, b1=(x>>8)&0xff, b2=(x>>16)&0xff, b3=(x>>24)&0xff;
            snprintf(out,n,"%u.%u.%u.%u", b0,b1,b2,b3);
            fclose(f); return 0;
        }
    }
    fclose(f); return -1;
}

static int cmd_netinfo(int json){
    char pub[64]="(falhou)";
    if(fetch_public_ip(pub,sizeof pub)!=0) strcpy(pub,"(sem internet?)");

    char gw[64]="(desconhecido)";
    read_default_gw(gw,sizeof gw);

    if(json){
        printf("{\n  \"public_ip\": \"%s\",\n", pub);
        printf("  \"gateway\": \"%s\",\n", gw);
        list_ifaces(stdout);
        printf("}\n");
    }else{
        printf("IP público: %s\n", pub);
        printf("Gateway  : %s\n", gw);
        printf("Interfaces:\n");
        struct ifaddrs *ifas=NULL;
        if(getifaddrs(&ifas)==0){
            for(struct ifaddrs *it=ifas; it; it=it->ifa_next){
                if(!it->ifa_addr) continue;
                if(!(it->ifa_flags & IFF_UP)) continue;
                if(it->ifa_addr->sa_family!=AF_INET) continue;
                if(strcmp(it->ifa_name,"lo")==0) continue;
                char ip[64]; inet_ntop(AF_INET,&((struct sockaddr_in*)it->ifa_addr)->sin_addr,ip,sizeof ip);
                printf("  - %s: %s\n", it->ifa_name, ip);
            }
            freeifaddrs(ifas);
        }
    }
    return 0;
}


typedef struct {
    char scheme[8]; char host[256]; int port; char path[512];
} Url;

static int parse_url(const char *u, Url *o){
    memset(o, 0, sizeof *o);
    strcpy(o->scheme, "http");
    strcpy(o->path, "/");

    if(!u || !*u) return -1;

    const char *rest = u;
    const char *p = strstr(u, "://");
    if (p) {
        size_t sl = (size_t)(p - u);
        if (sl == 0 || sl >= sizeof o->scheme) return -1;
        memcpy(o->scheme, u, sl);
        o->scheme[sl] = '\0';
        rest = p + 3;
    }

    const char *slash = strchr(rest, '/');
    char hostport[300];
    if (slash) {
        size_t hl = (size_t)(slash - rest);
        if (hl >= sizeof hostport) return -1;
        memcpy(hostport, rest, hl);
        hostport[hl] = '\0';

        size_t pl = strlen(slash);
        if (pl >= sizeof o->path) pl = sizeof o->path - 1;
        memcpy(o->path, slash, pl);
        o->path[pl] = '\0';
    } else {
        if (strlen(rest) >= sizeof hostport) return -1;
        strcpy(hostport, rest);
        o->path[0] = '/'; o->path[1] = '\0';
    }

    if (hostport[0] == '[') {
        char *rb = strchr(hostport, ']');
        if (!rb) return -1;
        *rb = '\0';
        size_t hlen = strlen(hostport + 1);
        if (hlen >= sizeof o->host) return -1;
        memcpy(o->host, hostport + 1, hlen + 1);

        if (rb[1] == ':') {
            o->port = atoi(rb + 2);
        }
    } else {
        char *colon = strrchr(hostport, ':');
        if (colon) {
            *colon = '\0';
            if (strlen(hostport) >= sizeof o->host) return -1;
            strcpy(o->host, hostport);
            o->port = atoi(colon + 1);
        } else {
            if (strlen(hostport) >= sizeof o->host) return -1;
            strcpy(o->host, hostport);
        }
    }

    if (o->port == 0) o->port = (strcmp(o->scheme, "https") == 0) ? 443 : 80;
    return 0;
}


static void x509_time(const ASN1_TIME *t, char *out, size_t n){
    BIO *b=BIO_new(BIO_s_mem());
    ASN1_TIME_print(b,t);
    int l=(int)BIO_read(b,out,(int)n-1); if(l<0) l=0; out[l]=0; BIO_free(b);
}

static int cmd_urlscan(const char *url, int json){
    Url u; if(parse_url(url,&u)!=0) die("URL inválida");
    char ip[128]=""; double t0=now_ms();
    int fd=tcp_connect_host(u.host,u.port,4000,ip,sizeof ip);
    double t1=now_ms();
    if(fd<0) die("conexão falhou");

    char resp[100*1024]; ssize_t used=0;
    int code=0; char server[256]="";
    char tls_ver[64]="", cert_cn[256]="", cert_issuer[256]="", cert_exp[128]="";

    if(strcmp(u.scheme,"https")==0){
        SSL_load_error_strings(); SSL_library_init();
        SSL_CTX *ctx=SSL_CTX_new(TLS_client_method());
        SSL *ssl=SSL_new(ctx);
        SSL_set_tlsext_host_name(ssl,u.host);
        SSL_set_fd(ssl,fd);
        if(SSL_connect(ssl)!=1){ SSL_free(ssl); SSL_CTX_free(ctx); close(fd); die("TLS falhou"); }
        const SSL_CIPHER *ciph=SSL_get_current_cipher(ssl);
        snprintf(tls_ver,sizeof tls_ver,"%s", SSL_get_version(ssl));

        char req[1024];
        snprintf(req,sizeof req,"HEAD %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: aegisnet/1\r\nConnection: close\r\n\r\n",u.path,u.host);
        SSL_write(ssl,req,(int)strlen(req));
        int r=0; do{ r=SSL_read(ssl,resp+used,(int)sizeof(resp)-1-(int)used); if(r>0) used+=r; }while(r>0 && used<(ssize_t)sizeof(resp)-1);
        resp[used]=0;

        X509 *cert=SSL_get_peer_certificate(ssl);
        if(cert){
            X509_NAME *sn=X509_get_subject_name(cert);
            X509_NAME *in=X509_get_issuer_name(cert);
            X509_NAME_get_text_by_NID(sn,NID_commonName,cert_cn,sizeof cert_cn);
            X509_NAME_get_text_by_NID(in,NID_commonName,cert_issuer,sizeof cert_issuer);
            x509_time(X509_get0_notAfter(cert), cert_exp, sizeof cert_exp);
            X509_free(cert);
        }
        (void)ciph; SSL_free(ssl); SSL_CTX_free(ctx);
    }else{
        char req[1024];
        snprintf(req,sizeof req,"HEAD %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: aegisnet/1\r\nConnection: close\r\n\r\n",u.path,u.host);
        write(fd,req,strlen(req));
        ssize_t r=0; do{ r=read(fd,resp+used,sizeof(resp)-1-used); if(r>0) used+=r; }while(r>0 && used<(ssize_t)sizeof(resp)-1);
        resp[used]=0;
    }
    close(fd);

    int http_major=0,http_minor=0;
    sscanf(resp,"HTTP/%d.%d %d",&http_major,&http_minor,&code);
    char *srv=strstr(resp,"\nServer:"); if(!srv) srv=strstr(resp,"\nserver:");
    if(srv){ srv=strchr(srv,':'); if(srv){ srv++; while(*srv==' '||*srv=='\t') srv++; size_t len=strcspn(srv,"\r\n"); len = len>255?255:len; memcpy(server,srv,len); server[len]=0; } }

    if(json){
        printf("{\"url\":\"%s\",\"scheme\":\"%s\",\"host\":\"%s\",\"port\":%d,"
               "\"ip\":\"%s\",\"rtt_ms\":%.2f,\"status\":%d,"
               "\"server\":\"%s\",\"tls\":{\"version\":\"%s\",\"cert_cn\":\"%s\",\"issuer\":\"%s\",\"not_after\":\"%s\"}}\n",
            url,u.scheme,u.host,u.port,ip,(t1-t0),code,server,tls_ver,cert_cn,cert_issuer,cert_exp);
    }else{
        printf("URL    : %s\n", url);
        printf("Host/IP: %s (%s)\n", u.host, ip);
        printf("Porta  : %d  | RTT: %.2f ms\n", u.port, (t1-t0));
        printf("Status : %d\n", code);
        if(server[0]) printf("Server : %s\n", server);
        if(strcmp(u.scheme,"https")==0){
            printf("TLS    : %s\n", tls_ver[0]?tls_ver:"(negociação ok)");
            if(cert_cn[0]) printf("Cert   : CN=%s | Issuer=%s | expira=%s\n", cert_cn, cert_issuer, cert_exp);
        }
    }
    return 0;
}


static void usage(const char *p){
    fprintf(stderr,
        "Uso:\n"
        "  %s netinfo [--json]\n"
        "  %s url --url <http[s]://host[:port]/path> [--json]\n", p,p);
}

int main(int argc, char **argv){
    if(argc<2){ usage(argv[0]); return 1; }
    int json=0;
    for(int i=1;i<argc;i++) if(!strcmp(argv[i],"--json")) json=1;

    if(!strcmp(argv[1],"netinfo")){
        return cmd_netinfo(json);
    }else if(!strcmp(argv[1],"url")){
        const char *url=NULL;
        for(int i=2;i<argc;i++){ if(!strcmp(argv[i],"--url") && i+1<argc) url=argv[++i]; }
        if(!url){ usage(argv[0]); return 1; }
        return cmd_urlscan(url,json);
    }
    usage(argv[0]); return 1;
}
