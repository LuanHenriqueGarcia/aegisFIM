// src/aegisweb.c — mini HTTP (localhost) servindo ./web e APIs da suíte
// Rotas estáticas:
//   GET /                  -> web/index.html
//   GET /<arquivo>         -> ./web (css/js/img)
// Rotas API:
//   GET /api/scan?host=&ports=           -> aegisport -h host -p ports -v
//   GET /api/fim?dir=                     -> aegisfim verificar -r dir
//   GET /api/whois?domain=                -> WHOIS via TCP 43 (iana)
//   GET /api/httphead?host=&port=&path=   -> HEAD HTTP simples
//   GET /api/pwgen?len=&sets=&allow=1     -> aegispass gen
//   GET /api/vault/init?file=&mpw=&iter=  -> aegispass init -f file -i iter --mpw mpw
//   GET /api/vault/list?file=&mpw=        -> aegispass list -f file --mpw mpw
//   GET /api/vault/add?file=&mpw=&site=&user=&pass=&gen=&sets=
//   GET /api/vault/get?file=&mpw=&site=   -> aegispass get ...
//   GET /api/vault/rm?file=&mpw=&site=    -> aegispass rm ...
//   GET /api/netinfo                      -> aegisnet netinfo --json
//   GET /api/urlscan?url=...              -> aegisnet url --url ... --json
//
// Segurança: escuta só 127.0.0.1; sem chamada de shell; valida parâmetros.

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef LISTEN_DEFAULT_PORT
#define LISTEN_DEFAULT_PORT 9002
#endif

#define RECV_MAX 16384
#define RESP_MAX 262144
#define FILE_MAX (4*1024*1024)

static volatile sig_atomic_t g_stop=0;
static void on_sigint(int s){ (void)s; g_stop=1; }

static const char *mime_text = "text/plain; charset=utf-8";


static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); fputc('\n', stderr);
    va_end(ap); exit(1);
}

static int set_nonblock(int fd){
    int fl = fcntl(fd, F_GETFL, 0); if(fl<0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void get_self_dir(char *out, size_t n){
    ssize_t r=readlink("/proc/self/exe", out, n-1);
    if(r<=0) die("não consegui ler /proc/self/exe");
    out[r]=0; char *slash=strrchr(out,'/'); if(slash) *slash=0;
}

static const char* guess_mime(const char *path){
    const char *ext = strrchr(path,'.');
    if(!ext) return mime_text;
    if(!strcasecmp(ext,".html")) return "text/html; charset=utf-8";
    if(!strcasecmp(ext,".css"))  return "text/css; charset=utf-8";
    if(!strcasecmp(ext,".js"))   return "application/javascript; charset=utf-8";
    if(!strcasecmp(ext,".json")) return "application/json; charset=utf-8";
    if(!strcasecmp(ext,".svg"))  return "image/svg+xml";
    if(!strcasecmp(ext,".png"))  return "image/png";
    if(!strcasecmp(ext,".jpg")||!strcasecmp(ext,".jpeg")) return "image/jpeg";
    if(!strcasecmp(ext,".ico"))  return "image/x-icon";
    return mime_text;
}

static bool path_is_safe(const char *p){
    if(strstr(p,"..")) return false;
    for(const unsigned char *s=(const unsigned char*)p; *s; ++s){
        unsigned char c=*s;
        if( (c>='a'&&c<='z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9') ||
            c=='/' || c=='.' || c=='-' || c=='_' ) continue;
        return false;
    }
    return true;
}

static void http_send(int cfd, int code, const char *ctype, const char *body, size_t blen){
    char hdr[1024];
    snprintf(hdr,sizeof hdr,
        "HTTP/1.1 %d OK\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
        "Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        code, ctype, blen);
    (void)write(cfd,hdr,strlen(hdr)); (void)write(cfd,body,blen);
}

static void http_replyf(int cfd, int code, const char *ctype, const char *fmt, ...){
    static char buf[RESP_MAX];
    va_list ap; va_start(ap, fmt); int n=vsnprintf(buf,sizeof buf,fmt,ap); va_end(ap);
    if(n<0) n=0; if((size_t)n>sizeof buf) n=(int)sizeof buf;
    http_send(cfd, code, ctype, buf, (size_t)n);
}

static void url_decode(char *s){
    char *o=s;
    for(char *p=s; *p; ++p){
        if(*p=='+') *o++=' ';
        else if(*p=='%' && p[1] && p[2]){
            char hex[3]={p[1],p[2],0};
            *o++=(char)strtol(hex,NULL,16); p+=2;
        } else *o++=*p;
    }
    *o=0;
}

static const char* qget(const char *query, const char *key, char *dst, size_t dstn){
    if(!query || !key || !*key) return NULL;
    char *buf = strdup(query);
    if(!buf) return NULL;
    const char *found = NULL;

    for(char *p=buf; p && *p; ){
        char *amp = strchr(p,'&'); if(amp) *amp = '\0';
        char *eq  = strchr(p,'=');
        if(eq){
            *eq = '\0';
            if(strcmp(p,key)==0){
                snprintf(dst, dstn, "%s", eq+1);
                url_decode(dst);
                found = dst;
                if(amp) *amp = '&';
                break;
            }
            *eq = '=';
        }
        if(amp){ *amp = '&'; p = amp + 1; } else break;
    }
    free(buf);
    return found;
}

static bool is_safe_token(const char *s){
    if(!s || !*s) return false;
    for(const unsigned char *p=(const unsigned char*)s; *p; ++p){
        unsigned char c=*p;
        if( (c>='a'&&c<='z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9') ||
            c=='.' || c=='-' || c=='_' || c=='/' || c==':' || c==',' ||
            c=='~' || c=='%' || c=='?' || c=='&' || c=='=' ) continue;
        return false;
    }
    return true;
}

static int exec_capture(char *const argv[], char *buf, size_t max){
    int pipefd[2]; if(pipe(pipefd)<0) return -1;
    pid_t pid=fork();
    if(pid<0){ close(pipefd[0]); close(pipefd[1]); return -1; }
    if(pid==0){
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        execvp(argv[0], argv);
        perror("execvp"); _exit(127);
    }
    close(pipefd[1]);
    ssize_t tot=0; for(;;){
        ssize_t r=read(pipefd[0], buf+tot, (tot<(ssize_t)max? (ssize_t)max-tot:0));
        if(r>0){ tot+=r; if(tot>=(ssize_t)max) break; }
        else if(r==0) break;
        else if(errno==EINTR) continue;
        else break;
    }
    if(tot<(ssize_t)max) buf[tot]=0; else buf[max-1]=0;
    close(pipefd[0]);
    int status=0; waitpid(pid,&status,0);
    return status;
}

static int tcp_text_query(const char *host, int port, const char *sendtxt, char *out, size_t outn, int timeout_ms){
    struct addrinfo hints={0}, *res=NULL;
    hints.ai_socktype=SOCK_STREAM; hints.ai_family=AF_UNSPEC;
    char portstr[16]; snprintf(portstr,sizeof portstr,"%d",port);
    int gai=getaddrinfo(host,portstr,&hints,&res); if(gai!=0) return -1;
    int fd=-1; struct addrinfo *ai;
    for(ai=res; ai; ai=ai->ai_next){
        fd=socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if(fd<0) continue;
        set_nonblock(fd);
        int rc=connect(fd, ai->ai_addr, ai->ai_addrlen);
        if(rc<0 && errno!=EINPROGRESS){ close(fd); fd=-1; continue; }
        fd_set wf; FD_ZERO(&wf); FD_SET(fd,&wf);
        struct timeval tv={timeout_ms/1000, (timeout_ms%1000)*1000};
        rc=select(fd+1,NULL,&wf,NULL,&tv);
        if(rc<=0){ close(fd); fd=-1; continue; }
        int err=0; socklen_t el=sizeof(err);
        getsockopt(fd,SOL_SOCKET,SO_ERROR,&err,&el);
        if(err!=0){ close(fd); fd=-1; continue; }
        break;
    }
    freeaddrinfo(res);
    if(fd<0) return -2;

    size_t len=strlen(sendtxt);
    if(write(fd, sendtxt, len)<0){ close(fd); return -3; }

    size_t tot=0;
    for(;;){
        fd_set rf; FD_ZERO(&rf); FD_SET(fd,&rf);
        struct timeval tv={timeout_ms/1000, (timeout_ms%1000)*1000};
        int rc=select(fd+1,&rf,NULL,NULL,&tv);
        if(rc<=0) break;
        ssize_t r=read(fd, out+tot, outn-1-tot);
        if(r>0){ tot+=r; if(tot>=outn-1) break; }
        else break;
    }
    out[tot]=0;
    close(fd);
    return 0;
}


static void serve_static(int cfd, const char *docroot, const char *req_path){
    char rel[1024];
    if(strcmp(req_path,"/")==0) strcpy(rel,"/index.html");
    else snprintf(rel,sizeof rel,"%s",req_path);

    if(!path_is_safe(rel)){ http_replyf(cfd,400,mime_text,"caminho inválido\n"); return; }

    char full[2048];
    snprintf(full,sizeof full,"%s%s",docroot,rel);

    struct stat st;
    if(stat(full,&st)!=0 || !S_ISREG(st.st_mode)){ http_replyf(cfd,404,mime_text,"404\n"); return; }
    if(st.st_size > FILE_MAX){ http_replyf(cfd,413,mime_text,"arquivo grande demais\n"); return; }

    FILE *f=fopen(full,"rb");
    if(!f){ http_replyf(cfd,404,mime_text,"404\n"); return; }
    char *buf=malloc((size_t)st.st_size);
    size_t n=fread(buf,1,(size_t)st.st_size,f);
    fclose(f);

    http_send(cfd,200,guess_mime(full),buf,n);
    free(buf);
}

static void handle_scan(int cfd, char *query, const char *exe_dir){
    char hbuf[512], pbuf[256];
    const char *host  = qget(query, "host",  hbuf, sizeof hbuf);
    const char *ports = qget(query, "ports", pbuf, sizeof pbuf);
    if(!host || !ports){ http_replyf(cfd,400,mime_text,"faltou host/ports\n"); return; }

    char hostnorm[512];
    const char *h = host;
    if(!strncmp(h,"http://",7))       h += 7;
    else if(!strncmp(h,"https://",8))  h += 8;
    size_t len = strcspn(h, "/");
    if(len >= sizeof hostnorm) len = sizeof hostnorm-1;
    memcpy(hostnorm, h, len); hostnorm[len] = 0;
    char *colon = strrchr(hostnorm, ':');
    if (colon) *colon = 0;

    if(!is_safe_token(hostnorm) || !is_safe_token(ports)){
        http_replyf(cfd,400,mime_text,"param inválido\n"); return;
    }

    char bin[600]; snprintf(bin,sizeof bin,"%s/%s",exe_dir,"aegisport");
    char *argv[]={(char*)bin,"-h",hostnorm,"-p",(char*)ports,"-v",NULL};
    static char out[RESP_MAX]; (void)exec_capture(argv,out,sizeof out);
    http_replyf(cfd,200,mime_text,"%s", out[0]?out:"(sem saída)\n");
}

static void handle_fim(int cfd, char *query, const char *exe_dir){
    char dbuf[512];
    const char *dir = qget(query,"dir", dbuf, sizeof dbuf);
    if(!dir){ http_replyf(cfd,400,mime_text,"faltou dir\n"); return; }
    if(!is_safe_token(dir)){ http_replyf(cfd,400,mime_text,"dir inválido\n"); return; }

    char bin[600]; snprintf(bin,sizeof bin,"%s/%s",exe_dir,"aegisfim");
    char *argv[]={(char*)bin,"verificar","-r",(char*)dir,NULL};
    static char out[RESP_MAX]; (void)exec_capture(argv,out,sizeof out);
    http_replyf(cfd,200,mime_text,"%s", out[0]?out:"(sem saída)\n");
}

static void handle_whois(int cfd, char *query){
    char dbuf[512];
    const char *domain = qget(query,"domain", dbuf, sizeof dbuf);
    if(!domain){ http_replyf(cfd,400,mime_text,"faltou domain\n"); return; }
    if(!is_safe_token(domain)){ http_replyf(cfd,400,mime_text,"domain inválido\n"); return; }
    char sendbuf[512]; snprintf(sendbuf,sizeof sendbuf,"%s\r\n",domain);
    static char resp[RESP_MAX]; int rc=tcp_text_query("whois.iana.org",43,sendbuf,resp,sizeof resp,3000);
    if(rc!=0) http_replyf(cfd,502,mime_text,"Falha WHOIS (%d)\n",rc);
    else http_replyf(cfd,200,mime_text,"%s",resp);
}

static void handle_httphead(int cfd, char *query){
    char hbuf[512], pbuf[64], pathbuf[1024];
    const char *host = qget(query,"host", hbuf, sizeof hbuf);
    const char *port = qget(query,"port", pbuf, sizeof pbuf);
    const char *path = qget(query,"path", pathbuf, sizeof pathbuf);
    if(!host||!port||!path){ http_replyf(cfd,400,mime_text,"faltou host/port/path\n"); return; }
    if(!is_safe_token(host)||!is_safe_token(port)||!is_safe_token(path)){ http_replyf(cfd,400,mime_text,"param inválido\n"); return; }
    int p=atoi(port); if(p<=0||p>65535){ http_replyf(cfd,400,mime_text,"porta inválida\n"); return; }
    char req[1024]; snprintf(req,sizeof req,"HEAD %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: aegisweb/1\r\n\r\n",path,host);
    static char resp[RESP_MAX]; int rc=tcp_text_query(host,p,req,resp,sizeof resp,3000);
    if(rc!=0) http_replyf(cfd,502,mime_text,"Falha ao conectar (%d)\n",rc);
    else http_replyf(cfd,200,mime_text,"%s",resp);
}

static void handle_pwgen(int cfd, char *query, const char *exe_dir){
    char lbuf[32], sbuf[64], abuf[8];
    const char *len  = qget(query,"len",  lbuf, sizeof lbuf);
    const char *sets = qget(query,"sets", sbuf, sizeof sbuf);
    const char *allow= qget(query,"allow",abuf, sizeof abuf);

    char bin[600]; snprintf(bin,sizeof bin,"%s/%s",exe_dir,"aegispass");
    char *argv[16]; int k=0; argv[k++]=(char*)bin; argv[k++]="gen";
    if(len){ argv[k++]="-l"; argv[k++]=(char*)len; }
    if(sets){ argv[k++]="--sets"; argv[k++]=(char*)sets; }
    if(allow){ argv[k++]="--allow-ambig"; }
    argv[k]=NULL;
    static char out[RESP_MAX]; (void)exec_capture(argv,out,sizeof out);
    http_replyf(cfd,200,"text/plain; charset=utf-8","%s", out[0]?out:"");
}


static void handle_vault_init(int cfd,char*q,const char*exe){
  char fbuf[512], mbuf[512], ibuf[32];
  const char *file=qget(q,"file",fbuf,sizeof fbuf);
  const char *mpw =qget(q,"mpw", mbuf,sizeof mbuf);
  const char *iter=qget(q,"iter",ibuf,sizeof ibuf);
  if(!file||!mpw){ http_replyf(cfd,400,mime_text,"faltou file/mpw\n"); return; }
  char bin[600]; snprintf(bin,sizeof bin,"%s/%s",exe,"aegispass");
  char *argv[16]; int k=0; argv[k++]=(char*)bin; argv[k++]="init";
  argv[k++]="-f"; argv[k++]=(char*)file;
  if(iter){ argv[k++]="-i"; argv[k++]=(char*)iter; }
  argv[k++]="--mpw"; argv[k++]=(char*)mpw;
  argv[k]=NULL; static char out[RESP_MAX]; (void)exec_capture(argv,out,sizeof out);
  http_replyf(cfd,200,mime_text,"%s", out[0]?out:"");
}
static void handle_vault_list(int cfd,char*q,const char*exe){
  char fbuf[512], mbuf[512];
  const char *file=qget(q,"file",fbuf,sizeof fbuf);
  const char *mpw =qget(q,"mpw", mbuf,sizeof mbuf);
  if(!file||!mpw){ http_replyf(cfd,400,mime_text,"faltou file/mpw\n"); return; }
  char bin[600]; snprintf(bin,sizeof bin,"%s/%s",exe,"aegispass");
  char *argv[]={(char*)bin,"list","-f",(char*)file,"--mpw",(char*)mpw,NULL};
  static char out[RESP_MAX]; (void)exec_capture(argv,out,sizeof out);
  http_replyf(cfd,200,mime_text,"%s", out[0]?out:"");
}
static void handle_vault_add (int cfd,char*q,const char*exe){
  char fbuf[512], mbuf[512], sbuf[256], ubuf[256], pbuf[256], gbuf[32], setbuf[64];
  const char *file=qget(q,"file",fbuf,sizeof fbuf);
  const char *mpw =qget(q,"mpw", mbuf,sizeof mbuf);
  const char *site=qget(q,"site",sbuf,sizeof sbuf);
  const char *user=qget(q,"user",ubuf,sizeof ubuf);
  const char *pass=qget(q,"pass",pbuf,sizeof pbuf);
  const char *gen =qget(q,"gen", gbuf,sizeof gbuf);
  const char *sets=qget(q,"sets",setbuf,sizeof setbuf);
  if(!file||!mpw||!site||!user){ http_replyf(cfd,400,mime_text,"faltou file/mpw/site/user\n"); return; }
  char bin[600]; snprintf(bin,sizeof bin,"%s/%s",exe,"aegispass");
  char *argv[24]; int k=0; argv[k++]=(char*)bin; argv[k++]="add";
  argv[k++]="-f"; argv[k++]=(char*)file; argv[k++]="--mpw"; argv[k++]=(char*)mpw;
  argv[k++]="-s"; argv[k++]=(char*)site; argv[k++]="-u"; argv[k++]=(char*)user;
  if(pass && *pass){ argv[k++]="-p"; argv[k++]=(char*)pass; }
  else if(gen && *gen){ argv[k++]="--gen"; argv[k++]=(char*)gen; if(sets){ argv[k++]="--sets"; argv[k++]=(char*)sets; } }
  argv[k]=NULL; static char out[RESP_MAX]; (void)exec_capture(argv,out,sizeof out);
  http_replyf(cfd,200,mime_text,"%s", out[0]?out:"");
}
static void handle_vault_get (int cfd,char*q,const char*exe){
  char fbuf[512], mbuf[512], sbuf[256]; 
  const char *file=qget(q,"file",fbuf,sizeof fbuf);
  const char *mpw =qget(q,"mpw", mbuf,sizeof mbuf);
  const char *site=qget(q,"site",sbuf,sizeof sbuf);
  if(!file||!mpw||!site){ http_replyf(cfd,400,mime_text,"faltou file/mpw/site\n"); return; }
  char bin[600]; snprintf(bin,sizeof bin,"%s/%s",exe,"aegispass");
  char *argv[]={(char*)bin,"get","-f",(char*)file,"--mpw",(char*)mpw,"-s",(char*)site,NULL};
  static char out[RESP_MAX]; (void)exec_capture(argv,out,sizeof out);
  http_replyf(cfd,200,mime_text,"%s", out[0]?out:"");
}
static void handle_vault_rm  (int cfd,char*q,const char*exe){
  char fbuf[512], mbuf[512], sbuf[256];
  const char *file=qget(q,"file",fbuf,sizeof fbuf);
  const char *mpw =qget(q,"mpw", mbuf,sizeof mbuf);
  const char *site=qget(q,"site",sbuf,sizeof sbuf);
  if(!file||!mpw||!site){ http_replyf(cfd,400,mime_text,"faltou file/mpw/site\n"); return; }
  char bin[600]; snprintf(bin,sizeof bin,"%s/%s",exe,"aegispass");
  char *argv[]={(char*)bin,"rm","-f",(char*)file,"--mpw",(char*)mpw,"-s",(char*)site,NULL};
  static char out[RESP_MAX]; (void)exec_capture(argv,out,sizeof out);
  http_replyf(cfd,200,mime_text,"%s", out[0]?out:"");
}

static void handle_netinfo(int cfd, const char *exe_dir){
    char bin[600]; snprintf(bin,sizeof bin,"%s/%s",exe_dir,"aegisnet");
    char *argv[]={(char*)bin,"netinfo","--json",NULL};
    static char out[RESP_MAX]; (void)exec_capture(argv,out,sizeof out);
    http_replyf(cfd,200,"application/json; charset=utf-8","%s", out[0]?out:"{}");
}

static void handle_urlscan(int cfd, char *query, const char *exe_dir){
    char ubuf[1024];
    const char *url = qget(query,"url", ubuf, sizeof ubuf);
    if(!url){ http_replyf(cfd,400,mime_text,"faltou url\n"); return; }
    if(!is_safe_token(url)){ http_replyf(cfd,400,mime_text,"url inválida\n"); return; }
    char bin[600]; snprintf(bin,sizeof bin,"%s/%s",exe_dir,"aegisnet");
    char *argv[8]; int k=0; argv[k++]=(char*)bin; argv[k++]="url"; argv[k++]="--url"; argv[k++]=(char*)url; argv[k++]="--json"; argv[k]=NULL;
    static char out[RESP_MAX]; (void)exec_capture(argv,out,sizeof out);
    http_replyf(cfd,200,"application/json; charset=utf-8","%s", out[0]?out:"{}");
}


int main(int argc, char **argv){
    int port = LISTEN_DEFAULT_PORT;
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"-p") && i+1<argc){ port=atoi(argv[++i]); if(port<=0||port>65535) port=LISTEN_DEFAULT_PORT; }
    }

    signal(SIGINT,on_sigint); signal(SIGTERM,on_sigint);

    char exe_dir[512]; get_self_dir(exe_dir,sizeof exe_dir);

    char docroot[1024];
    snprintf(docroot,sizeof docroot,"%s/web",exe_dir);
    struct stat st;
    if(stat(docroot,&st)!=0 || !S_ISDIR(st.st_mode)){
        char tmp[1024]; snprintf(tmp,sizeof tmp,"%s/../web",exe_dir);
        if(stat(tmp,&st)==0 && S_ISDIR(st.st_mode)) snprintf(docroot,sizeof docroot,"%s",tmp);
    }

    int s=socket(AF_INET,SOCK_STREAM,0); if(s<0) die("socket: %s",strerror(errno));
    int yes=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);
    struct sockaddr_in sa={0}; sa.sin_family=AF_INET; sa.sin_port=htons(port);
    inet_pton(AF_INET,"127.0.0.1",&sa.sin_addr);
    if(bind(s,(struct sockaddr*)&sa,sizeof sa)<0) die("bind: %s",strerror(errno));
    if(listen(s,64)<0) die("listen: %s",strerror(errno));
    printf("aegisweb ouvindo em http://127.0.0.1:%d  (docroot: %s)\n",port,docroot);

    for(;!g_stop;){
        int c=accept(s,NULL,NULL);
        if(c<0){ if(errno==EINTR) continue; perror("accept"); break; }

        char req[RECV_MAX]; ssize_t r=read(c,req,sizeof req - 1);
        if(r<=0){ close(c); continue; }
        req[r]=0;

        char method[8], path[1024]; method[0]=path[0]=0;
        sscanf(req,"%7s %1023s",method,path);
        if(strcmp(method,"GET")!=0){ http_replyf(c,405,mime_text,"Somente GET\n"); close(c); continue; }

        char *q=NULL; if((q=strchr(path,'?'))){ *q++=0; }

        if(!strncmp(path,"/api/",5)){
            if(!strcmp(path,"/api/scan")){
                if(!q) http_replyf(c,400,mime_text,"faltou query\n");
                else { char *dup=strdup(q); handle_scan(c,dup,exe_dir); free(dup); }
            }else if(!strcmp(path,"/api/fim")){
                if(!q) http_replyf(c,400,mime_text,"faltou query\n");
                else { char *dup=strdup(q); handle_fim(c,dup,exe_dir); free(dup); }
            }else if(!strcmp(path,"/api/whois")){
                if(!q) http_replyf(c,400,mime_text,"faltou query\n");
                else { char *dup=strdup(q); handle_whois(c,dup); free(dup); }
            }else if(!strcmp(path,"/api/httphead")){
                if(!q) http_replyf(c,400,mime_text,"faltou query\n");
                else { char *dup=strdup(q); handle_httphead(c,dup); free(dup); }
            }else if(!strcmp(path,"/api/pwgen")){
                if(!q) http_replyf(c,400,mime_text,"faltou query\n");
                else { char *dup=strdup(q); handle_pwgen(c,dup,exe_dir); free(dup); }
            }else if(!strcmp(path,"/api/vault/init")){
                if(!q) http_replyf(c,400,mime_text,"faltou query\n");
                else { char *dup=strdup(q); handle_vault_init(c,dup,exe_dir); free(dup); }
            }else if(!strcmp(path,"/api/vault/list")){
                if(!q) http_replyf(c,400,mime_text,"faltou query\n");
                else { char *dup=strdup(q); handle_vault_list(c,dup,exe_dir); free(dup); }
            }else if(!strcmp(path,"/api/vault/add")){
                if(!q) http_replyf(c,400,mime_text,"faltou query\n");
                else { char *dup=strdup(q); handle_vault_add(c,dup,exe_dir); free(dup); }
            }else if(!strcmp(path,"/api/vault/get")){
                if(!q) http_replyf(c,400,mime_text,"faltou query\n");
                else { char *dup=strdup(q); handle_vault_get(c,dup,exe_dir); free(dup); }
            }else if(!strcmp(path,"/api/vault/rm")){
                if(!q) http_replyf(c,400,mime_text,"faltou query\n");
                else { char *dup=strdup(q); handle_vault_rm(c,dup,exe_dir); free(dup); }
            }else if(!strcmp(path,"/api/netinfo")){
                handle_netinfo(c, exe_dir);
            }else if(!strcmp(path,"/api/urlscan")){
                if(!q) http_replyf(c,400,mime_text,"faltou query\n");
                else { char *dup=strdup(q); handle_urlscan(c,dup,exe_dir); free(dup); }
            }else{
                http_replyf(c,404,mime_text,"404\n");
            }
            close(c); continue;
        }

        serve_static(c, docroot, path);
        close(c);
    }

    close(s);
    return 0;
}
