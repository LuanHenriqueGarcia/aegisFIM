
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>

#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#ifdef __linux__
#include <termios.h>
#include <fcntl.h>
#endif

#define SALT_LEN 16
#define IV_LEN   12
#define TAG_LEN  16
#define KEY_LEN  32
#define MAGIC    "APV1"
#define DEFAULT_ITER 200000

static void die(const char *msg){ fprintf(stderr,"%s\n",msg); exit(2); }
static void dief(const char *fmt, ...){
    va_list ap; va_start(ap,fmt); vfprintf(stderr,fmt,ap); va_end(ap);
    fputc('\n',stderr); exit(2);
}

static int read_all(const char *path, unsigned char **out, size_t *outlen){
    FILE *f=fopen(path,"rb"); if(!f) return -1;
    if(fseek(f,0,SEEK_END)!=0){ fclose(f); return -1; }
    long n=ftell(f); if(n<0){ fclose(f); return -1; }
    if(fseek(f,0,SEEK_SET)!=0){ fclose(f); return -1; }
    unsigned char *buf=(unsigned char*)malloc((size_t)n+1);
    if(!buf){ fclose(f); return -1; }
    size_t r=fread(buf,1,(size_t)n,f);
    fclose(f);
    if(r!=(size_t)n){ free(buf); return -1; }
    *out=buf; *outlen=(size_t)n; return 0;
}

static int write_all_atomic(const char *path, const unsigned char *buf, size_t n){
   
    char tmp[1024];
    snprintf(tmp,sizeof tmp,"%s.tmp",path);
    FILE *f=fopen(tmp,"wb"); if(!f) return -1;
    size_t w=fwrite(buf,1,n,f);
    if(w!=n){ fclose(f); unlink(tmp); return -1; }
    if(fclose(f)!=0){ unlink(tmp); return -1; }
    if(rename(tmp,path)!=0){ unlink(tmp); return -1; }
    return 0;
}

static void be32_write(unsigned char *p, uint32_t x){
    p[0]=(x>>24)&0xFF; p[1]=(x>>16)&0xFF; p[2]=(x>>8)&0xFF; p[3]=x&0xFF;
}
static uint32_t be32_read(const unsigned char *p){
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}

static void cleanse(void *p, size_t n){
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPENSSL_cleanse(p,n);
#else
    volatile unsigned char *vp=(volatile unsigned char*)p; while(n--) *vp++=0;
#endif
}

#ifdef __linux__
static int read_password_hidden(const char *prompt, char *out, size_t n){
    
    fprintf(stderr,"%s",prompt); fflush(stderr);
    struct termios oldt, newt;
    if(tcgetattr(STDIN_FILENO,&oldt)!=0) return -1;
    newt=oldt; newt.c_lflag &= ~(ECHO);
    if(tcsetattr(STDIN_FILENO,TCSANOW,&newt)!=0) return -1;
    if(!fgets(out,(int)n,stdin)){ tcsetattr(STDIN_FILENO,TCSANOW,&oldt); return -1; }
    tcsetattr(STDIN_FILENO,TCSANOW,&oldt);
    size_t len=strcspn(out,"\r\n"); out[len]='\0';
    fprintf(stderr,"\n");
    return 0;
}
#else
static int read_password_hidden(const char *prompt, char *out, size_t n){
    // fallback simples
    fprintf(stderr,"%s",prompt); fflush(stderr);
    if(!fgets(out,(int)n,stdin)) return -1;
    size_t len=strcspn(out,"\r\n"); out[len]='\0';
    return 0;
}
#endif



static int rng_bytes(unsigned char *buf, size_t n){
    return RAND_bytes(buf,(int)n)==1 ? 0 : -1;
}

static const char *SET_LOW="abcdefghijklmnopqrstuvwxyz";
static const char *SET_UP ="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char *SET_DIG="0123456789";
static const char *SET_SYM="!@#$%^&*()-_=+[]{};:,./?|~";

static void build_charset(int use_low,int use_up,int use_dig,int use_sym,int no_ambig, char *out, size_t outn){
 
    const char *amb="O0oIl1|`'\";:., ";
    size_t k=0;
#define APPEND_SET(S) do{ for(const char *p=(S); *p; ++p){ \
        if(no_ambig && strchr(amb,*p)) continue; \
        if(k+1<outn) out[k++]=*p; \
    } }while(0)
    if(use_low) APPEND_SET(SET_LOW);
    if(use_up ) APPEND_SET(SET_UP);
    if(use_dig) APPEND_SET(SET_DIG);
    if(use_sym) APPEND_SET(SET_SYM);
#undef APPEND_SET
    out[k]='\0';
}

static int cmd_gen(int argc, char **argv){
    int len=16, use_low=1,use_up=1,use_dig=1,use_sym=1, no_ambig=1;
    for(int i=2;i<argc;i++){
        if(strcmp(argv[i],"-l")==0 && i+1<argc) { len=atoi(argv[++i]); }
        else if(strcmp(argv[i],"--sets")==0 && i+1<argc){
            const char *s=argv[++i];
            use_low = strchr(s,'a')!=NULL;
            use_up  = strchr(s,'A')!=NULL;
            use_dig = strchr(s,'0')!=NULL;
            use_sym = strchr(s,'s')!=NULL;
        } else if(strcmp(argv[i],"--allow-ambig")==0){
            no_ambig=0;
        }
    }
    if(len<4) len=4; if(len>1024) len=1024;
    char charset[512]; build_charset(use_low,use_up,use_dig,use_sym,no_ambig, charset, sizeof(charset));
    if(charset[0]=='\0') die("Conjunto de caracteres vazio — ajuste --sets");
    size_t cslen=strlen(charset);
    unsigned char rb[1024]; if((size_t)len>sizeof(rb)) die("len grande");
    if(rng_bytes(rb,(size_t)len)!=0) die("Falha RNG");
    char out[1100]; for(int i=0;i<len;i++) out[i]=charset[ rb[i] % cslen ];
    out[len]='\0';
    printf("%s\n",out);
    cleanse(rb,sizeof(rb)); cleanse(out,sizeof(out));
    return 0;
}


static int kdf_pbkdf2(const char *pass, const unsigned char *salt, size_t saltlen, uint32_t iter, unsigned char *key32){
    if(PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass), salt, (int)saltlen, (int)iter, EVP_sha256(), KEY_LEN, key32)!=1)
        return -1;
    return 0;
}
static int aes_gcm_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *pt, int ptlen, unsigned char **out_ct, int *out_len, unsigned char tag[TAG_LEN]){
    int rc=-1; EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new(); if(!ctx) return -1;
    unsigned char *ct=(unsigned char*)malloc(ptlen); if(!ct){ EVP_CIPHER_CTX_free(ctx); return -1; }
    int len=0, tot=0;
    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)!=1) goto end;
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL)!=1) goto end;
    if(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)!=1) goto end;
    if(EVP_EncryptUpdate(ctx, ct, &len, pt, ptlen)!=1) goto end; tot=len;
    if(EVP_EncryptFinal_ex(ctx, ct+tot, &len)!=1) goto end; tot+=len;
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag)!=1) goto end;
    *out_ct=ct; *out_len=tot; rc=0;
end:
    if(rc!=0) free(ct);
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}
static int aes_gcm_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *ct, int ctlen, const unsigned char tag[TAG_LEN], unsigned char **out_pt, int *out_len){
    int rc=-1; EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new(); if(!ctx) return -1;
    unsigned char *pt=(unsigned char*)malloc(ctlen); if(!pt){ EVP_CIPHER_CTX_free(ctx); return -1; }
    int len=0, tot=0;
    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)!=1) goto end;
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL)!=1) goto end;
    if(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)!=1) goto end;
    if(EVP_DecryptUpdate(ctx, pt, &len, ct, ctlen)!=1) goto end; tot=len;
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag)!=1) goto end;
    if(EVP_DecryptFinal_ex(ctx, pt+tot, &len)!=1) goto end; tot+=len;
    *out_pt=pt; *out_len=tot; rc=0;
end:
    if(rc!=0) free(pt);
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}


typedef struct { char *site; char *user; char *pass; } Item;
typedef struct { Item *v; size_t n,cap; } Vec;

static void vpush(Vec *a, Item it){ if(a->n==a->cap){ a->cap=a->cap? a->cap*2:32; a->v=realloc(a->v,a->cap*sizeof(Item)); } a->v[a->n++]=it; }
static void vfree(Vec *a){ for(size_t i=0;i<a->n;i++){ free(a->v[i].site); free(a->v[i].user); free(a->v[i].pass);} free(a->v); }

static char* str_dup(const char *s){ size_t n=strlen(s); char *d=malloc(n+1); memcpy(d,s,n+1); return d; }

static int parse_tsv(unsigned char *buf, size_t n, Vec *out){

    char *s=(char*)buf; char *end=s+n;
    while(s<end){
        char *nl=memchr(s,'\n', (size_t)(end-s));
        if(!nl) nl=end;
        char *line=malloc((size_t)(nl-s)+1);
        memcpy(line,s,(size_t)(nl-s)); line[nl-s]='\0';
        if(line[0]){
            char *p1=strchr(line,'\t'); 
            char *p2 = p1? strchr(p1+1,'\t'):NULL;
            if(p1 && p2){
                *p1=0; *p2=0;
                Item it={ str_dup(line), str_dup(p1+1), str_dup(p2+1) };
                vpush(out,it);
            }
        }
        free(line);
        s=(nl==end)?end:nl+1;
    }
    return 0;
}
static unsigned char* serialize_tsv(const Vec *v, size_t *outn){
    // junta em memória
    size_t cap=1024, k=0; unsigned char *buf=malloc(cap);
    for(size_t i=0;i<v->n;i++){
        const char *a=v->v[i].site; const char *b=v->v[i].user; const char *c=v->v[i].pass;
        size_t need=strlen(a)+strlen(b)+strlen(c)+3; // 2 tabs + \n
        if(k+need>cap){ while(k+need>cap) cap*=2; buf=realloc(buf,cap); }
        k+= (size_t)sprintf((char*)buf+k, "%s\t%s\t%s\n", a,b,c);
    }
    *outn=k; return buf;
}

static int vault_load(const char *path, const char *master, Vec *out, uint32_t *iters_out){
    unsigned char *file=NULL; size_t n=0;
    if(read_all(path,&file,&n)!=0) return -1;
    if(n < 4+SALT_LEN+4+IV_LEN+TAG_LEN){ free(file); return -2; }
    if(memcmp(file, MAGIC, 4)!=0){ free(file); return -3; }
    unsigned char *p=file+4;
    unsigned char salt[SALT_LEN]; memcpy(salt,p,SALT_LEN); p+=SALT_LEN;
    uint32_t iters=be32_read(p); p+=4;
    unsigned char iv[IV_LEN]; memcpy(iv,p,IV_LEN); p+=IV_LEN;

    size_t ctlen = n - (4+SALT_LEN+4+IV_LEN+TAG_LEN);
    unsigned char *ct=p;
    unsigned char tag[TAG_LEN]; memcpy(tag, file+n-TAG_LEN, TAG_LEN);

    unsigned char key[KEY_LEN];
    if(kdf_pbkdf2(master, salt, SALT_LEN, iters, key)!=0){ free(file); return -4; }

    unsigned char *pt=NULL; int ptlen=0;
    int rc=aes_gcm_decrypt(key, iv, ct, (int)ctlen, tag, &pt, &ptlen);
    cleanse(key,sizeof key);
    if(rc!=0){ free(file); return -5; }

    out->v=NULL; out->n=out->cap=0;
    parse_tsv(pt,(size_t)ptlen,out);

    if(iters_out) *iters_out=iters;
    cleanse(pt,(size_t)ptlen); free(pt); free(file);
    return 0;
}

static int vault_save(const char *path, const char *master, const Vec *v, uint32_t iters){
    unsigned char salt[SALT_LEN], iv[IV_LEN]; if(rng_bytes(salt,SALT_LEN)!=0||rng_bytes(iv,IV_LEN)!=0) return -1;
    unsigned char key[KEY_LEN]; if(kdf_pbkdf2(master,salt,SALT_LEN,iters,key)!=0) return -1;
    size_t ptn=0; unsigned char *pt=serialize_tsv(v,&ptn);

    unsigned char *ct=NULL; int ctlen=0; unsigned char tag[TAG_LEN];
    if(aes_gcm_encrypt(key, iv, pt, (int)ptn, &ct, &ctlen, tag)!=0){ cleanse(key,sizeof key); free(pt); return -1; }

    size_t outn = 4 + SALT_LEN + 4 + IV_LEN + (size_t)ctlen + TAG_LEN;
    unsigned char *out=malloc(outn);
    unsigned char *p=out;
    memcpy(p, MAGIC, 4); p+=4;
    memcpy(p, salt, SALT_LEN); p+=SALT_LEN;
    be32_write(p, iters); p+=4;
    memcpy(p, iv, IV_LEN); p+=IV_LEN;
    memcpy(p, ct, (size_t)ctlen); p+=ctlen;
    memcpy(p, tag, TAG_LEN); p+=TAG_LEN;

    int rc=write_all_atomic(path,out,outn);

    cleanse(key,sizeof key); cleanse(pt,ptn);
    free(pt); free(ct); free(out);
    return rc;
}



static const char *default_vault_path(void){
    static char path[512];

    snprintf(path,sizeof path,"%s",".aegisfim/vault.apv");
    return path;
}

static void ensure_parent(const char *path){
    const char *slash=strrchr(path,'/');
    if(!slash) return;
    size_t n=(size_t)(slash-(path));
    char *dir=malloc(n+1); memcpy(dir,path,n); dir[n]='\0';
    struct stat st;
    if(stat(dir,&st)!=0){ mkdir(dir,0755); }
    free(dir);
}

static int cmd_init(int argc, char **argv){
    const char *vault=default_vault_path();
    uint32_t iters=DEFAULT_ITER;
    for(int i=2;i<argc;i++){
        if(strcmp(argv[i],"-f")==0 && i+1<argc) vault=argv[++i];
        else if(strcmp(argv[i],"-i")==0 && i+1<argc) iters=(uint32_t)atoi(argv[++i]);
    }
    char pw1[512], pw2[512];
    if(read_password_hidden("Crie senha-mestra: ", pw1, sizeof pw1)!=0) die("Falha lendo senha");
    if(read_password_hidden("Repita a senha-mestra: ", pw2, sizeof pw2)!=0) die("Falha lendo senha");
    if(strcmp(pw1,pw2)!=0) die("Senhas não conferem");

    Vec v={0};
    ensure_parent(vault);
    if(vault_save(vault, pw1, &v, iters)!=0) dief("Erro salvando vault em %s", vault);
    cleanse(pw1,sizeof pw1); cleanse(pw2,sizeof pw2);
    printf(" Vault criado: %s (iter=%u)\n", vault, iters);
    return 0;
}

static int cmd_list(int argc, char **argv){
    const char *vault=default_vault_path();
    for(int i=2;i<argc;i++)
        if(strcmp(argv[i],"-f")==0 && i+1<argc) vault=argv[++i];

    char mpw[512];
    if(read_password_hidden("Senha-mestra: ", mpw, sizeof mpw)!=0) die("Falha lendo senha");
    Vec v={0}; uint32_t it=0;
    if(vault_load(vault, mpw, &v, &it)!=0) die("Falha ao abrir vault (senha incorreta ou arquivo inválido)");
    printf("Iterações: %u\n", it);
    for(size_t i=0;i<v.n;i++) printf("%s\t%s\n", v.v[i].site, v.v[i].user);
    vfree(&v); cleanse(mpw,sizeof mpw);
    return 0;
}

static int cmd_get(int argc, char **argv){
    const char *vault=default_vault_path();
    const char *site=NULL;
    for(int i=2;i<argc;i++){
        if(strcmp(argv[i],"-f")==0 && i+1<argc) vault=argv[++i];
        else if(strcmp(argv[i],"-s")==0 && i+1<argc) site=argv[++i];
    }
    if(!site) die("Use: get -s <site> [-f vault]");
    char mpw[512];
    if(read_password_hidden("Senha-mestra: ", mpw, sizeof mpw)!=0) die("Falha lendo senha");
    Vec v={0}; uint32_t it=0;
    if(vault_load(vault, mpw, &v, &it)!=0) die("Falha ao abrir vault");
    for(size_t i=0;i<v.n;i++){
        if(strcmp(v.v[i].site, site)==0){
            printf("%s\t%s\t%s\n", v.v[i].site, v.v[i].user, v.v[i].pass);
            vfree(&v); cleanse(mpw,sizeof mpw); return 0;
        }
    }
    vfree(&v); cleanse(mpw,sizeof mpw);
    die("Site não encontrado");
    return 1;
}

static int cmd_rm(int argc, char **argv){
    const char *vault=default_vault_path();
    const char *site=NULL;
    for(int i=2;i<argc;i++){
        if(strcmp(argv[i],"-f")==0 && i+1<argc) vault=argv[++i];
        else if(strcmp(argv[i],"-s")==0 && i+1<argc) site=argv[++i];
    }
    if(!site) die("Use: rm -s <site> [-f vault]");
    char mpw[512];
    if(read_password_hidden("Senha-mestra: ", mpw, sizeof mpw)!=0) die("Falha lendo senha");
    Vec v={0}; uint32_t it=0;
    if(vault_load(vault, mpw, &v, &it)!=0) die("Falha ao abrir vault");
    size_t w=0; int removed=0;
    for(size_t i=0;i<v.n;i++){
        if(strcmp(v.v[i].site,site)==0){ removed=1; free(v.v[i].site); free(v.v[i].user); free(v.v[i].pass); }
        else v.v[w++]=v.v[i];
    }
    v.n=w;
    if(!removed){ vfree(&v); cleanse(mpw,sizeof mpw); die("Site não encontrado"); }
    if(vault_save(vault, mpw, &v, it)!=0) die("Falha ao salvar vault");
    vfree(&v); cleanse(mpw,sizeof mpw);
    printf("Removido: %s\n", site);
    return 0;
}

static int cmd_add(int argc, char **argv){
    const char *vault=default_vault_path();
    const char *site=NULL,*user=NULL,*pass=NULL;
    int want_gen=0, gen_len=16; int sets_low=1,sets_up=1,sets_dig=1,sets_sym=1, no_ambig=1;
    for(int i=2;i<argc;i++){
        if(strcmp(argv[i],"-f")==0 && i+1<argc) vault=argv[++i];
        else if(strcmp(argv[i],"-s")==0 && i+1<argc) site=argv[++i];
        else if(strcmp(argv[i],"-u")==0 && i+1<argc) user=argv[++i];
        else if(strcmp(argv[i],"-p")==0 && i+1<argc) pass=argv[++i];
        else if(strcmp(argv[i],"--gen")==0 && i+1<argc){ want_gen=1; gen_len=atoi(argv[++i]); }
        else if(strcmp(argv[i],"--sets")==0 && i+1<argc){
            const char *s=argv[++i];
            sets_low = strchr(s,'a')!=NULL;
            sets_up  = strchr(s,'A')!=NULL;
            sets_dig = strchr(s,'0')!=NULL;
            sets_sym = strchr(s,'s')!=NULL;
        } else if(strcmp(argv[i],"--allow-ambig")==0){ no_ambig=0; }
    }
    if(!site||!user) die("Use: add -s <site> -u <user> [-p <pass> | --gen N [--sets aA0s]] [-f vault]");
    char mpw[512];
    if(read_password_hidden("Senha-mestra: ", mpw, sizeof mpw)!=0) die("Falha lendo senha");

    Vec v={0}; uint32_t it=0;
    if(access(vault,F_OK)==0){
        if(vault_load(vault, mpw, &v, &it)!=0) die("Falha ao abrir vault");
    } else {
        it=DEFAULT_ITER; ensure_parent(vault);
    }

    char *generated=NULL;
    if(want_gen){
        if(gen_len<8) gen_len=8; if(gen_len>1024) gen_len=1024;
        char charset[512];
        build_charset(sets_low,sets_up,sets_dig,sets_sym,no_ambig, charset, sizeof(charset));
        if(charset[0]=='\0') die("Conjunto vazio (--sets)");
        size_t cslen=strlen(charset);
        unsigned char rb[1024]; if(rng_bytes(rb,(size_t)gen_len)!=0) die("RNG");
        generated = (char*)malloc((size_t)gen_len+1);
        for(int i=0;i<gen_len;i++) generated[i]=charset[rb[i] % cslen];
        generated[gen_len]='\0';
        cleanse(rb,sizeof(rb));
        pass=generated;
    }
    if(!pass){

        fprintf(stderr,"Senha (visível) para %s/%s: ", site,user);
        char buf[2048]; if(!fgets(buf,sizeof buf,stdin)) die("stdin");
        buf[strcspn(buf,"\r\n")]='\0';
        pass = str_dup(buf);
    }

    int replaced=0;
    for(size_t i=0;i<v.n;i++){
        if(strcmp(v.v[i].site,site)==0){
            free(v.v[i].user); free(v.v[i].pass);
            v.v[i].user = str_dup(user);
            v.v[i].pass = str_dup(pass);
            replaced=1; break;
        }
    }
    if(!replaced){
        Item itx={ str_dup(site), str_dup(user), str_dup(pass) };
        vpush(&v,itx);
    }

    if(vault_save(vault, mpw, &v, it)!=0) die("Falha ao salvar vault");
    printf("%s: %s/%s %s\n", replaced? "Atualizado":"Adicionado", site, user, want_gen? "(senha gerada)": "");
    if(generated){ cleanse(generated,strlen(generated)); free(generated); }
    if(pass && pass!=generated && pass!=NULL && pass!=user) { /*pass pode ser literal*/ }
    vfree(&v); cleanse(mpw,sizeof mpw);
    return 0;
}



static void usage(const char *p){
    fprintf(stderr,
    "Uso:\n"
    "  %s gen [-l 16] [--sets aA0s] [--allow-ambig]\n"
    "  %s init [-f vault.apv] [-i iter]\n"
    "  %s add  -s <site> -u <user> [-p <pass> | --gen N [--sets aA0s] [--allow-ambig]] [-f vault.apv]\n"
    "  %s list [-f vault.apv]\n"
    "  %s get  -s <site> [-f vault.apv]\n"
    "  %s rm   -s <site> [-f vault.apv]\n", p,p,p,p,p,p);
}

int main(int argc, char **argv){
    if(argc<2){ usage(argv[0]); return 1; }
    OpenSSL_add_all_algorithms();
    if(strcmp(argv[1],"gen")==0)  return cmd_gen(argc,argv);
    if(strcmp(argv[1],"init")==0) return cmd_init(argc,argv);
    if(strcmp(argv[1],"add")==0)  return cmd_add(argc,argv);
    if(strcmp(argv[1],"list")==0) return cmd_list(argc,argv);
    if(strcmp(argv[1],"get")==0)  return cmd_get(argc,argv);
    if(strcmp(argv[1],"rm")==0)   return cmd_rm(argc,argv);
    usage(argv[0]); return 1;
}
