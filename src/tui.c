#include "aegisfim.h"
#include <ncurses.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { char **lines; size_t n, cap; } LogBuf;

static void log_push(LogBuf *L, const char *msg){
    if(L->n==L->cap){
        size_t newcap = L->cap? L->cap*2 : 256;
        char **nl = (char**)realloc(L->lines, newcap*sizeof(char*));
        if(!nl) return;
        L->lines = nl; L->cap = newcap;
    }
    L->lines[L->n++] = strdup(msg? msg:"");
    if(L->n > 2000){
        free(L->lines[0]);
        memmove(&L->lines[0], &L->lines[1], (L->n-1)*sizeof(char*));
        L->n--;
    }
}
static void log_free(LogBuf *L){
    for(size_t i=0;i<L->n;i++) free(L->lines[i]);
    free(L->lines);
}

static void pad_line_print(int y, const char *txt){
    int cols = getmaxx(stdscr);
    mvprintw(y, 0, "%.*s", cols, txt);
    int len = (int)strlen(txt);
    if(len < cols){
        move(y, len);
        for(int x=len; x<cols; ++x) addch(' ');
    }
}

static void draw_header(const char *root, const char *base, int interval, int watching){
    attron(A_REVERSE);
    char buf[1024];
    snprintf(buf, sizeof(buf), " AegisFIM TUI | dir: %s | baseline: %s | interval: %ds | %s ",
             root, base, interval, watching? "Watching":"Paused");
    pad_line_print(0, buf);
    attroff(A_REVERSE);
}
static void draw_footer(){
    int rows = getmaxy(stdscr);
    attron(A_REVERSE);
    pad_line_print(rows-1, " [i] init  [c] check  [w] watch  [+/-] interval  [q] quit ");
    attroff(A_REVERSE);
}

static void append_diff_log(const RecVec *base, const RecVec *curr, LogBuf *L,
                            size_t *a,size_t *r,size_t *m,size_t *u){
    *a=*r=*m=*u=0;
    size_t i=0,j=0;
    while(i<base->len && j<curr->len){
        int c = strcmp(base->items[i].path, curr->items[j].path);
        if(c==0){
            if(memcmp(base->items[i].sha256, curr->items[j].sha256, 32)==0){
                (*u)++;
            }else{
                (*m)++;
                char hb[65], hc[65], line[1024];
                sha256_hex(base->items[i].sha256, hb);
                sha256_hex(curr->items[j].sha256, hc);
                snprintf(line,sizeof(line),"[MOD] %s\n      old:%s\n      new:%s",
                         curr->items[j].path, hb, hc);
                log_push(L,line);
            }
            i++; j++;
        }else if(c<0){
            (*r)++;
            char line[1024];
            snprintf(line,sizeof(line),"[DEL] %s", base->items[i].path);
            log_push(L,line);
            i++;
        }else{
            (*a)++;
            char line[1024];
            snprintf(line,sizeof(line),"[ADD] %s", curr->items[j].path);
            log_push(L,line);
            j++;
        }
    }
    while(i<base->len){
        (*r)++; char line[1024];
        snprintf(line,sizeof(line),"[DEL] %s", base->items[i].path);
        log_push(L,line); i++;
    }
    while(j<curr->len){
        (*a)++; char line[1024];
        snprintf(line,sizeof(line),"[ADD] %s", curr->items[j].path);
        log_push(L,line); j++;
    }
}

static void do_init(const char *root, const char *base, LogBuf *L){
    RecVec v; scan_tree(root,&v); stable_sort(&v);
    if(baseline_save_tsv(base,&v)==0){
        char msg[256]; snprintf(msg,sizeof(msg)," baseline criada com %zu arquivos -> %s", v.len, base);
        log_push(L,msg);
    }else{
        log_push(L," erro salvando baseline");
    }
    vec_free(&v);
}
static void do_check(const char *root, const char *base, LogBuf *L){
    RecVec b; if(baseline_load_tsv(base,&b)!=0){ log_push(L," erro carregando baseline"); return; }
    stable_sort(&b);
    RecVec c; scan_tree(root,&c); stable_sort(&c);
    size_t a,r,m,u; append_diff_log(&b,&c,L,&a,&r,&m,&u);
    char line[128]; snprintf(line,sizeof(line),"[check] +%zu -%zu ~%zu =%zu (total:%zu)", a,r,m,u,c.len);
    log_push(L,line);
    vec_free(&b); vec_free(&c);
}

int run_tui(const char *root, const char *baseline, int interval){
    initscr(); cbreak(); noecho(); keypad(stdscr, TRUE);
    timeout(300);
    if(has_colors()){ start_color(); use_default_colors(); }

    LogBuf L={0};
    int watching = 0;
    time_t last = 0;

    for(;;){
        erase();
        draw_header(root, baseline, interval, watching);
        draw_footer();

        time_t now = time(NULL);
        if(watching && (now - last) >= interval){
            do_check(root, baseline, &L);
            last = now;
        }

        int rows = getmaxy(stdscr);
        if(L.n>0){
            const char *lastline = L.lines[L.n-1];
            if(strncmp(lastline, "[check]", 7)==0){
                mvprintw(1,0,"%s", lastline);
            }else{
                mvprintw(1,0,"Resumo: (rode [c] check ou [w] watch)");
            }
        }else{
            mvprintw(1,0,"Resumo: (rode [i] init ou [c] check)");
        }

        int top = 2;
        int max_visible = rows - 3;
        int start = (int)L.n - max_visible;
        if(start < 0) start = 0;

        int y = top;
        for(size_t i = (size_t)start; i < L.n && y < rows-1; ++i, ++y){
            pad_line_print(y, L.lines[i]);
        }

        refresh();

        int ch = getch();
        if(ch == ERR) continue;
        if(ch=='q' || ch=='Q'){ break; }
        else if(ch=='i' || ch=='I'){ do_init(root, baseline, &L); }
        else if(ch=='c' || ch=='C'){ do_check(root, baseline, &L); }
        else if(ch=='w' || ch=='W'){ watching = !watching; last = 0; }
        else if(ch=='+'){ if(interval<3600) interval++; }
        else if(ch=='-'){ if(interval>1) interval--; }
        else if(ch==KEY_RESIZE){ /* redesenha no próximo loop */ }
    }

    endwin();
    log_free(&L);
    return 0;
}
