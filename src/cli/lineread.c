#define _POSIX_C_SOURCE 200809L
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cli/lineread.h"
#include "cli/registry.h"

static int set_raw_mode(int enable){ static struct termios orig; static int saved=0; if(enable){ struct termios t; if(tcgetattr(STDIN_FILENO,&orig)<0) return -1; saved=1; t=orig; t.c_lflag &= ~(ICANON|ECHO); t.c_cc[VMIN]=1; t.c_cc[VTIME]=0; if(tcsetattr(STDIN_FILENO,TCSAFLUSH,&t)<0) return -1; } else if(saved){ tcsetattr(STDIN_FILENO,TCSAFLUSH,&orig); } return 0; }

static const char *complete(const char *prefix){ size_t n=cli_command_count(); size_t match_count=0; const char *first=NULL; size_t prelen=strlen(prefix); for(size_t i=0;i<n;i++){ const char *name=cli_command_name_at(i); if(strncmp(name,prefix,prelen)==0){ if(!first) first=name; match_count++; if(match_count>1) return NULL; } } return match_count==1?first:NULL; }

char *cli_readline(const char *prompt){ fputs(prompt, stdout); fflush(stdout); size_t cap=128; size_t len=0; char *buf=(char*)malloc(cap); if(!buf) return NULL; while(1){ unsigned char c; if(read(STDIN_FILENO,&c,1)!=1){ free(buf); return NULL; } if(c=='\n' || c=='\r'){ fputc('\n', stdout); buf[len]=0; return buf; } if(c==127 || c=='\b'){ if(len>0){ len--; fputs("\b \b", stdout); fflush(stdout); } continue; } if(c=='\t'){ buf[len]=0; const char *m=complete(buf); if(m){ const char *suffix=m+len; fputs(suffix, stdout); fflush(stdout); size_t add=strlen(suffix); if(len+add+1>cap){ cap=(len+add+1)*2; buf=(char*)realloc(buf,cap);} memcpy(buf+len,suffix,add); len+=add; } continue; } if(c<32) continue; if(len+2>cap){ cap*=2; buf=(char*)realloc(buf,cap); } buf[len++]=c; fputc(c, stdout); fflush(stdout); }
}