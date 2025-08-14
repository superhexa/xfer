#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include "core/runtime.h"
#include "cli/ui.h"
#include "cli/commands_decl.h"

int cmd_stat(int argc, char **argv){ if(argc<2){ ui_usage("stat <file>"); return -1; } struct stat st; if(stat(argv[1],&st)!=0){perror("stat");return -1;} printf("size=%lld mode=%o\n", (long long)st.st_size, (unsigned)st.st_mode); return 0; }
int cmd_overwrite(int argc, char **argv){ if(argc<2){ ui_usage("overwrite <skip|ask|force>"); return -1; } int p; if(strcmp(argv[1],"skip")==0) p=0; else if(strcmp(argv[1],"ask")==0) p=1; else if(strcmp(argv[1],"force")==0) p=2; else { ui_err("bad policy: %s", argv[1]); return -1; } sx_runtime_cfg_set_overwrite_policy(p); ui_ok("overwrite=%s", argv[1]); return 0; }
int cmd_preserve(int argc, char **argv){ if(argc<2){ ui_usage("preserve <mode|mtime|all|none>"); return -1; } if(strcmp(argv[1],"all")==0){ sx_runtime_cfg_set_preserve_mode(1); sx_runtime_cfg_set_preserve_mtime(1); ui_ok("preserve=mode,mtime"); return 0; } if(strcmp(argv[1],"none")==0){ sx_runtime_cfg_set_preserve_mode(0); sx_runtime_cfg_set_preserve_mtime(0); ui_ok("preserve=none"); return 0; } if(strcmp(argv[1],"mode")==0){ sx_runtime_cfg_set_preserve_mode(1); ui_ok("preserve=mode"); return 0; } if(strcmp(argv[1],"mtime")==0){ sx_runtime_cfg_set_preserve_mtime(1); ui_ok("preserve=mtime"); return 0; } ui_err("bad value: %s", argv[1]); return -1; }
int cmd_ls(int argc, char **argv){ const char*path = argc>1?argv[1]:"."; DIR *d=opendir(path); if(!d){perror("opendir"); return -1;} struct dirent *e; while((e=readdir(d))){ if(strcmp(e->d_name,".")==0||strcmp(e->d_name,"..")==0) continue; printf("%s\n", e->d_name); } closedir(d); return 0; }
static unsigned long long du_sum_path(const char *path){ struct stat st; if(stat(path,&st)!=0) return 0ULL; if(S_ISREG(st.st_mode)) return (unsigned long long)st.st_size; if(S_ISDIR(st.st_mode)){ unsigned long long total=0ULL; DIR *d=opendir(path); if(!d) return 0ULL; struct dirent *e; char buf[4096]; while((e=readdir(d))){ if(strcmp(e->d_name,".")==0||strcmp(e->d_name,"..")==0) continue; snprintf(buf,sizeof(buf), "%s/%s", path, e->d_name); total += du_sum_path(buf); } closedir(d); return total; } return 0ULL; }
int cmd_du(int argc, char **argv){ const char*path = argc>1?argv[1]:"."; unsigned long long t = du_sum_path(path); printf("%llu\n", t); return 0; }