#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <glob.h>
#include "core/transfer.h"
#include "core/runtime.h"
#include "cli/ui.h"
#include "cli/commands_decl.h"

int cmd_xfer(int argc, char **argv) {
	if (argc < 2) { ui_usage("xfer <send|recv|serve> ..."); return -1; }
	if (strcmp(argv[1], "send") == 0) {
		if (argc < 5) { ui_usage("xfer send <host> <port> <file>"); return -1; }
		const char *host = argv[2]; uint16_t port = (uint16_t)atoi(argv[3]); const char *file = argv[4];
		int rc = sx_transfer_send(host, port, file);
		if(rc!=0) ui_log_error("send failed: %d", rc);
		return rc;
	} else if (strcmp(argv[1], "recv") == 0) {
		if (argc < 4) { ui_usage("xfer recv <port> <outfile>"); return -1; }
		uint16_t port = (uint16_t)atoi(argv[2]); const char *file = argv[3];
		int rc = sx_transfer_recv(port, file);
		if(rc!=0) ui_log_error("recv failed: %d", rc);
		return rc;
	} else if (strcmp(argv[1], "serve") == 0) {
		if (argc < 4) { ui_usage("xfer serve <port> <out_dir>"); return -1; }
		uint16_t port = (uint16_t)atoi(argv[2]); const char *outdir = argv[3];
		int rc = sx_transfer_serve(port, outdir);
		if(rc!=0) ui_log_error("serve failed: %d", rc);
		return rc;
	} else { ui_err("unknown mode: %s", argv[1]); return -1; }
}

static int send_one(const char *host, uint16_t port, const char *path){ return sx_transfer_send(host, port, path); }

int cmd_sendr(int argc, char **argv){ if(argc<4){ ui_usage("sendr <host> <port> <dir>"); return -1; } const char*host=argv[1]; uint16_t port=(uint16_t)atoi(argv[2]); const char*dir=argv[3]; DIR *d = opendir(dir); if(!d){ ui_log_error("opendir failed: %s", dir); return -1;} struct dirent *e; char buf[4096]; int rc=0; while((e=readdir(d))){ if(strcmp(e->d_name,".")==0||strcmp(e->d_name,"..")==0) continue; snprintf(buf,sizeof(buf), "%s/%s", dir, e->d_name); struct stat st; if(stat(buf,&st)==0){ if(S_ISREG(st.st_mode)) { int trc = send_one(host, port, buf); if(trc!=0){ ui_log_warn("send failed (%d): %s", trc, buf); rc=trc; } } } }
closedir(d); return rc; }
int cmd_sendg(int argc, char **argv){ if(argc<4){ ui_usage("sendg <host> <port> <pattern>"); return -1; } const char*host=argv[1]; uint16_t port=(uint16_t)atoi(argv[2]); glob_t g; memset(&g,0,sizeof(g)); if(glob(argv[3],0,NULL,&g)!=0){ ui_log_warn("no matches: %s", argv[3]); return -1;} int rc=0; for(size_t i=0;i<g.gl_pathc;i++){ int trc = send_one(host, port, g.gl_pathv[i]); if(trc!=0){ ui_log_warn("send failed (%d): %s", trc, g.gl_pathv[i]); rc=trc; } } globfree(&g); return rc; }
int cmd_sendp(int argc, char **argv){ if(argc<4){ ui_usage("sendp <host> <port> <pattern>"); return -1; } const char*host=argv[1]; uint16_t port=(uint16_t)atoi(argv[2]); glob_t g; memset(&g,0,sizeof(g)); if(glob(argv[3],0,NULL,&g)!=0){ ui_log_warn("no matches: %s", argv[3]); return -1;} int rc=0; for(size_t i=0;i<g.gl_pathc;i++){ int trc = send_one(host, port, g.gl_pathv[i]); if(trc!=0){ ui_log_warn("send failed (%d): %s", trc, g.gl_pathv[i]); rc=trc; } } globfree(&g); return rc; }
int cmd_resume(int argc, char **argv){ if(argc<5){ ui_usage("resume <host> <port> <file> <offset>"); return -1; } const char*host=argv[1]; uint16_t port=(uint16_t)atoi(argv[2]); const char*file=argv[3]; uint64_t off=strtoull(argv[4],NULL,10); extern int sx_transfer_send_offset(const char*,uint16_t,const char*,uint64_t); return sx_transfer_send_offset(host,port,file,off); }