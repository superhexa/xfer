#include <stdlib.h>
#include <string.h>
#include "core/runtime.h"
#include "cli/ui.h"
#include "cli/commands_decl.h"

int cmd_compress(int argc, char **argv){ if(argc<2) { ui_usage("compress <on|off>"); return -1; } sx_runtime_cfg_set_compress(strcmp(argv[1],"on")==0); ui_ok("compression=%s", sx_runtime_cfg_get()->compression_enabled?"on":"off"); return 0; }
int cmd_zlevel(int argc, char **argv){ if(argc<2){ ui_usage("zlevel <0-9>"); return -1; } int lv=(int)strtol(argv[1],NULL,10); if(lv<0) lv=0; if(lv>9) lv=9; sx_runtime_cfg_set_zlevel(lv); ui_ok("zlevel=%d", sx_runtime_cfg_get()->zlib_level); return 0; }
int cmd_chunk(int argc, char **argv){ if(argc<2){ ui_usage("chunk <bytes>"); return -1; } sx_runtime_cfg_set_chunk((uint32_t)strtoul(argv[1],NULL,10)); ui_ok("chunk=%u", sx_runtime_cfg_get()->chunk_size); return 0; }
int cmd_throttle(int argc, char **argv){ if(argc<2){ ui_usage("throttle <kbps>"); return -1; } sx_runtime_cfg_set_throttle((uint32_t)strtoul(argv[1],NULL,10)); ui_ok("throttle=%ukbps", sx_runtime_cfg_get()->throttle_kbps); return 0; }
int cmd_streams(int argc, char **argv){ if(argc<2){ ui_usage("streams <n>"); return -1; } sx_runtime_cfg_set_streams((uint32_t)strtoul(argv[1],NULL,10)); ui_ok("streams=%u", sx_runtime_cfg_get()->streams); return 0; }
int cmd_progress(int argc, char **argv){ if(argc<2){ ui_usage("progress <none|bar|dots|n>"); return -1; } int style; if(strcmp(argv[1],"none")==0) style=0; else if(strcmp(argv[1],"bar")==0) style=1; else if(strcmp(argv[1],"dots")==0) style=2; else style=(int)strtol(argv[1],NULL,10); sx_runtime_cfg_set_progress_style(style); ui_ok("progress=%d", sx_runtime_cfg_get()->progress_style); return 0; }
int cmd_timeout(int argc, char **argv){ if(argc<2){ ui_usage("timeout <ms>"); return -1; } sx_runtime_cfg_set_io_timeout((uint32_t)strtoul(argv[1],NULL,10)); ui_log_info("timeout=%ums", sx_runtime_cfg_get()->io_timeout_ms); return 0; }
int cmd_ctmo(int argc, char **argv){ if(argc<2){ ui_usage("ctmo <ms>"); return -1; } sx_runtime_cfg_set_connect_timeout((uint32_t)strtoul(argv[1],NULL,10)); ui_ok("ctmo=%ums", sx_runtime_cfg_get()->connect_timeout_ms); return 0; }
int cmd_retries(int argc, char **argv){ if(argc<2){ ui_usage("retries <n>"); return -1; } sx_runtime_cfg_set_retries((uint32_t)strtoul(argv[1],NULL,10)); ui_ok("retries=%u", sx_runtime_cfg_get()->max_retries); return 0; }
int cmd_keepalive(int argc, char **argv){ if(argc<2){ ui_usage("keepalive <on|off>"); return -1; } sx_runtime_cfg_set_keepalive(strcmp(argv[1],"on")==0); ui_ok("keepalive=%s", sx_runtime_cfg_get()->keepalive_enabled?"on":"off"); return 0; }
int cmd_port(int argc, char **argv){ if(argc<2){ ui_usage("port <num>"); return -1; } sx_runtime_cfg_set_port((uint32_t)strtoul(argv[1],NULL,10)); ui_ok("port=%u", sx_runtime_cfg_get()->default_port); return 0; }