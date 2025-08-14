#include <string.h>
#include <stdlib.h>
#include "core/runtime.h"
#include "cli/ui.h"
#include "cli/commands_decl.h"

int cmd_encrypt(int argc, char **argv){ if(argc<2) { ui_usage("encrypt <on|off>"); return -1; } sx_runtime_cfg_set_encrypt(strcmp(argv[1],"on")==0); ui_ok("encryption=%s", sx_runtime_cfg_get()->encryption_enabled?"on":"off"); return 0; }
int cmd_auth(int argc, char **argv){ if(argc<2){ ui_usage("auth <token>"); return -1; } sx_runtime_cfg_set_auth(argv[1]); ui_ok("auth=set"); return 0; }
int cmd_cipher(int argc, char **argv){ if(argc<2){ ui_usage("cipher <aes|chacha>"); return -1; } const char *v=argv[1]; if(strcmp(v,"aes")==0||strcmp(v,"aesgcm")==0){ sx_runtime_cfg_set_cipher(1); ui_ok("cipher=aesgcm"); return 0; } if(strcmp(v,"chacha")==0||strcmp(v,"chacha20")==0||strcmp(v,"cc20")==0){ sx_runtime_cfg_set_cipher(2); ui_ok("cipher=chacha20"); return 0; } ui_err("unknown cipher: %s", v); return -1; }
int cmd_verify(int argc, char **argv){ if(argc<2){ ui_usage("verify <on|off>"); return -1; } sx_runtime_cfg_set_verify(strcmp(argv[1],"on")==0); ui_ok("verify=%s", sx_runtime_cfg_get()->verify_enabled?"on":"off"); return 0; }