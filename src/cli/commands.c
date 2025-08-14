#include <string.h>
#include <stdlib.h>
#include "cli/ui.h"
#include "cli/commands_decl.h"
#include "cli/registry.h"

typedef struct { const char *name; int (*func)(int argc, char **argv); } command_t;

static command_t commands[] = {
	{"xfer", cmd_xfer},
	{"encrypt", cmd_encrypt},
	{"compress", cmd_compress},
	{"chunk", cmd_chunk},
	{"throttle", cmd_throttle},
	{"port", cmd_port},
	{"cfg", cmd_cfg},
	{"auth", cmd_auth},
	{"streams", cmd_streams},
	{"hash", cmd_hash},
	{"ping", cmd_ping},
	{"stat", cmd_stat},
	{"resume", cmd_resume},
	{"sendr", cmd_sendr},
	{"sendg", cmd_sendg},
	{"sendp", cmd_sendp},
	{"cipher", cmd_cipher},
	{"zlevel", cmd_zlevel},
	{"verify", cmd_verify},
	{"progress", cmd_progress},
	{"timeout", cmd_timeout},
	{"ctmo", cmd_ctmo},
	{"retries", cmd_retries},
	{"keepalive", cmd_keepalive},
	{"overwrite", cmd_overwrite},
	{"preserve", cmd_preserve},
	{"loglevel", cmd_loglevel},
	{"ls", cmd_ls},
	{"du", cmd_du},
	{"version", cmd_version},
	{"help", cmd_help},
	{"exit", cmd_exit},
	{NULL, NULL}
};

int cli_execute(int argc, char **argv) {
	if (argc == 0) return -1;
	for (int i = 0; commands[i].name; ++i) {
		if (strcmp(commands[i].name, argv[0]) == 0)
			return commands[i].func(argc, argv);
	}
	ui_err("unknown command: %s", argv[0]);
	return -1;
}

size_t cli_command_count(void){ size_t n=0; while(commands[n].name) n++; return n; }
const char *cli_command_name_at(size_t idx){ return commands[idx].name; }
