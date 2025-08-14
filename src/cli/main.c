#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cli/parser.h"
#include "cli/commands.h"
#include "cli/ui.h"
#include "cli/lineread.h"

#define BUF_SIZE 4096

#define ANSI_RESET      "\033[0m"
#define ANSI_BOLD       "\033[1m"
#define FG_RED          "\033[31m"
#define FG_GREEN        "\033[32m"
#define FG_YELLOW       "\033[33m"
#define FG_CYAN         "\033[36m"
#define FG_MAGENTA      "\033[35m"
#define FG_BLUE         "\033[34m"
#define FG_WHITE        "\033[37m"

static void print_banner(void) {
    printf(FG_MAGENTA ANSI_BOLD "╔" FG_CYAN "════════════════════════════════════════════════════" FG_BLUE "╗\n" ANSI_RESET);
    printf(FG_MAGENTA ANSI_BOLD "║          ██╗  ██╗███████╗███████╗██████╗           ║\n");
    printf(FG_MAGENTA ANSI_BOLD "║          ╚██╗██╔╝██╔════╝██╔════╝██╔══██╗          ║\n");
    printf(FG_MAGENTA ANSI_BOLD "║           ╚███╔╝ █████╗  █████╗  ██████╔╝          ║\n");
    printf(FG_MAGENTA ANSI_BOLD "║           ██╔██╗ ██╔══╝  ██╔══╝  ██╔══██╗          ║\n");
    printf(FG_MAGENTA ANSI_BOLD "║          ██╔╝ ██╗██║     ███████╗██║  ██║          ║\n");
    printf(FG_MAGENTA ANSI_BOLD "║          ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝          ║\n");
    printf(FG_MAGENTA ANSI_BOLD "╚" FG_CYAN "════════════════════════════════════════════════════" FG_BLUE "╝\n" ANSI_RESET);
    printf(FG_GREEN "Secure E2E Encrypted File Transfer Tool\n" ANSI_RESET);
    printf(FG_YELLOW "Type " FG_CYAN "help" FG_YELLOW " to view all commands\n\n" ANSI_RESET);
}

static void print_prompt(int line) {
    (void)line;
    printf(FG_BLUE ANSI_BOLD "xfer" FG_CYAN " ➜ " ANSI_RESET);
    fflush(stdout);
}

static void shell_loop(void) {
	int argc; char **argv; int line_count = 1;
	while (1) {
		print_prompt(line_count);
		char *line = cli_readline("");
		if (!line) break;
		argv = cli_parse(line, &argc);
		if (argc > 0) {
			int rc;
			ui_cmd_start(line);
			rc = cli_execute(argc, argv);
			if (rc < 0) ui_log_warn("command returned %d", rc);
			ui_cmd_end(line, rc, 0.0);
		}
		free(line);
		cli_free_args(argv, argc);
		line_count++;
	}
}

int main(void) {
#ifdef _WIN32
    system("");
#endif
    print_banner();
    shell_loop();
    printf(FG_YELLOW "\nGoodbye!\n" ANSI_RESET);
    return 0;
}
