#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include "cli/ui.h"
#include "core/runtime.h"

static void ui_vprintf(const char *color, const char *fmt, va_list ap){ printf("%s", color); vprintf(fmt, ap); printf(R); }

void ui_ok(const char *fmt, ...){ va_list ap; va_start(ap, fmt); printf(G B "%s " R, CHECK); ui_vprintf(G, fmt, ap); va_end(ap); printf("\n"); }
void ui_err(const char *fmt, ...){ va_list ap; va_start(ap, fmt); printf(Y B "%s " R, WARN); ui_vprintf(Y, fmt, ap); va_end(ap); printf("\n"); }
void ui_usage(const char *fmt, ...){ va_list ap; va_start(ap, fmt); printf(Y B "Usage:" R " "); ui_vprintf(C, fmt, ap); va_end(ap); printf("\n"); }

void help_header(void){
	printf(BL "+======================================================================+\n" R);
	printf(BL "|" B " XFER Help" R "                                                           " BL "|\n" R);
	printf(BL "+======================================================================+\n" R);
}

void section_heading(const char *title){ printf("\n" M "[%s]" R "\n", title); }
void box_top(void){ printf(BL "+----------------------------------------------------------------------+\n" R); }
void box_bottom(void){ printf(BL "+----------------------------------------------------------------------+\n" R); }
void help_line(const char *cmd, const char *desc){ printf(BL "| " C); printf("%-33s", cmd); printf(R "  %-33s" BL, desc); printf(" |\n" R); }
void help_footer(void){ printf(BL "| " G "Tip:" R " Use " C "cfg" R " to view current settings.                    " BL "|\n" R); printf(BL "+======================================================================+\n" R); }

static int allow_level(unsigned lvl){ const sx_runtime_cfg_t *c=sx_runtime_cfg_get(); return (unsigned)c->log_level <= lvl; }

static void vlog(const char *tag_color, const char *tag, const char *msg_color, const char *fmt, va_list ap){ printf("%s%s%s%s ", tag_color, B, tag, R); ui_vprintf(msg_color, fmt, ap); printf("\n"); }

void ui_log_debug(const char *fmt, ...){ if(!allow_level(0)) return; va_list ap; va_start(ap, fmt); vlog(C, "DBG", W, fmt, ap); va_end(ap); }
void ui_log_info(const char *fmt, ...){ if(!allow_level(1)) return; va_list ap; va_start(ap, fmt); vlog(G, "INF", W, fmt, ap); va_end(ap); }
void ui_log_warn(const char *fmt, ...){ if(!allow_level(2)) return; va_list ap; va_start(ap, fmt); vlog(Y, "WRN", Y, fmt, ap); va_end(ap); }
void ui_log_error(const char *fmt, ...){ if(!allow_level(3)) return; va_list ap; va_start(ap, fmt); vlog(RD, "ERR", RD, fmt, ap); va_end(ap); }
void ui_log_fatal(const char *fmt, ...){ if(!allow_level(4)) return; va_list ap; va_start(ap, fmt); vlog(RD, "FTL", RD, fmt, ap); va_end(ap); }

void ui_cmd_start(const char *cmdline){ printf(BL "+----------------------------------------------------------------------+\n" R); printf(BL "|" R " executing: " B C "%s" R "\n", cmdline?cmdline:"" ); printf(BL "+----------------------------------------------------------------------+\n" R); }
void ui_cmd_end(const char *cmdline, int rc, double elapsed_ms){ const char *col = rc==0?G:RD; const char *tag = rc==0?CHECK:CROSS; printf(BL "+----------------------------------------------------------------------+\n" R); printf(BL "|" R " result: %s%s%s %s" R "  " C "%.1fms" R "\n", col, B, tag, R, elapsed_ms); if(cmdline){ printf(BL "|" R " command: " B C "%s" R "\n", cmdline); } printf(BL "+----------------------------------------------------------------------+\n" R); }