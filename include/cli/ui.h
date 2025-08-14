#ifndef XFER_CLI_UI_H
#define XFER_CLI_UI_H

#ifdef __cplusplus
extern "C" {
#endif

#define R "\033[0m"
#define B "\033[1m"
#define C "\033[36m"
#define G "\033[32m"
#define Y "\033[33m"
#define M "\033[35m"
#define BL "\033[34m"
#define W "\033[37m"
#define RD "\033[31m"

#define CHECK "[OK]"
#define WARN  "[!]"
#define CROSS "[X]"

void ui_ok(const char *fmt, ...);
void ui_err(const char *fmt, ...);
void ui_usage(const char *fmt, ...);

void help_header(void);
void section_heading(const char *title);
void box_top(void);
void box_bottom(void);
void help_line(const char *cmd, const char *desc);
void help_footer(void);

void ui_log_debug(const char *fmt, ...);
void ui_log_info(const char *fmt, ...);
void ui_log_warn(const char *fmt, ...);
void ui_log_error(const char *fmt, ...);
void ui_log_fatal(const char *fmt, ...);

void ui_cmd_start(const char *cmdline);
void ui_cmd_end(const char *cmdline, int rc, double elapsed_ms);

#ifdef __cplusplus
}
#endif

#endif