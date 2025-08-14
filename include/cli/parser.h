#ifndef SECUREXFER_PARSER_H
#define SECUREXFER_PARSER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

char **cli_parse(const char *input, int *out_argc);
void cli_free_args(char **args, int argc);
int cli_execute(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif
