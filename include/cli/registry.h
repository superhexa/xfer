#ifndef XFER_CLI_REGISTRY_H
#define XFER_CLI_REGISTRY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

size_t cli_command_count(void);
const char *cli_command_name_at(size_t idx);

#ifdef __cplusplus
}
#endif

#endif