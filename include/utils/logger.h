#ifndef SECUREXFER_LOGGER_H
#define SECUREXFER_LOGGER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SX_LOG_DEBUG = 0,
    SX_LOG_INFO,
    SX_LOG_WARN,
    SX_LOG_ERROR,
    SX_LOG_FATAL
} sx_log_level_t;

typedef struct sx_logger {
    FILE *out;
    sx_log_level_t level;
    pthread_mutex_t lock;
    int use_syslog;
    const char *ident;
} sx_logger_t;

int sx_logger_init(sx_logger_t *l, FILE *out, sx_log_level_t level, const char *ident);
void sx_logger_log(sx_logger_t *l, sx_log_level_t lvl, const char *fmt, ...);
void sx_logger_set_level(sx_logger_t *l, sx_log_level_t lvl);
void sx_logger_destroy(sx_logger_t *l);

#ifdef __cplusplus
}
#endif

#endif
