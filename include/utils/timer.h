#ifndef SECUREXFER_TIMER_H
#define SECUREXFER_TIMER_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sx_timer {
    struct timespec start;
    struct timespec last;
    double elapsed_ms;
    double delta_ms;
} sx_timer_t;

int sx_timer_start(sx_timer_t *t);
int sx_timer_tick(sx_timer_t *t);
double sx_timer_elapsed_ms(const sx_timer_t *t);
double sx_timer_delta_ms(const sx_timer_t *t);

#ifdef __cplusplus
}
#endif

#endif
