#define _POSIX_C_SOURCE 199309L
#include <timer.h>
#include <time.h>
#include <string.h>

int sx_timer_start(sx_timer_t *t){
    if(!t) return -1;
    memset(t,0,sizeof(*t));
    clock_gettime(CLOCK_MONOTONIC, &t->start);
    t->last = t->start;
    t->elapsed_ms = 0.0;
    t->delta_ms = 0.0;
    return 0;
}

int sx_timer_tick(sx_timer_t *t){
    if(!t) return -1;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double last_ms = (double)t->last.tv_sec * 1000.0 + (double)t->last.tv_nsec / 1e6;
    double now_ms = (double)now.tv_sec * 1000.0 + (double)now.tv_nsec / 1e6;
    t->delta_ms = now_ms - last_ms;
    t->elapsed_ms = now_ms - ((double)t->start.tv_sec * 1000.0 + (double)t->start.tv_nsec / 1e6);
    t->last = now;
    return 0;
}

double sx_timer_elapsed_ms(const sx_timer_t *t){
    if(!t) return 0.0;
    return t->elapsed_ms;
}

double sx_timer_delta_ms(const sx_timer_t *t){
    if(!t) return 0.0;
    return t->delta_ms;
}
