#ifndef SECUREXFER_BUFFER_H
#define SECUREXFER_BUFFER_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sx_buf_segment {
    uint8_t *data;
    size_t len;
    size_t cap;
    struct sx_buf_segment *next;
} sx_buf_segment_t;

typedef struct sx_buffer {
    sx_buf_segment_t *head;
    sx_buf_segment_t *tail;
    size_t total_len;
    size_t segment_size;
    pthread_mutex_t lock;
} sx_buffer_t;

int sx_buffer_init(sx_buffer_t *b, size_t segment_size);
int sx_buffer_push(sx_buffer_t *b, const uint8_t *data, size_t len);
int sx_buffer_pop(sx_buffer_t *b, uint8_t *out, size_t len);
size_t sx_buffer_len(const sx_buffer_t *b);
int sx_buffer_clear(sx_buffer_t *b);
int sx_buffer_destroy(sx_buffer_t *b);

#ifdef __cplusplus
}
#endif

#endif
