#include "utils/buffer.h"
#include <stdlib.h>
#include <string.h>

int sx_buffer_init(sx_buffer_t *b, size_t segment_size){
    if(!b || segment_size == 0) return -1;
    memset(b,0,sizeof(*b));
    b->segment_size = segment_size;
    pthread_mutex_init(&b->lock, NULL);
    return 0;
}

int sx_buffer_push(sx_buffer_t *b, const uint8_t *data, size_t len){
    if(!b || !data || len==0) return -1;
    pthread_mutex_lock(&b->lock);
    size_t off = 0;
    while(off < len){
        size_t need = b->segment_size;
        sx_buf_segment_t *seg = b->tail;
        if(!seg || seg->cap - seg->len == 0){
            sx_buf_segment_t *n = malloc(sizeof(*n));
            n->data = malloc(b->segment_size);
            n->len = 0;
            n->cap = b->segment_size;
            n->next = NULL;
            if(!b->head) b->head = n;
            if(b->tail) b->tail->next = n;
            b->tail = n;
            seg = n;
        }
        size_t writable = seg->cap - seg->len;
        size_t tocopy = (len - off) < writable ? (len - off) : writable;
        memcpy(seg->data + seg->len, data + off, tocopy);
        seg->len += tocopy;
        off += tocopy;
        b->total_len += tocopy;
    }
    pthread_mutex_unlock(&b->lock);
    return 0;
}

int sx_buffer_pop(sx_buffer_t *b, uint8_t *out, size_t len){
    if(!b || !out || len==0) return -1;
    pthread_mutex_lock(&b->lock);
    size_t need = len;
    size_t written = 0;
    while(written < need && b->head){
        sx_buf_segment_t *seg = b->head;
        size_t toread = (need - written) < seg->len ? (need - written) : seg->len;
        memcpy(out + written, seg->data, toread);
        if(toread < seg->len){
            memmove(seg->data, seg->data + toread, seg->len - toread);
            seg->len -= toread;
        } else {
            b->head = seg->next;
            if(b->tail == seg) b->tail = NULL;
            free(seg->data);
            free(seg);
        }
        written += toread;
        b->total_len -= toread;
    }
    pthread_mutex_unlock(&b->lock);
    return (int)written;
}

size_t sx_buffer_len(const sx_buffer_t *b){
    if(!b) return 0;
    return b->total_len;
}

int sx_buffer_clear(sx_buffer_t *b){
    if(!b) return -1;
    pthread_mutex_lock(&b->lock);
    sx_buf_segment_t *cur = b->head;
    while(cur){
        sx_buf_segment_t *n = cur->next;
        free(cur->data);
        free(cur);
        cur = n;
    }
    b->head = b->tail = NULL;
    b->total_len = 0;
    pthread_mutex_unlock(&b->lock);
    return 0;
}

int sx_buffer_destroy(sx_buffer_t *b){
    if(!b) return -1;
    sx_buffer_clear(b);
    pthread_mutex_destroy(&b->lock);
    return 0;
}
