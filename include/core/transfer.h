#ifndef SECUREXFER_TRANSFER_H
#define SECUREXFER_TRANSFER_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SX_XFER_IDLE = 0,
    SX_XFER_RUNNING,
    SX_XFER_PAUSED,
    SX_XFER_COMPLETED,
    SX_XFER_FAILED
} sx_xfer_state_t;

typedef struct sx_xfer_meta {
    char filename[1024];
    uint64_t filesize;
    uint64_t offset;
    uint32_t chunk_size;
    uint64_t checksum;
    uint64_t id;
    uint32_t flags;
} sx_xfer_meta_t;

typedef struct sx_xfer_stats {
    uint64_t bytes_transferred;
    uint64_t start_ts;
    uint64_t last_activity_ts;
    double speed_bytes_per_sec;
    int progress_percent;
} sx_xfer_stats_t;

typedef struct sx_session {
    uint8_t key[32];
    uint8_t iv[12];
    uint64_t send_seq;
    uint64_t recv_seq;
    int established;
    int compression;
} sx_session_t;

typedef struct sx_transfer {
    sx_xfer_meta_t meta;
    sx_xfer_stats_t stats;
    sx_xfer_state_t state;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int sock_fd;
    int resumable;
    int encrypted;
    sx_session_t session;
    uint64_t max_bytes;
    void *user;
    int (*on_progress)(struct sx_transfer *, const sx_xfer_stats_t *);
    int (*on_complete)(struct sx_transfer *, int);
} sx_transfer_t;

int sx_transfer_init(sx_transfer_t *t, const sx_xfer_meta_t *meta);
int sx_transfer_start(sx_transfer_t *t, int out_fd);
int sx_transfer_resume(sx_transfer_t *t);
int sx_transfer_pause(sx_transfer_t *t);
int sx_transfer_stop(sx_transfer_t *t);
int sx_transfer_destroy(sx_transfer_t *t);
int sx_transfer_send(const char *host, uint16_t port, const char *path);
int sx_transfer_send_offset(const char *host, uint16_t port, const char *path, uint64_t offset);
int sx_transfer_send_parallel(const char *host, uint16_t port, const char *path, uint32_t streams);
int sx_transfer_recv(uint16_t port, const char *out_path);
int sx_transfer_serve(uint16_t port, const char *out_dir);

#ifdef __cplusplus
}
#endif

#endif
