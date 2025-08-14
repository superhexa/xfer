#ifndef SECUREXFER_FILEIO_H
#define SECUREXFER_FILEIO_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SX_FIO_OK = 0,
    SX_FIO_ERR = -1,
    SX_FIO_EOF = 1
} sx_fio_err_t;

typedef struct sx_file {
    int fd;
    char path[1024];
    off_t size;
    off_t pos;
    int flags;
    int mode;
} sx_file_t;

int sx_file_open(sx_file_t *f, const char *path, int flags, int mode);
ssize_t sx_file_read(sx_file_t *f, void *buf, size_t count);
ssize_t sx_file_write(sx_file_t *f, const void *buf, size_t count);
int sx_file_seek(sx_file_t *f, off_t offset, int whence);
int sx_file_close(sx_file_t *f);
int sx_file_stat_size(const char *path, off_t *size_out);
int sx_file_truncate(const char *path, off_t length);

#ifdef __cplusplus
}
#endif

#endif
