#define _POSIX_C_SOURCE 200809L
#include "utils/fileio.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

int sx_file_open(sx_file_t *f, const char *path, int flags, int mode){
    if(!f || !path) return SX_FIO_ERR;
    int fd = open(path, flags, mode);
    if(fd < 0) return SX_FIO_ERR;
    memset(f,0,sizeof(*f));
    f->fd = fd;
    strncpy(f->path, path, sizeof(f->path)-1);
    struct stat st;
    if(fstat(fd,&st)==0) f->size = st.st_size;
    f->pos = 0;
    f->flags = flags;
    f->mode = mode;
    return SX_FIO_OK;
}

ssize_t sx_file_read(sx_file_t *f, void *buf, size_t count){
    if(!f || f->fd < 0) return -1;
    ssize_t r = read(f->fd, buf, count);
    if(r > 0) f->pos += r;
    if(r == 0) return SX_FIO_EOF;
    return r;
}

ssize_t sx_file_write(sx_file_t *f, const void *buf, size_t count){
    if(!f || f->fd < 0) return -1;
    ssize_t w = write(f->fd, buf, count);
    if(w > 0) f->pos += w;
    return w;
}

int sx_file_seek(sx_file_t *f, off_t offset, int whence){
    if(!f || f->fd < 0) return SX_FIO_ERR;
    off_t r = lseek(f->fd, offset, whence);
    if(r == (off_t)-1) return SX_FIO_ERR;
    f->pos = r;
    return SX_FIO_OK;
}

int sx_file_close(sx_file_t *f){
    if(!f) return SX_FIO_ERR;
    if(f->fd >= 0) close(f->fd);
    f->fd = -1;
    return SX_FIO_OK;
}

int sx_file_stat_size(const char *path, off_t *size_out){
    if(!path || !size_out) return SX_FIO_ERR;
    struct stat st;
    if(stat(path,&st) != 0) return SX_FIO_ERR;
    *size_out = st.st_size;
    return SX_FIO_OK;
}

int sx_file_truncate(const char *path, off_t length){
    if(!path) return SX_FIO_ERR;
    if(truncate(path, length) != 0) return SX_FIO_ERR;
    return SX_FIO_OK;
}
