#ifndef SECUREXFER_NETUTILS_H
#define SECUREXFER_NETUTILS_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SX_NET_OK = 0,
    SX_NET_ERR = -1
} sx_net_err_t;

int sx_net_bind_tcp(int *out_fd, const char *host, uint16_t port, int backlog);
int sx_net_connect_tcp(int *out_fd, const char *host, uint16_t port, int timeout_ms);
int sx_net_set_nonblock(int fd);
int sx_net_set_reuseaddr(int fd);
int sx_net_close(int fd);
ssize_t sx_net_send_all(int fd, const void *buf, size_t len, int flags);
ssize_t sx_net_recv_all(int fd, void *buf, size_t len, int flags);
int sx_net_peek_peer_name(int fd, struct sockaddr_in *peer);

#ifdef __cplusplus
}
#endif

#endif
