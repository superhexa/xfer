#include "utils/netutils.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

int sx_net_bind_tcp(int *out_fd, const char *host, uint16_t port, int backlog){
    if(!out_fd) return SX_NET_ERR;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if(s < 0) return SX_NET_ERR;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = host ? inet_addr(host) : INADDR_ANY;
    if(bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0){ close(s); return SX_NET_ERR; }
    if(listen(s, backlog) != 0){ close(s); return SX_NET_ERR; }
    *out_fd = s;
    return SX_NET_OK;
}

int sx_net_connect_tcp(int *out_fd, const char *host, uint16_t port, int timeout_ms){
    if(!out_fd || !host) return SX_NET_ERR;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if(s < 0) return SX_NET_ERR;
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host);
    if(connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0){ close(s); return SX_NET_ERR; }
    *out_fd = s;
    return SX_NET_OK;
}

int sx_net_set_nonblock(int fd){
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags == -1) return SX_NET_ERR;
    if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) return SX_NET_ERR;
    return SX_NET_OK;
}

int sx_net_set_reuseaddr(int fd){
    int one = 1;
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) return SX_NET_ERR;
    return SX_NET_OK;
}

int sx_net_close(int fd){
    if(fd >= 0) close(fd);
    return SX_NET_OK;
}

ssize_t sx_net_send_all(int fd, const void *buf, size_t len, int flags){
    size_t sent = 0;
    const uint8_t *p = buf;
    while(sent < len){
        ssize_t w = send(fd, p + sent, len - sent, flags);
        if(w <= 0) return -1;
        sent += (size_t)w;
    }
    return (ssize_t)sent;
}

ssize_t sx_net_recv_all(int fd, void *buf, size_t len, int flags){
    size_t recvd = 0;
    uint8_t *p = buf;
    while(recvd < len){
        ssize_t r = recv(fd, p + recvd, len - recvd, flags);
        if(r <= 0) return -1;
        recvd += (size_t)r;
    }
    return (ssize_t)recvd;
}

int sx_net_peek_peer_name(int fd, struct sockaddr_in *peer){
    if(!peer) return SX_NET_ERR;
    socklen_t sl = sizeof(*peer);
    if(getpeername(fd, (struct sockaddr *)peer, &sl) != 0) return SX_NET_ERR;
    return SX_NET_OK;
}
