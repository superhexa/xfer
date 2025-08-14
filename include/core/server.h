#ifndef SECUREXFER_SERVER_H
#define SECUREXFER_SERVER_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SX_DEFAULT_BACKLOG 128
#define SX_MAX_CLIENTS 1024

typedef enum {
    SX_SRV_OK = 0,
    SX_SRV_ERR = -1,
    SX_SRV_INVALID_CFG = -2,
    SX_SRV_BIND_FAIL = -3,
    SX_SRV_LISTEN_FAIL = -4
} sx_srv_err_t;

typedef struct sx_listener {
    int fd;
    struct sockaddr_in addr;
    uint16_t port;
    int backlog;
    int reuse_addr;
} sx_listener_t;

typedef struct sx_client {
    int fd;
    struct sockaddr_in peer;
    uint64_t id;
    pthread_t thread;
    void *user;
} sx_client_t;

typedef struct sx_server_cfg {
    uint16_t port;
    const char *host;
    size_t max_clients;
    int ipv6;
    int enable_tls;
    const char *cert_file;
    const char *key_file;
    int backlog; 
} sx_server_cfg_t;

typedef struct sx_server {
    sx_listener_t listener;
    sx_server_cfg_t cfg;
    sx_client_t **clients;
    size_t client_count;
    pthread_mutex_t clients_lock;
    volatile int running;
    void (*on_connect)(sx_client_t *);
    void (*on_disconnect)(sx_client_t *);
    void (*on_error)(struct sx_server *, int);
} sx_server_t;

sx_srv_err_t sx_server_init(sx_server_t *srv, const sx_server_cfg_t *cfg);
sx_srv_err_t sx_server_start(sx_server_t *srv);
sx_srv_err_t sx_server_stop(sx_server_t *srv);
sx_srv_err_t sx_server_destroy(sx_server_t *srv);
int sx_server_dispatch_accept(sx_server_t *srv);
int sx_server_register_client(sx_server_t *srv, sx_client_t *client);
int sx_server_unregister_client(sx_server_t *srv, sx_client_t *client);

#ifdef __cplusplus
}
#endif

#endif
