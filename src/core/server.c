#include "core/server.h"
#include "utils/netutils.h"
#include "core/protocol.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

static void *sx_server_client_thread(void *arg){
    sx_client_t *c = (sx_client_t *)arg;
    uint8_t hdrbuf[sizeof(sx_proto_hdr_t)];
    while(1){
        ssize_t r = recv(c->fd, hdrbuf, sizeof(hdrbuf), 0);
        if(r <= 0) break;
        sx_packet_t p;
        if(sx_proto_parse(hdrbuf, r, &p) != 0) break;
        if(p.payload) sx_proto_free_packet(&p);
    }
    close(c->fd);
    return NULL;
}

sx_srv_err_t sx_server_init(sx_server_t *srv, const sx_server_cfg_t *cfg){
    if(!srv || !cfg) return SX_SRV_INVALID_CFG;
    memset(srv,0,sizeof(*srv));
    srv->cfg = *cfg;
    srv->listener.fd = -1;
    if(sx_net_bind_tcp(&srv->listener.fd, cfg->host, cfg->port, cfg->backlog) != SX_NET_OK){}
    srv->clients = calloc(cfg->max_clients, sizeof(sx_client_t *));
    pthread_mutex_init(&srv->clients_lock, NULL);
    srv->running = 0;
    return SX_SRV_OK;
}

sx_srv_err_t sx_server_start(sx_server_t *srv){
    if(!srv) return SX_SRV_ERR;
    srv->running = 1;
    while(srv->running){
        struct sockaddr_in peer;
        socklen_t sl = sizeof(peer);
        int cfd = accept(srv->listener.fd, (struct sockaddr *)&peer, &sl);
        if(cfd < 0) continue;
        sx_client_t *c = malloc(sizeof(*c));
        memset(c,0,sizeof(*c));
        c->fd = cfd;
        c->peer = peer;
        c->id = (uint64_t)cfd;
        pthread_create(&c->thread, NULL, sx_server_client_thread, c);
        sx_server_register_client(srv, c);
        if(srv->on_connect) srv->on_connect(c);
    }
    return SX_SRV_OK;
}

sx_srv_err_t sx_server_stop(sx_server_t *srv){
    if(!srv) return SX_SRV_ERR;
    srv->running = 0;
    close(srv->listener.fd);
    return SX_SRV_OK;
}

sx_srv_err_t sx_server_destroy(sx_server_t *srv){
    if(!srv) return SX_SRV_ERR;
    for(size_t i=0;i<srv->client_count;i++){
        if(srv->clients[i]) {
            close(srv->clients[i]->fd);
            free(srv->clients[i]);
            srv->clients[i] = NULL;
        }
    }
    free(srv->clients);
    pthread_mutex_destroy(&srv->clients_lock);
    return SX_SRV_OK;
}

int sx_server_dispatch_accept(sx_server_t *srv){
    return 0;
}

int sx_server_register_client(sx_server_t *srv, sx_client_t *client){
    if(!srv || !client) return -1;
    pthread_mutex_lock(&srv->clients_lock);
    if(srv->client_count < srv->cfg.max_clients){
        srv->clients[srv->client_count++] = client;
        pthread_mutex_unlock(&srv->clients_lock);
        return 0;
    }
    pthread_mutex_unlock(&srv->clients_lock);
    return -1;
}

int sx_server_unregister_client(sx_server_t *srv, sx_client_t *client){
    if(!srv || !client) return -1;
    pthread_mutex_lock(&srv->clients_lock);
    for(size_t i=0;i<srv->client_count;i++){
        if(srv->clients[i] == client){
            for(size_t j=i;j+1<srv->client_count;j++) srv->clients[j] = srv->clients[j+1];
            srv->clients[--srv->client_count] = NULL;
            free(client);
            break;
        }
    }
    pthread_mutex_unlock(&srv->clients_lock);
    return 0;
}
