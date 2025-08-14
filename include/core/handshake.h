#ifndef SECUREXFER_HANDSHAKE_H
#define SECUREXFER_HANDSHAKE_H

#include "transfer.h"

#ifdef __cplusplus
extern "C" {
#endif

int sx_handshake_client(int fd, sx_session_t *session);
int sx_handshake_server(int fd, sx_session_t *session);

#ifdef __cplusplus
}
#endif

#endif