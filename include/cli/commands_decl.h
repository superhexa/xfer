#ifndef XFER_CLI_COMMANDS_DECL_H
#define XFER_CLI_COMMANDS_DECL_H

#ifdef __cplusplus
extern "C" {
#endif

int cmd_xfer(int argc, char **argv);
int cmd_encrypt(int argc, char **argv);
int cmd_compress(int argc, char **argv);
int cmd_chunk(int argc, char **argv);
int cmd_throttle(int argc, char **argv);
int cmd_port(int argc, char **argv);
int cmd_cfg(int argc, char **argv);
int cmd_hash(int argc, char **argv);
int cmd_auth(int argc, char **argv);
int cmd_streams(int argc, char **argv);
int cmd_ping(int argc, char **argv);
int cmd_stat(int argc, char **argv);
int cmd_resume(int argc, char **argv);
int cmd_sendr(int argc, char **argv);
int cmd_sendg(int argc, char **argv);
int cmd_sendp(int argc, char **argv);
int cmd_cipher(int argc, char **argv);
int cmd_zlevel(int argc, char **argv);
int cmd_verify(int argc, char **argv);
int cmd_progress(int argc, char **argv);
int cmd_timeout(int argc, char **argv);
int cmd_ctmo(int argc, char **argv);
int cmd_retries(int argc, char **argv);
int cmd_keepalive(int argc, char **argv);
int cmd_overwrite(int argc, char **argv);
int cmd_preserve(int argc, char **argv);
int cmd_loglevel(int argc, char **argv);
int cmd_ls(int argc, char **argv);
int cmd_du(int argc, char **argv);
int cmd_help(int argc, char **argv);
int cmd_version(int argc, char **argv);
int cmd_exit(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif