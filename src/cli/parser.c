#define _POSIX_C_SOURCE 200809L
#include <string.h>
#include <stdlib.h>
#include "parser.h"

typedef struct {
    char **args;
    int argc;
    int capacity;
} arg_store_t;

static void add_arg(arg_store_t *store, const char *arg) {
    if (store->argc == store->capacity) {
        store->capacity = store->capacity ? store->capacity * 2 : 4;
        store->args = (char **)realloc(store->args, store->capacity * sizeof(char *));
    }
    store->args[store->argc++] = strdup(arg);
}

static int is_ws(char c) {
    return (c == ' ' || c == '\t' || c == '\n');
}

static char *parse_token(const char **input) {
    const char *p = *input;
    char buf[1024];
    int idx = 0;
    int in_quote = 0;

    while (*p) {
        if (!in_quote && is_ws(*p)) break;
        if (*p == '"') {
            in_quote = !in_quote;
            p++;
            continue;
        }
        buf[idx++] = *p++;
    }
    buf[idx] = 0;
    *input = p;
    return strdup(buf);
}

char **cli_parse(const char *input, int *out_argc) {
    arg_store_t store = {0};
    const char *p = input;

    while (*p) {
        while (is_ws(*p)) p++;
        if (!*p) break;
        char *tok = parse_token(&p);
        if (tok) add_arg(&store, tok);
        free(tok);
    }

    *out_argc = store.argc;
    return store.args;
}

void cli_free_args(char **args, int argc) {
    for (int i = 0; i < argc; i++) free(args[i]);
    free(args);
}
