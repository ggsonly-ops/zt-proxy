#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>

#define MAX_HEADER 8192

struct request {
    char method[16];
    char host[256];
    int port;
    char path[2048];
    char auth[512];      /* value of Proxy-Authorization, if any */
    size_t header_len;   /* bytes up to and including the blank line */
};

/* 1 = parsed, 0 = need more bytes, -1 = bad request */
int parse_request(const char *buf, size_t len, struct request *req);

/* Rewrites a proxied request into origin form with proxy headers stripped.
   Returns bytes written to out, or -1 if it does not fit. */
int build_forward_request(const char *buf, const struct request *req, char *out, size_t out_cap);

#endif
