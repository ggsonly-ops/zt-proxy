#define _GNU_SOURCE
#include "http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int split_host_port(char *target, char *host, size_t host_cap, int *port, int default_port)
{
    char *colon = strrchr(target, ':');
    *port = default_port;
    if (colon) {
        *colon = '\0';
        char *end;
        long value = strtol(colon + 1, &end, 10);
        if (*end != '\0' || value < 1 || value > 65535)
            return -1;
        *port = (int)value;
    }
    size_t host_len = strlen(target);
    if (host_len == 0 || host_len >= host_cap)
        return -1;
    memcpy(host, target, host_len + 1);
    return 0;
}

static int is_hop_header(const char *line, size_t len)
{
    static const char *names[] = { "Proxy-Authorization:", "Proxy-Connection:", "Connection:", "Keep-Alive:" };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        size_t name_len = strlen(names[i]);
        if (len >= name_len && strncasecmp(line, names[i], name_len) == 0)
            return 1;
    }
    return 0;
}

int parse_request(const char *buf, size_t len, struct request *req)
{
    const char *blank = memmem(buf, len, "\r\n\r\n", 4);
    if (!blank)
        return len >= MAX_HEADER ? -1 : 0;

    memset(req, 0, sizeof *req);
    req->header_len = (size_t)(blank - buf) + 4;

    const char *line_end = memmem(buf, len, "\r\n", 2);
    char line[4096], target[4096], version[16];
    size_t line_len = (size_t)(line_end - buf);
    if (line_len >= sizeof line)
        return -1;
    memcpy(line, buf, line_len);
    line[line_len] = '\0';

    if (sscanf(line, "%15s %4095s %15s", req->method, target, version) != 3)
        return -1;
    if (strncmp(version, "HTTP/1.", 7) != 0)
        return -1;

    if (strcmp(req->method, "CONNECT") == 0) {
        if (split_host_port(target, req->host, sizeof req->host, &req->port, 443) < 0)
            return -1;
    } else {
        /* a forward proxy gets absolute URIs: GET http://host[:port]/path HTTP/1.1 */
        if (strncasecmp(target, "http://", 7) != 0)
            return -1;
        char *authority = target + 7;
        char *slash = strchr(authority, '/');
        if (slash) {
            if (strlen(slash) >= sizeof req->path)
                return -1;
            strcpy(req->path, slash);
            *slash = '\0';
        } else {
            strcpy(req->path, "/");
        }
        if (split_host_port(authority, req->host, sizeof req->host, &req->port, 80) < 0)
            return -1;
    }

    const char *cursor = line_end + 2;
    while (cursor < blank + 2) {
        const char *eol = memmem(cursor, (size_t)(blank + 2 - cursor), "\r\n", 2);
        size_t header_len = (size_t)(eol - cursor);
        const char *key = "Proxy-Authorization:";
        size_t key_len = strlen(key);
        if (header_len > key_len && strncasecmp(cursor, key, key_len) == 0) {
            const char *value = cursor + key_len;
            while (*value == ' ')
                value++;
            size_t value_len = (size_t)(eol - value);
            if (value_len >= sizeof req->auth)
                return -1;
            memcpy(req->auth, value, value_len);
            req->auth[value_len] = '\0';
        }
        cursor = eol + 2;
    }
    return 1;
}

int build_forward_request(const char *buf, const struct request *req, char *out, size_t out_cap)
{
    int written = snprintf(out, out_cap, "%s %s HTTP/1.1\r\n", req->method, req->path);
    if (written < 0 || (size_t)written >= out_cap)
        return -1;
    size_t used = (size_t)written;

    const char *header_end = buf + req->header_len - 2;   /* points at the final CRLF */
    const char *cursor = (const char *)memmem(buf, req->header_len, "\r\n", 2) + 2;
    while (cursor < header_end) {
        const char *eol = memmem(cursor, (size_t)(header_end - cursor + 2), "\r\n", 2);
        size_t line_len = (size_t)(eol - cursor) + 2;
        if (!is_hop_header(cursor, line_len)) {
            if (used + line_len >= out_cap)
                return -1;
            memcpy(out + used, cursor, line_len);
            used += line_len;
        }
        cursor = eol + 2;
    }

    const char *tail = "Connection: close\r\n\r\n";
    size_t tail_len = strlen(tail);
    if (used + tail_len >= out_cap)
        return -1;
    memcpy(out + used, tail, tail_len);
    return (int)(used + tail_len);
}
